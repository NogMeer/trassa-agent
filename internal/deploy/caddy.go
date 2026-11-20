// SPDX-License-Identifier: AGPL-3.0-only

package deploy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strings"
	"time"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/fsutil"
)

// Прокси (decisions E17, часть 1): Caddy бинарником с systemd под trassa-caddy, админ-API на Unix-сокете.
const (
	CaddyUser    = "trassa-caddy"
	CaddyUnit    = "trassa-caddy.service"
	CaddyBinDir  = "/usr/local/lib/trassa"
	CaddyHome    = "/var/lib/trassa-caddy"
	CaddyEtc     = "/etc/trassa/caddy"
	CaddyRunDir  = "/run/trassa-caddy"
	AdminSocket  = "/run/trassa-caddy/admin.sock"
	unitFile     = "/etc/systemd/system/trassa-caddy.service"
	acmeStaging  = "https://acme-staging-v02.api.letsencrypt.org/directory"
	routesFile   = "routes.json"
	streamDelay  = "5m"
	streamTimout = "24h"
)

// Ошибки прокси.
var (
	ErrRoutesStale  = errors.New("DEPLOY_ROUTES_STALE")
	ErrProxyMissing = errors.New("PROXY_UNAVAILABLE")
	ErrProxyPort    = errors.New("PROXY_PORT_BUSY")
)

// CaddyPath — бинарник версии.
func CaddyPath(version string) string { return filepath.Join(CaddyBinDir, "caddy-"+version) }

func caddyUnitText(bin string) string {
	return `# Trassa: прокси приложений (E17). Файл пишет Trassa.
[Unit]
Description=Trassa proxy (Caddy)
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
User=` + CaddyUser + `
Group=` + CaddyUser + `
Environment=XDG_CONFIG_HOME=` + CaddyHome + `/config XDG_DATA_HOME=` + CaddyHome + `/data
ExecStart=` + bin + ` run --resume --config ` + CaddyEtc + `/initial.json
ExecReload=` + bin + ` reload --force --config ` + CaddyEtc + `/initial.json
RuntimeDirectory=trassa-caddy
RuntimeDirectoryMode=0750
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=` + CaddyHome + `
LimitNOFILE=1048576
Restart=on-failure

[Install]
WantedBy=multi-user.target
`
}

// ProxyState — что знает помощник о прокси: версия и маршруты по приложениям с адресами назначения.
type ProxyState struct {
	Version   string                `json:"version"`
	ACMEEmail string                `json:"acme_email"`
	Staging   bool                  `json:"acme_staging"`
	Grace     uint32                `json:"grace_seconds"`
	Apps      map[string][]RouteRec `json:"apps"`
}

// RouteRec — маршрут приложения: имена, сервис, адрес 127.0.0.1:<порт> (подставляет агент) или перенаправление.
type RouteRec struct {
	Hosts      []string `json:"hosts"`
	Service    string   `json:"service,omitempty"`
	RedirectTo string   `json:"redirect_to,omitempty"`
	Dial       string   `json:"dial,omitempty"`
}

func (e *Env) proxyStatePath() string { return filepath.Join(e.StateDir, "proxy.json") }

// LoadProxy — состояние прокси; нет — ErrProxyMissing.
func (e *Env) LoadProxy() (*ProxyState, error) {
	raw, err := fsutil.ReadLimited(e.proxyStatePath(), 8<<20)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%w: proxy.ensure не выполнялся", ErrProxyMissing)
	}
	if err != nil {
		return nil, err
	}
	var st ProxyState
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, fmt.Errorf("состояние прокси повреждено: %w", err)
	}
	if st.Apps == nil {
		st.Apps = map[string][]RouteRec{}
	}
	return &st, nil
}

func (e *Env) saveProxy(st *ProxyState) error {
	if err := os.MkdirAll(e.StateDir, 0o700); err != nil {
		return err
	}
	raw, _ := json.Marshal(st)
	return fsutil.WriteFileAtomic(e.proxyStatePath(), raw, 0o600, fsutil.Keep)
}

// ProxyPaths — файлы прокси для точки отката CONFIG.
func (e *Env) ProxyPaths() []string {
	return []string{e.path(unitFile), e.path(CaddyEtc + "/initial.json"), e.proxyStatePath()}
}

// EnsureProxy — proxy.ensure: бинарник Caddy (sha256 из таблицы), пользователь trassa-caddy без входа, служба
// с CAP_NET_BIND_SERVICE и песочницей, админ-API только на Unix-сокете.
func (e *Env) EnsureProxy(ctx context.Context, op string, p *agentv1.ProxyEnsureParams) (*agentv1.ProxyEnsureResult, error) {
	t := p.GetCaddy()
	raw, err := readTool(e.Stage(op), t)
	if err != nil {
		return nil, err
	}
	bin, err := untarOne(raw, "caddy")
	if err != nil {
		return nil, fmt.Errorf("архив caddy: %w", err)
	}
	dst := e.path(CaddyPath(t.GetVersion()))
	if err := e.write(CaddyPath(t.GetVersion()), bin, 0o755); err != nil {
		return nil, err
	}
	if out, err := e.Run(ctx, dst, "version"); err != nil || !strings.HasPrefix(strings.TrimSpace(string(out)), "v"+t.GetVersion()) {
		return nil, fmt.Errorf("caddy version: %q %v", firstLine(out), err)
	}
	if _, err := user.Lookup(CaddyUser); err != nil {
		if out, err := e.Run(ctx, "useradd", "--system", "--user-group", "--home-dir", CaddyHome, "--no-create-home",
			"--shell", "/usr/sbin/nologin", CaddyUser); err != nil {
			return nil, fmt.Errorf("useradd: %v %s", err, firstLine(out))
		}
	}
	if err := os.MkdirAll(e.path(CaddyHome), 0o700); err != nil {
		return nil, err
	}
	if out, err := e.Run(ctx, "chown", "-R", "--no-dereference", CaddyUser+":"+CaddyUser, e.path(CaddyHome)); err != nil {
		return nil, fmt.Errorf("chown: %v %s", err, firstLine(out))
	}
	st, err := e.LoadProxy()
	if err != nil {
		st = &ProxyState{Apps: map[string][]RouteRec{}, Grace: 30}
	}
	st.Version, st.ACMEEmail, st.Staging = t.GetVersion(), p.GetAcmeEmail(), p.GetAcmeStaging()
	doc, err := caddyDoc(st)
	if err != nil {
		return nil, err
	}
	if err := e.write(CaddyEtc+"/initial.json", doc, 0o644); err != nil {
		return nil, err
	}
	if err := e.write(unitFile, []byte(caddyUnitText(CaddyPath(t.GetVersion()))), 0o644); err != nil {
		return nil, err
	}
	if err := e.saveProxy(st); err != nil {
		return nil, err
	}
	for _, args := range [][]string{{"daemon-reload"}, {"enable", "--", CaddyUnit}, {"restart", "--", CaddyUnit}} {
		if out, err := e.Run(ctx, "systemctl", args...); err != nil {
			return nil, fmt.Errorf("systemctl %s: %v %s", args[0], err, firstLine(out))
		}
	}
	res := &agentv1.ProxyEnsureResult{Version: t.GetVersion()}
	if err := e.waitAdmin(ctx); err != nil {
		return nil, err
	}
	res.AdminOk = true
	return res, nil
}

// admin — HTTP к админ-API Caddy через Unix-сокет.
func (e *Env) admin(ctx context.Context, method, p string, body []byte) ([]byte, int, error) {
	hc := &http.Client{Transport: &http.Transport{DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", e.path(AdminSocket))
		}}}
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://caddy"+p, rd)
	if err != nil {
		return nil, 0, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	return out, resp.StatusCode, err
}

func (e *Env) waitAdmin(ctx context.Context) error {
	var last error
	for i := 0; i < 50; i++ {
		_, code, err := e.admin(ctx, http.MethodGet, "/config/", nil)
		if err == nil && code == http.StatusOK {
			return nil
		}
		last = err
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
	return fmt.Errorf("%w: админ-API Caddy не отвечает: %v", ErrProxyMissing, last)
}

// caddyDoc — документ Caddy из состояния: админ-API только на сокете, маршруты по именам, обратный прокси на
// 127.0.0.1:<порт> со stream_close_delay (смена маршрутов не рвёт WebSocket соседей) и grace_period.
func caddyDoc(st *ProxyState) ([]byte, error) {
	type m = map[string]any
	var routes []any
	apps := make([]string, 0, len(st.Apps))
	for a := range st.Apps {
		apps = append(apps, a)
	}
	sort.Strings(apps)
	for _, a := range apps {
		for _, r := range st.Apps[a] {
			var handle []any
			switch {
			case r.RedirectTo != "":
				handle = []any{m{"handler": "static_response", "status_code": 308,
					"headers": m{"Location": []string{"https://" + r.RedirectTo + "{http.request.uri}"}}}}
			case r.Dial != "":
				handle = []any{m{"handler": "reverse_proxy", "upstreams": []any{m{"dial": r.Dial}},
					"stream_close_delay": streamDelay, "stream_timeout": streamTimout}}
			default:
				continue // приложение без запущенного контейнера: маршрута нет
			}
			routes = append(routes, m{"match": []any{m{"host": r.Hosts}}, "handle": handle, "terminal": true})
		}
	}
	grace := st.Grace
	if grace == 0 {
		grace = 30
	}
	issuer := m{"module": "acme", "email": st.ACMEEmail}
	if st.Staging {
		issuer["ca"] = acmeStaging
	}
	doc := m{
		"admin": m{"listen": "unix/" + AdminSocket, "config": m{"persist": true}},
		"apps": m{
			"http": m{"grace_period": fmt.Sprintf("%ds", grace), "servers": m{"trassa": m{"listen": []string{":443"}, "routes": routes}}},
			"tls":  m{"automation": m{"policies": []any{m{"issuers": []any{issuer}}}}},
		},
	}
	return json.Marshal(doc)
}

// RoutesHash — хэш маршрутов (по приложениям, без адресов): base_hash панели для защиты от гонки.
func RoutesHash(st *ProxyState) string {
	type item struct {
		App string   `json:"app"`
		R   RouteRec `json:"r"`
	}
	var items []item
	for a, rs := range st.Apps {
		for _, r := range rs {
			r.Dial = ""
			items = append(items, item{a, r})
		}
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].App != items[j].App {
			return items[i].App < items[j].App
		}
		return strings.Join(items[i].R.Hosts, ",") < strings.Join(items[j].R.Hosts, ",")
	})
	raw, _ := json.Marshal(items)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// loadRoutes — документ целиком (POST /load); при ответе не 200 прежний остаётся в силе.
func (e *Env) loadRoutes(ctx context.Context, st *ProxyState) error {
	doc, err := caddyDoc(st)
	if err != nil {
		return err
	}
	out, code, err := e.admin(ctx, http.MethodPost, "/load", doc)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrProxyMissing, err)
	}
	if code != http.StatusOK {
		msg := firstLine(out)
		if strings.Contains(msg, "address already in use") {
			return fmt.Errorf("%w: %s", ErrProxyPort, msg)
		}
		return fmt.Errorf("caddy /load: HTTP %d: %s", code, msg)
	}
	return nil
}

// ApplyRoutes — proxy.route.apply: полное состояние маршрутов; base_hash не совпал с текущим — отказ
// DEPLOY_ROUTES_STALE (панель пересобирает). Адреса назначения сохраняются из состояния агента.
func (e *Env) ApplyRoutes(ctx context.Context, p *agentv1.ProxyRouteApplyParams) (*agentv1.ProxyRouteApplyResult, error) {
	st, err := e.LoadProxy()
	if err != nil {
		return nil, err
	}
	if cur := RoutesHash(st); p.GetBaseHash() != cur && !(p.GetBaseHash() == "" && len(st.Apps) == 0) {
		return nil, fmt.Errorf("%w: маршруты изменились (%s)", ErrRoutesStale, cur)
	}
	dials := map[string]string{} // app/service → прежний адрес
	for a, rs := range st.Apps {
		for _, r := range rs {
			if r.Dial != "" {
				dials[a+"/"+r.Service] = r.Dial
			}
		}
	}
	next := map[string][]RouteRec{}
	for _, r := range p.GetRoutes() {
		rec := RouteRec{Hosts: r.GetHosts(), Service: r.GetService(), RedirectTo: r.GetRedirectTo()}
		if rec.RedirectTo == "" {
			rec.Dial = dials[r.GetAppId()+"/"+r.GetService()]
		}
		next[r.GetAppId()] = append(next[r.GetAppId()], rec)
	}
	st.Apps = next
	if err := e.loadRoutes(ctx, st); err != nil {
		return nil, err
	}
	if err := e.saveProxy(st); err != nil {
		return nil, err
	}
	return &agentv1.ProxyRouteApplyResult{RoutesHash: RoutesHash(st), Certs: e.certs(st)}, nil
}

// certs — сертификаты из каталога данных Caddy: файл есть — ACTIVE (срок и издатель), нет — ISSUING.
func (e *Env) certs(st *ProxyState) []*agentv1.CertStatus {
	var out []*agentv1.CertStatus
	root := e.path(filepath.Join(CaddyHome, "data", "caddy", "certificates"))
	issuers, _ := os.ReadDir(root)
	for _, rs := range st.Apps {
		for _, r := range rs {
			for _, h := range r.Hosts {
				cs := &agentv1.CertStatus{Host: h, State: agentv1.CertState_CERT_STATE_ISSUING}
				for _, is := range issuers {
					raw, err := fsutil.ReadLimited(filepath.Join(root, is.Name(), h, h+".crt"), 64<<10)
					if err != nil {
						continue
					}
					if b, _ := pem.Decode(raw); b != nil {
						if c, err := x509.ParseCertificate(b.Bytes); err == nil {
							cs.State, cs.NotAfterMs, cs.Issuer = agentv1.CertState_CERT_STATE_ACTIVE, c.NotAfter.UnixMilli(), c.Issuer.CommonName
						}
					}
				}
				out = append(out, cs)
			}
		}
	}
	return out
}

// SyncProxy — после отката маршрутов: документ Caddy по возвращённому состоянию (trassa-helper proxy-sync).
func (e *Env) SyncProxy(ctx context.Context) error {
	st, err := e.LoadProxy()
	if err != nil {
		return err
	}
	return e.loadRoutes(ctx, st)
}
