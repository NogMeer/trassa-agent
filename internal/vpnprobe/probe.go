// SPDX-License-Identifier: AGPL-3.0-only

package vpnprobe

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
)

// Env — окружение точки замера.
type Env struct {
	// Dir — движки: /var/lib/trassa/vpn-probe (root, 0755).
	Dir string
	// RunDir — каталоги замеров с доступом: /run/trassa-vpnprobe (root, 0711); скрыт от движка, кроме своего.
	RunDir  string
	Sandbox Sandbox
	// Owner — uid и gid пользователя движка (trassa-vpnprobe, не trassa): ему принадлежит каталог замера и
	// конфигурация; агенту они недоступны.
	Owner func() (uid, gid int, err error)
	// EnsureUser — создать пользователя движка, если его нет (vpn.probe.ensure).
	EnsureUser func(ctx context.Context) error
	// LookupIP — разрешение имени входа (системный резолвер).
	LookupIP func(ctx context.Context, host string) ([]net.IP, error)
	// DialEntry — TCP-проверка порта входа; DialLocal — к socks движка на 127.0.0.1.
	DialEntry func(ctx context.Context, addr string) (net.Conn, error)
	Now       func() time.Time
	// Interval — пауза между запросами удержания; ReadyWait — сколько ждать socks движка.
	Interval  time.Duration
	ReadyWait time.Duration

	once sync.Once
	sem  chan struct{}
}

func (e *Env) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

// Пределы одного запроса удержания: тело читается не больше этого (поток проверяется, а не скачивается).
const (
	bodyLimit   = 256 << 10
	entryDial   = 5 * time.Second
	readyWait   = 15 * time.Second
	holdPause   = 2 * time.Second
	requestWait = 30 * time.Second
)

// Заметки звена (VpnProbeHop.note).
const (
	NoteTCPRefused = "TCP_REFUSED"
	NoteTCPTimeout = "TCP_TIMEOUT"
	NoteTunnel     = "TUNNEL_FAILED"
	NoteReset      = "STREAM_RESET"
)

// Probe — один замер: вход по ссылке доступа, его адрес — только из allowed_endpoints; TCP-проверка порта входа;
// движок в песочнице; запрос target_url через туннель и удержание потока hold_seconds повторными запросами.
// Ошибка — отказ (код из Codes); статус FAILED или RESET — это итог замера, не ошибка.
func (e *Env) Probe(ctx context.Context, p *agentv1.VpnProbeRunParams, access []byte) (*agentv1.VpnProbeRunResult, error) {
	e.once.Do(func() { e.sem = make(chan struct{}, MaxParallel) })
	select {
	case e.sem <- struct{}{}:
		defer func() { <-e.sem }()
	default:
		return nil, fmt.Errorf("%w: уже %d замера", ErrBusy, MaxParallel)
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(p.GetTimeoutSeconds())*time.Second)
	defer cancel()
	version, bin, err := e.Installed(p.GetEngine())
	if err != nil {
		return nil, err
	}
	link, err := ParseLink(string(access))
	if err != nil {
		return nil, err
	}
	allowed, err := Endpoints(p.GetAllowedEndpoints())
	if err != nil {
		return nil, err
	}
	target, _, err := TargetURL(p.GetTargetUrl())
	if err != nil {
		return nil, err
	}
	entry, err := e.entry(ctx, link.Host, allowed)
	if err != nil {
		return nil, err
	}
	res := &agentv1.VpnProbeRunResult{CheckId: p.GetCheckId(), EngineVersion: version}
	hop0 := &agentv1.VpnProbeHop{Index: 0}
	t0 := e.now()
	dctx, dcancel := context.WithTimeout(ctx, entryDial)
	c, derr := e.DialEntry(dctx, net.JoinHostPort(entry.String(), strconv.Itoa(link.Port)))
	dcancel()
	if derr != nil {
		hop0.Note = NoteTCPTimeout
		if errors.Is(derr, syscall.ECONNREFUSED) {
			hop0.Note = NoteTCPRefused
		}
		res.Status, res.FirstBrokenHop, res.Hops = agentv1.VpnProbeStatus_VPN_PROBE_STATUS_FAILED, ptr(0), []*agentv1.VpnProbeHop{hop0}
		return res, nil
	}
	c.Close()
	res.EntryPortOpen, hop0.Reachable, hop0.LatencyMs = true, true, ms(e.now().Sub(t0))

	port, err := freePort()
	if err != nil {
		return nil, err
	}
	dir, cfgPath, err := e.writeConfig(p.GetCheckId(), link, entry, port)
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	proc, err := e.Sandbox.Start(ctx, Unit{
		Name:     "trassa-vpnprobe-" + strings.ToLower(p.GetCheckId()) + "-" + randHex(3),
		Exec:     []string{bin, "run", "-c", cfgPath},
		AllowIPs: []string{entry.String()},
		Visible:  []string{dir},
		Timeout:  int(p.GetTimeoutSeconds()) + 30,
		Env:      []string{"XRAY_LOCATION_ASSET=" + filepath.Dir(bin)},
	})
	if err != nil {
		return nil, err
	}
	defer proc.Stop(context.WithoutCancel(ctx))
	if err := e.waitReady(ctx, proc, port); err != nil {
		return nil, err
	}
	m := e.measure(ctx, proc, port, target, time.Duration(p.GetHoldSeconds())*time.Second)
	if m.timeout {
		return nil, fmt.Errorf("%w: замер не уложился в %d с", ErrTimeout, p.GetTimeoutSeconds())
	}
	res.LatencyMs, res.HeldSeconds, res.BytesTransferred = m.latency, m.held, m.bytes
	switch {
	case m.ok:
		res.Status = agentv1.VpnProbeStatus_VPN_PROBE_STATUS_OK
		// Поток прошёл всю цепочку: все звенья на связи; задержка известна только у входа.
		res.Hops = []*agentv1.VpnProbeHop{hop0}
		for i := uint32(1); i < p.GetHopCount(); i++ {
			res.Hops = append(res.Hops, &agentv1.VpnProbeHop{Index: i, Reachable: true})
		}
	case m.started:
		res.Status, hop0.Note = agentv1.VpnProbeStatus_VPN_PROBE_STATUS_RESET, ""
		res.Hops = []*agentv1.VpnProbeHop{hop0}
	default:
		// Порт входа открыт, туннель не поднялся: какое звено сломано, с точки замера не видно.
		res.Status = agentv1.VpnProbeStatus_VPN_PROBE_STATUS_FAILED
		hop0.Note = NoteTunnel
		res.Hops = []*agentv1.VpnProbeHop{hop0}
	}
	return res, nil
}

func ptr(v uint32) *uint32 { return &v }

func ms(d time.Duration) uint32 { return uint32(min(max(d.Milliseconds(), 1), 1<<31)) }

// entry — адрес входа: IP из ссылки или разрешённое имя; берётся первый адрес из allowed_endpoints. Ни одного —
// VPN_PROBE_ENDPOINT_FORBIDDEN: движок пойдёт только на закреплённый IP, не на имя (DNS не переиграет проверку).
func (e *Env) entry(ctx context.Context, host string, allowed map[string]net.IP) (net.IP, error) {
	var ips []net.IP
	if ip := net.ParseIP(host); ip != nil {
		ips = []net.IP{ip}
	} else {
		lctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		var err error
		ips, err = e.LookupIP(lctx, host)
		if err != nil || len(ips) == 0 {
			return nil, fmt.Errorf("%w: имя входа %s не разрешается: %v", ErrConfigInvalid, host, err)
		}
	}
	for _, ip := range ips {
		if a, ok := allowed[ip.String()]; ok {
			return a, nil
		}
	}
	return nil, fmt.Errorf("%w: адрес входа %s не из серверов цепочки", ErrEndpointForbid, host)
}

func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// writeConfig — <RunDir>/<check_id>: каталог 0700 и config.json 0600 пользователя движка. Каталог от прошлой
// попытки с тем же check_id удаляется.
func (e *Env) writeConfig(checkID string, l *Link, entry net.IP, port int) (string, string, error) {
	cfg, err := XrayConfig(l, entry, port)
	if err != nil {
		return "", "", err
	}
	uid, gid, err := e.Owner()
	if err != nil {
		return "", "", err
	}
	if err := os.MkdirAll(e.RunDir, 0o711); err != nil {
		return "", "", err
	}
	dir := filepath.Join(e.RunDir, strings.ToLower(checkID))
	if err := os.RemoveAll(dir); err != nil {
		return "", "", err
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		return "", "", err
	}
	path := filepath.Join(dir, "config.json")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		os.RemoveAll(dir)
		return "", "", err
	}
	_, werr := f.Write(cfg)
	cerr := f.Close()
	clear(cfg)
	if err := errors.Join(werr, cerr, chown(path, uid, gid), chown(dir, uid, gid)); err != nil {
		os.RemoveAll(dir)
		return "", "", err
	}
	return dir, path, nil
}

func chown(path string, uid, gid int) error {
	if runtime.GOOS != "linux" && os.Geteuid() != 0 {
		return nil // тесты на машине разработчика: без root владельца не сменить
	}
	return os.Lchown(path, uid, gid)
}

// waitReady — socks движка принимает соединения; движок вышел раньше — конфигурация не принята.
func (e *Env) waitReady(ctx context.Context, proc Process, port int) error {
	wait := e.ReadyWait
	if wait == 0 {
		wait = readyWait
	}
	deadline := e.now().Add(wait)
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	for {
		select {
		case <-proc.Exited():
			if strings.Contains(string(proc.Output()), "Failed to start") {
				return fmt.Errorf("%w: движок не принял доступ", ErrConfigInvalid)
			}
			return fmt.Errorf("%w: движок завершился при запуске", ErrEngineFailed)
		default:
		}
		var d net.Dialer
		c, err := d.DialContext(ctx, "tcp", addr)
		if err == nil {
			c.Close()
			return nil
		}
		if e.now().After(deadline) {
			return fmt.Errorf("%w: движок не открыл порт за %s", ErrEngineFailed, wait)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("%w: %v", ErrTimeout, ctx.Err())
		case <-time.After(200 * time.Millisecond):
		}
	}
}

type measured struct {
	ok, started, timeout bool
	latency, held        uint32
	bytes                uint64
}

// measure — запросы к target_url через socks движка: первый — задержка до первого байта; дальше повторные
// запросы раз в Interval, пока поток не продержится hold. Ошибка после первого ответа — обрыв (RESET).
// Перенаправления не выполняются: поток проверяется к заданному адресу, а не по ссылкам ответа.
func (e *Env) measure(ctx context.Context, proc Process, port int, target *url.URL, hold time.Duration) measured {
	tr := &http.Transport{
		Proxy:                 http.ProxyURL(&url.URL{Scheme: "socks5", Host: net.JoinHostPort("127.0.0.1", strconv.Itoa(port))}),
		MaxConnsPerHost:       1,
		TLSHandshakeTimeout:   20 * time.Second,
		ResponseHeaderTimeout: requestWait,
		DisableCompression:    true,
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	pause := e.Interval
	if pause == 0 {
		pause = holdPause
	}
	var m measured
	var first time.Time
	for {
		// Вызов из горутины транспорта: время первого байта — атомарно.
		var gotByte atomic.Int64
		start := e.now()
		trace := &httptrace.ClientTrace{GotFirstResponseByte: func() { gotByte.Store(e.now().UnixNano()) }}
		rctx, cancel := context.WithTimeout(httptrace.WithClientTrace(ctx, trace), requestWait+10*time.Second)
		req, _ := http.NewRequestWithContext(rctx, http.MethodGet, target.String(), nil)
		req.Header.Set("User-Agent", "trassa-vpn-probe")
		resp, err := client.Do(req)
		if err == nil {
			n, rerr := io.Copy(io.Discard, io.LimitReader(resp.Body, bodyLimit))
			resp.Body.Close()
			m.bytes += uint64(n)
			err = rerr
		}
		cancel()
		if ctx.Err() != nil {
			m.timeout = true
			return m
		}
		select {
		case <-proc.Exited():
			// Движок упал посреди замера: поток не держится.
			if err == nil {
				err = errors.New("движок завершился")
			}
		default:
		}
		if err != nil {
			if m.started {
				m.held = uint32(min(e.now().Sub(first)/time.Second, hold/time.Second))
			}
			return m
		}
		if first.IsZero() {
			fb := e.now()
			if ns := gotByte.Load(); ns != 0 {
				fb = time.Unix(0, ns)
			}
			first, m.started, m.latency = fb, true, ms(fb.Sub(start))
		}
		h := e.now().Sub(first)
		m.held = uint32(min(h/time.Second, hold/time.Second))
		if h >= hold {
			m.ok = true
			return m
		}
		select {
		case <-ctx.Done():
			m.timeout = true
			return m
		case <-time.After(min(pause, hold-h)):
		}
	}
}

// Cleanup — при старте помощника: каталоги замеров от прошлой жизни (в них доступ) удаляются.
func (e *Env) Cleanup() error {
	entries, err := os.ReadDir(e.RunDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var errs []error
	for _, d := range entries {
		errs = append(errs, os.RemoveAll(filepath.Join(e.RunDir, d.Name())))
	}
	return errors.Join(errs...)
}
