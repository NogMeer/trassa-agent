// SPDX-License-Identifier: AGPL-3.0-only

// Заглушка панели для матрицы ОС в CI (E05-T28). Только для одноразового контейнера CI: свой УЦ, тестовый ключ
// выпуска и тестовый ключ панели создаются при запуске и живут до конца прогона. Отдаёт то же, что настоящая панель:
// install.sh, манифест выпуска, файлы выпуска с подписью minisign, регистрацию и шлюз WSS. Шлюз проводит рукопожатие,
// отправляет подписанную операцию system.info, принимает метрики и записывает итог в <out>/result.json.
//
// Запуск: stubpanel -release <каталог с бинарниками> -version 1.2.3 -script scripts/install.sh -out <каталог>
// Файлы в <out>: ca.pem (корневой сертификат), release.pub (ключ выпуска для install.sh), token, result.json.
package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"aead.dev/minisign"
	"github.com/coder/websocket"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/identity"
	"github.com/NogMeer/trassa-agent/internal/security"
	"github.com/NogMeer/trassa-agent/internal/verify"
)

const (
	serverID  = "01a1f4b6-f327-7a5d-ac23-e95c272c0fe8"
	operation = "01a1f4b6-f2f2-7e66-85b4-000000000001"
	// logsOperation — подписка на журналы после system.info.
	logsOperation = "01a1f4b6-f2f2-7e66-85b4-000000000002"
	// scanOperation и updatesOperation — security.scan и packages.list_updates после подписки на журналы.
	scanOperation    = "01a1f4b6-f2f2-7e66-85b4-000000000003"
	updatesOperation = "01a1f4b6-f2f2-7e66-85b4-000000000004"
	// hardenOperation и hardenRevert — ssh.harden и его возврат.
	hardenOperation = "01a1f4b6-f2f2-7e66-85b4-000000000300"
	hardenRevert    = "01a1f4b6-f2f2-7e66-85b4-000000000301"
	// fwLockPlan, fwPlan, fwApply, fwRevert — firewall.plan (запирающий и рабочий), firewall.apply и возврат.
	fwLockPlan = "01a1f4b6-f2f2-7e66-85b4-000000000400"
	fwPlan     = "01a1f4b6-f2f2-7e66-85b4-000000000401"
	fwApply    = "01a1f4b6-f2f2-7e66-85b4-000000000402"
	fwRevert   = "01a1f4b6-f2f2-7e66-85b4-000000000403"
	// restartOp и upgradeOp — service.restart и packages.upgrade.
	restartOp = "01a1f4b6-f2f2-7e66-85b4-000000000500"
	upgradeOp = "01a1f4b6-f2f2-7e66-85b4-000000000501"
	// netCheckOp — net.check (E07).
	netCheckOp = "01a1f4b6-f2f2-7e66-85b4-000000000600"
	// wgKeygenOp, wgApplyOp, wgRemoveOp — приватная сеть (E14).
	wgKeygenOp = "01a1f4b6-f2f2-7e66-85b4-000000000700"
	wgApplyOp  = "01a1f4b6-f2f2-7e66-85b4-000000000701"
	wgRemoveOp = "01a1f4b6-f2f2-7e66-85b4-000000000702"
	panelKeyID = "stub"
)

type panel struct {
	addr    string
	version string
	out     string
	script  []byte
	files   map[string][]byte // имя → содержимое каталога выпуска
	token   string
	panel   ed25519.PrivateKey

	mu       sync.Mutex
	agentPub ed25519.PublicKey
	used     bool
	// pendingFix и pendingRevert — исправления и их возвраты, ждущие итога.
	pendingFix    map[string]fix
	pendingRevert map[string]string
}

func main() {
	addr := flag.String("addr", "localhost:8443", "адрес (хост:порт), он же адрес панели в команде установки")
	release := flag.String("release", "", "каталог с trassa-agent-linux-<arch> и trassa-helper-linux-<arch>")
	version := flag.String("version", "", "версия выпуска (как -X config.Version при сборке)")
	script := flag.String("script", "", "scripts/install.sh — в отдаваемую копию вписывается тестовый ключ выпуска")
	out := flag.String("out", "", "каталог для ca.pem, release.pub, token, result.json")
	tamper := flag.Bool("tamper", false, "испортить подпись SHA256SUMS: установка обязана отказать с кодом 3")
	flag.Parse()
	if *release == "" || *version == "" || *script == "" || *out == "" {
		flag.Usage()
		os.Exit(2)
	}
	p, cert, err := setup(*addr, *release, *version, *script, *out, *tamper)
	if err != nil {
		log.Fatal(err)
	}
	srv := &http.Server{
		Addr:              *addr,
		Handler:           p,
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("заглушка панели на https://%s", *addr)
	log.Fatal(srv.ListenAndServeTLS("", ""))
}

func setup(addr, release, version, script, out string, tamper bool) (*panel, tls.Certificate, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, tls.Certificate{}, err
	}
	cert, caPEM, err := newCert(host)
	if err != nil {
		return nil, tls.Certificate{}, err
	}
	files, err := releaseFiles(release)
	if err != nil {
		return nil, tls.Certificate{}, err
	}
	pub, priv, err := minisign.GenerateKey(rand.Reader)
	if err != nil {
		return nil, tls.Certificate{}, err
	}
	sig := signHashed(priv, files["SHA256SUMS"], "trassa-agent "+version)
	if tamper {
		sig = bytes.Replace(sig, []byte("trassa-agent "+version), []byte("trassa-agent 0.0.1"), 1)
	}
	files["SHA256SUMS.minisig"] = sig
	pubText, err := pub.MarshalText()
	if err != nil {
		return nil, tls.Certificate{}, err
	}
	lines := strings.Split(strings.TrimSpace(string(pubText)), "\n")
	key := lines[len(lines)-1]

	// Копия install.sh с тестовым ключом. Настоящий скрипт не трогается: в нём список ключей пуст (R12).
	src, err := os.ReadFile(script)
	if err != nil {
		return nil, tls.Certificate{}, err
	}
	const empty = "\nTRASSA_RELEASE_KEYS=\"\"\n"
	if bytes.Count(src, []byte(empty)) != 1 {
		return nil, tls.Certificate{}, errors.New("в install.sh не найдена ровно одна строка TRASSA_RELEASE_KEYS=\"\"")
	}
	src = bytes.Replace(src, []byte(empty), []byte("\nTRASSA_RELEASE_KEYS=\""+key+"\"\n"), 1)

	tok := make([]byte, 32)
	if _, err := rand.Read(tok); err != nil {
		return nil, tls.Certificate{}, err
	}
	_, panelPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, tls.Certificate{}, err
	}
	p := &panel{
		addr: addr, version: version, out: out, script: src, files: files, panel: panelPriv,
		pendingFix: map[string]fix{}, pendingRevert: map[string]string{},
		token: "trs_enr_" + base64.RawURLEncoding.EncodeToString(tok),
	}
	if err := os.MkdirAll(out, 0o700); err != nil {
		return nil, tls.Certificate{}, err
	}
	for name, b := range map[string][]byte{"ca.pem": caPEM, "release.pub": []byte(key + "\n"), "token": []byte(p.token)} {
		if err := os.WriteFile(filepath.Join(out, name), b, 0o600); err != nil {
			return nil, tls.Certificate{}, err
		}
	}
	_ = os.Remove(filepath.Join(out, "result.json"))
	return p, cert, nil
}

// releaseFiles читает бинарники выпуска и составляет SHA256SUMS в формате sha256sum.
func releaseFiles(dir string) (map[string][]byte, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	files := map[string][]byte{}
	var sums strings.Builder
	for _, e := range ents {
		n := e.Name()
		if !e.Type().IsRegular() || !(strings.HasPrefix(n, "trassa-agent-linux-") || strings.HasPrefix(n, "trassa-helper-linux-")) {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			return nil, err
		}
		files[n] = b
		h := sha256.Sum256(b)
		fmt.Fprintf(&sums, "%s  %s\n", hex.EncodeToString(h[:]), n)
	}
	if len(files) < 2 {
		return nil, fmt.Errorf("в %s нет бинарников агента и помощника", dir)
	}
	files["SHA256SUMS"] = []byte(sums.String())
	return files, nil
}

func signHashed(priv minisign.PrivateKey, msg []byte, comment string) []byte {
	r := minisign.NewReader(bytes.NewReader(msg))
	_, _ = io.Copy(io.Discard, r)
	return r.SignWithComments(priv, comment, "stub panel")
}

// newCert создаёт УЦ и сертификат сервера для host; возвращает сертификат и PEM корня.
func newCert(host string) (tls.Certificate, []byte, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	now := time.Now()
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Trassa CI stub CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: host},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		leaf.IPAddresses = []net.IP{ip}
	} else {
		leaf.DNSNames = []string{host}
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	return tls.Certificate{Certificate: [][]byte{leafDER, caDER}, PrivateKey: leafKey},
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), nil
}

func (p *panel) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s", r.Method, r.URL.Path)
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/install.sh":
		_, _ = w.Write(p.script)
	case r.Method == http.MethodGet && r.URL.Path == "/agent/v1/releases/current":
		p.manifest(w, r)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/releases/"+p.version+"/"):
		b, ok := p.files[strings.TrimPrefix(r.URL.Path, "/releases/"+p.version+"/")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(b)
	case r.Method == http.MethodPost && r.URL.Path == "/agent/v1/enroll":
		p.enroll(w, r)
	case r.URL.Path == "/agent/v1/connect":
		p.connect(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (p *panel) base() string { return "https://" + p.addr }

func (p *panel) manifest(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	arch := q.Get("arch")
	if q.Get("os") != "linux" || (arch != "amd64" && arch != "arm64") || q.Get("channel") != "stable" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"code": "BAD_REQUEST", "message": "os, arch, channel"})
		return
	}
	dir := p.base() + "/releases/" + p.version
	h := sha256.Sum256(p.files["trassa-agent-linux-"+arch])
	writeJSON(w, http.StatusOK, map[string]any{
		"version": p.version, "protocolVersion": 1, "signatureUrl": dir + "/SHA256SUMS.minisig",
		"artifacts": []map[string]string{{"os": "linux", "arch": arch, "url": dir + "/trassa-agent-linux-" + arch, "sha256": hex.EncodeToString(h[:])}},
	})
}

func (p *panel) enroll(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token     string `json:"token"`
		PublicKey string `json:"publicKey"`
		Hostname  string `json:"hostname"`
		OS        string `json:"os"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"code": "BAD_REQUEST", "message": err.Error()})
		return
	}
	pk, err := base64.StdEncoding.DecodeString(req.PublicKey)
	p.mu.Lock()
	defer p.mu.Unlock()
	if req.Token != p.token || p.used {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"code": "ENROLLMENT_TOKEN_INVALID", "message": "токен"})
		return
	}
	if err != nil || len(pk) != ed25519.PublicKeySize {
		writeJSON(w, http.StatusBadRequest, map[string]string{"code": "BAD_REQUEST", "message": "publicKey"})
		return
	}
	p.used = true
	p.agentPub = pk
	log.Printf("регистрация: %s (%s)", req.Hostname, req.OS)
	writeJSON(w, http.StatusOK, map[string]any{
		"serverId": serverID, "gatewayUrl": "wss://" + p.addr + "/agent/v1/connect", "protocolVersion": 1,
		"panelKeys": []map[string]string{{"keyId": panelKeyID, "publicKey": base64.StdEncoding.EncodeToString(p.panel.Public().(ed25519.PublicKey))}},
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

type conn struct {
	ws  *websocket.Conn
	mu  sync.Mutex
	seq uint64
}

func (c *conn) send(ctx context.Context, m *agentv1.GatewayMessage) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.seq++
	m.Seq = c.seq
	raw, err := proto.Marshal(m)
	if err != nil {
		return err
	}
	return c.ws.Write(ctx, websocket.MessageBinary, raw)
}

func (c *conn) read(ctx context.Context) (*agentv1.AgentMessage, error) {
	_, raw, err := c.ws.Read(ctx)
	if err != nil {
		return nil, err
	}
	var m agentv1.AgentMessage
	return &m, proto.Unmarshal(raw, &m)
}

// connect — рукопожатие раздела 5 E05, затем одна операция system.info; итог — в result.json.
func (p *panel) connect(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	agentPub := p.agentPub
	p.mu.Unlock()
	if agentPub == nil {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	ws, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	defer ws.CloseNow()
	ws.SetReadLimit(1 << 20)
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	c := &conn{ws: ws}
	nonce := make([]byte, 32)
	_, _ = rand.Read(nonce)
	if err := c.send(ctx, &agentv1.GatewayMessage{Payload: &agentv1.GatewayMessage_Challenge{Challenge: &agentv1.Challenge{
		Nonce: nonce, GatewayTimeMs: time.Now().UnixMilli(), ProtocolVersions: []agentv1.ProtocolVersion{agentv1.ProtocolVersion_PROTOCOL_VERSION_1},
	}}}); err != nil {
		return
	}
	m, err := c.read(ctx)
	if err != nil || m.GetHello() == nil {
		log.Printf("ждали Hello: %v", err)
		return
	}
	h := m.GetHello()
	if h.GetServerId() != serverID || !ed25519.Verify(agentPub, identity.AuthInput(nonce, serverID), h.GetSignature()) {
		log.Printf("подпись Hello не сошлась")
		_ = c.send(ctx, &agentv1.GatewayMessage{Payload: &agentv1.GatewayMessage_Close{Close: &agentv1.Close{Reason: agentv1.CloseReason_CLOSE_REASON_AUTH_FAILED}}})
		return
	}
	if err := c.send(ctx, &agentv1.GatewayMessage{Payload: &agentv1.GatewayMessage_Welcome{Welcome: &agentv1.Welcome{
		ProtocolVersion: agentv1.ProtocolVersion_PROTOCOL_VERSION_1, GatewayTimeMs: time.Now().UnixMilli(), HeartbeatSec: 15,
	}}}); err != nil {
		return
	}
	log.Printf("агент на связи: %s %s %s, агент %s, помощник %s", h.GetOs(), h.GetOsVersion(), h.GetArch(), h.GetAgentVersion(), h.GetHelperVersion())
	if err := c.send(ctx, &agentv1.GatewayMessage{Payload: &agentv1.GatewayMessage_Operation{Operation: p.systemInfo()}}); err != nil {
		return
	}
	// Итог пишется, когда пришли и результат system.info, и первая пачка метрик (E08-T5).
	var res *agentv1.OperationResult
	var names []string
	written := false
	for {
		m, err := c.read(ctx)
		if err != nil {
			log.Printf("соединение: %v", err)
			return
		}
		if a := m.GetOperationAck(); a != nil && !a.GetAccepted() {
			p.result(h, nil, nil, "отказ помощника по "+a.GetOperationId()+": "+a.GetRejectCode())
			return
		}
		switch {
		case m.GetEvent() != nil:
			p.event(m.GetEvent())
		case m.GetLogChunk() != nil:
			p.logChunk(m.GetLogChunk())
		case m.GetOperationResult().GetOperationId() == operation:
			res = m.GetOperationResult()
			// После system.info — подписка на журналы (E08-T15): файл из /var/log и ссылка наружу, которую
			// помощник обязан отклонить.
			if err := c.send(ctx, &agentv1.GatewayMessage{Payload: &agentv1.GatewayMessage_Operation{Operation: p.sign(logsOperation, "logs.subscribe",
				&agentv1.OperationParams{Params: &agentv1.OperationParams_LogsSubscribe{LogsSubscribe: &agentv1.LogsSubscribeParams{
					MinLevel: agentv1.LogLevel_LOG_LEVEL_INFO,
					Sources: []*agentv1.LogSource{
						{Kind: agentv1.LogSourceKind_LOG_SOURCE_KIND_FILE, Name: "/var/log/ci-logs.log"},
						{Kind: agentv1.LogSourceKind_LOG_SOURCE_KIND_FILE, Name: "/var/log/ci-evil.log"},
					},
				}}})}}); err != nil {
				return
			}
		case m.GetOperationResult().GetOperationId() == logsOperation:
			p.writeJSON("subscribe.json", m.GetOperationResult())
			// Центр безопасности (E10, блок A): скан по всем кодам помощника и список обновлений.
			for _, op := range []*agentv1.SignedOperation{
				p.sign(scanOperation, "security.scan", &agentv1.OperationParams{Params: &agentv1.OperationParams_SecurityScan{
					SecurityScan: &agentv1.SecurityScanParams{Checks: security.Codes()}}}),
				p.sign(updatesOperation, "packages.list_updates", &agentv1.OperationParams{Params: &agentv1.OperationParams_PackagesListUpdates{
					PackagesListUpdates: &agentv1.PackagesListUpdatesParams{}}}),
			} {
				if err := c.send(ctx, &agentv1.GatewayMessage{Payload: &agentv1.GatewayMessage_Operation{Operation: op}}); err != nil {
					return
				}
			}
		case m.GetOperationResult().GetOperationId() == scanOperation:
			p.writeJSON("security.json", m.GetOperationResult())
			// ssh.harden с автооткатом (E10-T13): ждёт подтверждения, затем возврат.
			if err := c.send(ctx, &agentv1.GatewayMessage{Payload: &agentv1.GatewayMessage_Operation{Operation: p.signHarden()}}); err != nil {
				return
			}
			// Исправления E10-T10 по находкам скана, затем возврат каждого (rollback.restore).
			for i, fx := range p.fixes(m.GetOperationResult().GetSecurityScan()) {
				id := fmt.Sprintf("01a1f4b6-f2f2-7e66-85b4-0000000001%02d", i)
				p.mu.Lock()
				p.pendingFix[id] = fx
				p.mu.Unlock()
				op := p.signRollback(id, "security.fix."+fx.code, &agentv1.OperationParams{Params: &agentv1.OperationParams_SecurityFix{
					SecurityFix: &agentv1.SecurityFixParams{Subjects: fx.subjects}}})
				if err := c.send(ctx, &agentv1.GatewayMessage{Payload: &agentv1.GatewayMessage_Operation{Operation: op}}); err != nil {
					return
				}
			}
		case m.GetOperationResult().GetOperationId() == hardenOperation:
			r := m.GetOperationResult()
			switch r.GetOutcome() {
			case agentv1.OperationOutcome_OPERATION_OUTCOME_AWAITING_CONFIRM:
				p.writeJSON("ssh-await.json", r)
				if err := c.send(ctx, &agentv1.GatewayMessage{Payload: &agentv1.GatewayMessage_Confirm{Confirm: p.confirm(hardenOperation)}}); err != nil {
					return
				}
			case agentv1.OperationOutcome_OPERATION_OUTCOME_SUCCEEDED:
				p.writeJSON("ssh-harden.json", r)
				op := p.signRollback(hardenRevert, "rollback.restore", &agentv1.OperationParams{Params: &agentv1.OperationParams_RollbackRestore{
					RollbackRestore: &agentv1.RollbackRestoreParams{TargetOperationId: hardenOperation}}})
				if err := c.send(ctx, &agentv1.GatewayMessage{Payload: &agentv1.GatewayMessage_Operation{Operation: op}}); err != nil {
					return
				}
			default:
				p.writeJSON("ssh-harden.json", r)
			}
		case m.GetOperationResult().GetOperationId() == hardenRevert:
			p.writeJSON("ssh-revert.json", m.GetOperationResult())
			// firewall (E10-T15/T16): план без порта SSH запирает — отказ; план с SSH, применение, подтверждение, возврат.
			lock := &agentv1.FirewallRuleset{SshPort: 22, Rules: []*agentv1.FirewallRule{
				{Target: agentv1.FirewallTarget_FIREWALL_TARGET_HOST, Protocol: "tcp", Port: 80}}}
			for _, op := range []*agentv1.SignedOperation{
				p.sign(fwLockPlan, "firewall.plan", &agentv1.OperationParams{Params: &agentv1.OperationParams_FirewallPlan{FirewallPlan: &agentv1.FirewallPlanParams{
					Mode: agentv1.FirewallPlanMode_FIREWALL_PLAN_MODE_DIFF, Ruleset: lock}}}),
				p.sign(fwPlan, "firewall.plan", &agentv1.OperationParams{Params: &agentv1.OperationParams_FirewallPlan{FirewallPlan: &agentv1.FirewallPlanParams{
					Mode: agentv1.FirewallPlanMode_FIREWALL_PLAN_MODE_DIFF, Ruleset: ciRuleset()}}}),
			} {
				if err := c.send(ctx, &agentv1.GatewayMessage{Payload: &agentv1.GatewayMessage_Operation{Operation: op}}); err != nil {
					return
				}
			}
		case m.GetOperationResult().GetOperationId() == fwLockPlan:
			p.writeJSON("fw-lock.json", m.GetOperationResult())
		case m.GetOperationResult().GetOperationId() == fwPlan:
			r := m.GetOperationResult()
			p.writeJSON("fw-plan.json", r)
			if r.GetOutcome() == agentv1.OperationOutcome_OPERATION_OUTCOME_SUCCEEDED {
				if err := c.send(ctx, &agentv1.GatewayMessage{Payload: &agentv1.GatewayMessage_Operation{Operation: p.signFirewallApply(r.GetFirewallPlan().GetRulesetHash())}}); err != nil {
					return
				}
			}
		case m.GetOperationResult().GetOperationId() == fwApply:
			r := m.GetOperationResult()
			switch r.GetOutcome() {
			case agentv1.OperationOutcome_OPERATION_OUTCOME_AWAITING_CONFIRM:
				p.writeJSON("fw-await.json", r)
				if err := c.send(ctx, &agentv1.GatewayMessage{Payload: &agentv1.GatewayMessage_Confirm{Confirm: p.confirm(fwApply)}}); err != nil {
					return
				}
			case agentv1.OperationOutcome_OPERATION_OUTCOME_SUCCEEDED:
				p.writeJSON("fw-apply.json", r)
				op := p.signRollback(fwRevert, "rollback.restore", &agentv1.OperationParams{Params: &agentv1.OperationParams_RollbackRestore{
					RollbackRestore: &agentv1.RollbackRestoreParams{TargetOperationId: fwApply}}})
				if err := c.send(ctx, &agentv1.GatewayMessage{Payload: &agentv1.GatewayMessage_Operation{Operation: op}}); err != nil {
					return
				}
			default:
				p.writeJSON("fw-apply.json", r)
			}
		case m.GetOperationResult().GetOperationId() == fwRevert:
			p.writeJSON("fw-revert.json", m.GetOperationResult())
			// Обслуживание (E10-T24): перезапуск службы и обновления безопасности; перезагрузку в контейнере не делаем.
			for _, op := range []*agentv1.SignedOperation{
				p.sign(restartOp, "service.restart", &agentv1.OperationParams{Params: &agentv1.OperationParams_ServiceRestart{
					ServiceRestart: &agentv1.ServiceRestartParams{Unit: "ssh.service"}}}),
				p.sign(upgradeOp, "packages.upgrade", &agentv1.OperationParams{Params: &agentv1.OperationParams_PackagesUpgrade{
					PackagesUpgrade: &agentv1.PackagesUpgradeParams{Scope: agentv1.UpgradeScope_UPGRADE_SCOPE_SECURITY}}}),
				// net.check (E07) исполняет сам агент: соединение с sshd контейнера по его адресу (loopback запрещён).
				p.sign(netCheckOp, "net.check", &agentv1.OperationParams{Params: &agentv1.OperationParams_NetCheck{
					NetCheck: &agentv1.NetCheckParams{Host: ownIPv4(), Port: 22, TimeoutMs: 2000}}}),
			} {
				if err := c.send(ctx, &agentv1.GatewayMessage{Payload: &agentv1.GatewayMessage_Operation{Operation: op}}); err != nil {
					return
				}
			}
		case m.GetOperationResult().GetOperationId() == restartOp:
			p.writeJSON("restart.json", m.GetOperationResult())
		case m.GetOperationResult().GetOperationId() == upgradeOp:
			p.writeJSON("upgrade.json", m.GetOperationResult())
		case m.GetOperationResult().GetOperationId() == netCheckOp:
			p.writeJSON("netcheck.json", m.GetOperationResult())
			// Приватная сеть (E14): ключ хаба, затем apply по ключам узлов от CI (wg-peers.txt), затем remove (wg-remove).
			if err := c.send(ctx, &agentv1.GatewayMessage{Payload: &agentv1.GatewayMessage_Operation{Operation: p.sign(wgKeygenOp, "wireguard.keygen",
				&agentv1.OperationParams{Params: &agentv1.OperationParams_WireguardKeygen{WireguardKeygen: &agentv1.WireguardKeygenParams{IfaceName: "wg0"}}})}}); err != nil {
				return
			}
		case m.GetOperationResult().GetOperationId() == wgKeygenOp:
			r := m.GetOperationResult()
			p.writeJSON("wg-keygen.json", r)
			go p.wireguardFlow(ctx, c, r.GetWireguardKeygen().GetPublicKey())
		case m.GetOperationResult().GetOperationId() == wgApplyOp || m.GetOperationResult().GetOperationId() == wgRemoveOp:
			r := m.GetOperationResult()
			name := "wg-apply"
			if r.GetOperationId() == wgRemoveOp {
				name = "wg-remove"
			}
			if r.GetOutcome() == agentv1.OperationOutcome_OPERATION_OUTCOME_AWAITING_CONFIRM {
				if err := c.send(ctx, &agentv1.GatewayMessage{Payload: &agentv1.GatewayMessage_Confirm{Confirm: p.confirm(r.GetOperationId())}}); err != nil {
					return
				}
				break
			}
			p.writeJSON(name+".json", r)
		case p.isFix(m.GetOperationResult().GetOperationId()):
			r := m.GetOperationResult()
			fx := p.takeFix(r.GetOperationId())
			p.writeJSON("fix-"+fx.code+".json", r)
			if r.GetOutcome() == agentv1.OperationOutcome_OPERATION_OUTCOME_SUCCEEDED {
				id := strings.Replace(r.GetOperationId(), "-0000000001", "-0000000002", 1)
				p.mu.Lock()
				p.pendingRevert[id] = fx.code
				p.mu.Unlock()
				op := p.signRollback(id, "rollback.restore", &agentv1.OperationParams{Params: &agentv1.OperationParams_RollbackRestore{
					RollbackRestore: &agentv1.RollbackRestoreParams{TargetOperationId: r.GetOperationId()}}})
				if err := c.send(ctx, &agentv1.GatewayMessage{Payload: &agentv1.GatewayMessage_Operation{Operation: op}}); err != nil {
					return
				}
			}
		case p.isRevert(m.GetOperationResult().GetOperationId()):
			r := m.GetOperationResult()
			p.mu.Lock()
			code := p.pendingRevert[r.GetOperationId()]
			p.mu.Unlock()
			p.writeJSON("revert-"+code+".json", r)
		case m.GetOperationResult().GetOperationId() == updatesOperation:
			p.writeJSON("packages.json", m.GetOperationResult())
		case m.GetMetrics() != nil:
			if names != nil {
				break
			}
			b := m.GetMetrics()
			names = []string{}
			for _, x := range b.GetMetrics() {
				names = append(names, x.GetName())
			}
			if d := time.Since(time.UnixMilli(b.GetCollectedAtMs())); d > time.Minute || d < -time.Minute {
				p.result(h, nil, nil, fmt.Sprintf("время пачки метрик сбито на %s", d))
				return
			}
		default:
			continue
		}
		_ = c.send(ctx, &agentv1.GatewayMessage{Payload: &agentv1.GatewayMessage_InboundAck{InboundAck: &agentv1.InboundAck{Seq: m.GetSeq()}}})
		if !written && res != nil && names != nil {
			p.result(h, res, names, "")
			written = true
		}
	}
}

func (p *panel) systemInfo() *agentv1.SignedOperation {
	return p.sign(operation, "system.info", &agentv1.OperationParams{Params: &agentv1.OperationParams_SystemInfo{SystemInfo: &agentv1.SystemInfoParams{}}})
}

func (p *panel) sign(id, typ string, params *agentv1.OperationParams) *agentv1.SignedOperation {
	return p.signKind(id, typ, params, agentv1.RollbackKind_ROLLBACK_KIND_NONE)
}

func (p *panel) signRollback(id, typ string, params *agentv1.OperationParams) *agentv1.SignedOperation {
	return p.signKind(id, typ, params, agentv1.RollbackKind_ROLLBACK_KIND_CONFIG)
}

type fix struct {
	code     string
	subjects []string
}

// fixes — что исправляет матрица: файл, доступный всем на запись (его создаёт CI), параметры ядра из находок
// скана и защита от перебора (ставит fail2ban из репозитория системы).
func (p *panel) fixes(res *agentv1.SecurityScanResult) []fix {
	by := map[string][]string{}
	for _, c := range res.GetChecks() {
		if c.GetState() == agentv1.CheckState_CHECK_STATE_FAIL {
			by[c.GetCode()] = append(by[c.GetCode()], c.GetSubject())
		}
	}
	var out []fix
	for _, code := range []string{"PERM_WORLD_WRITABLE", "SYSCTL_NETWORK", "BRUTEFORCE_NO_PROTECTION"} {
		if len(by[code]) > 0 {
			out = append(out, fix{code: code, subjects: by[code]})
		}
	}
	return out
}

func (p *panel) isFix(id string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	_, ok := p.pendingFix[id]
	return ok
}

func (p *panel) takeFix(id string) fix {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.pendingFix[id]
}

func (p *panel) isRevert(id string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	_, ok := p.pendingRevert[id]
	return ok
}

func (p *panel) signKind(id, typ string, params *agentv1.OperationParams, rb agentv1.RollbackKind) *agentv1.SignedOperation {
	now := time.Now()
	n := make([]byte, 16)
	_, _ = rand.Read(n)
	body, _ := proto.Marshal(&agentv1.OperationBody{
		OperationId: id, ServerId: serverID, Type: typ, Nonce: n, Params: params,
		NotAfterMs: now.Add(5 * time.Minute).UnixMilli(), IssuedAtMs: now.UnixMilli(), Rollback: rb,
	})
	return &agentv1.SignedOperation{Body: body, KeyId: panelKeyID, Signature: ed25519.Sign(p.panel, verify.Input(verify.ContextOperation, body))}
}

// writeJSON пишет сообщение в <out>/name (protojson: файл читает jq, а не grep).
func (p *panel) writeJSON(name string, m proto.Message) {
	b, _ := protojson.MarshalOptions{UseProtoNames: true}.Marshal(m)
	if err := os.WriteFile(filepath.Join(p.out, name), append(b, '\n'), 0o600); err != nil {
		log.Printf("%s: %v", name, err)
	}
}

// logChunk дописывает записи пачки журналов строками JSON в <out>/logs.jsonl.
func (p *panel) logChunk(ch *agentv1.LogChunk) {
	f, err := os.OpenFile(filepath.Join(p.out, "logs.jsonl"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		log.Printf("logs.jsonl: %v", err)
		return
	}
	defer f.Close()
	for _, r := range ch.GetRecords() {
		b, _ := json.Marshal(map[string]any{"subscription": ch.GetSubscriptionId(), "seq": ch.GetSeq(), "level": r.GetLevel().String(),
			"source": r.GetSource().GetName(), "message": r.GetMessage(), "time_ms": r.GetTimeMs()})
		_, _ = f.Write(append(b, '\n'))
	}
	log.Printf("журналы: пачка %d, записей %d", ch.GetSeq(), len(ch.GetRecords()))
}

// result пишет итог прогона: hello, итог операции и ошибку, если была.
func (p *panel) result(h *agentv1.Hello, res *agentv1.OperationResult, metrics []string, problem string) {
	mo := protojson.MarshalOptions{UseProtoNames: true}
	hello, _ := mo.Marshal(&agentv1.Hello{Os: h.GetOs(), OsVersion: h.GetOsVersion(), Arch: h.GetArch(),
		AgentVersion: h.GetAgentVersion(), HelperVersion: h.GetHelperVersion(), Capabilities: h.GetCapabilities()})
	var resJSON json.RawMessage = []byte("null")
	if res != nil {
		resJSON, _ = mo.Marshal(res)
	}
	b, _ := json.MarshalIndent(map[string]any{"problem": problem, "hello": json.RawMessage(hello), "result": resJSON, "metrics": metrics}, "", "  ")
	if err := os.WriteFile(filepath.Join(p.out, "result.json"), append(b, '\n'), 0o600); err != nil {
		log.Printf("result.json: %v", err)
	}
	log.Printf("итог записан: %s", b)
}

// event дописывает событие агента строкой JSON в <out>/events.jsonl (E08-T12).
func (p *panel) event(e *agentv1.Event) {
	// encoding/json, а не protojson: у protojson пробелы в выводе намеренно случайны, а CI ищет строки grep.
	b, err := json.Marshal(map[string]any{"kind": e.GetKind(), "severity": e.GetSeverity().String(), "at_ms": e.GetAtMs(), "attributes": e.GetAttributes()})
	if err != nil {
		return
	}
	f, err := os.OpenFile(filepath.Join(p.out, "events.jsonl"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		log.Printf("events.jsonl: %v", err)
		return
	}
	defer f.Close()
	_, _ = f.Write(append(b, '\n'))
	log.Printf("событие: %s", b)
}

// signHarden — ssh.harden без смены пароля и порта (в контейнере нет ключей): попытки входа, пустые пароли,
// строгая криптография; автооткат 120 с.
func (p *panel) signHarden() *agentv1.SignedOperation {
	now := time.Now()
	n := make([]byte, 16)
	_, _ = rand.Read(n)
	f := false
	body, _ := proto.Marshal(&agentv1.OperationBody{
		OperationId: hardenOperation, ServerId: serverID, Type: "ssh.harden", Nonce: n,
		Params: &agentv1.OperationParams{Params: &agentv1.OperationParams_SshHarden{SshHarden: &agentv1.SshHardenParams{
			MaxAuthTries: 3, EmptyPasswords: &f, CryptoPreset: agentv1.CryptoPreset_CRYPTO_PRESET_STRICT}}},
		NotAfterMs: now.Add(5 * time.Minute).UnixMilli(), IssuedAtMs: now.UnixMilli(),
		Rollback: agentv1.RollbackKind_ROLLBACK_KIND_CONFIG, ConfirmWithinSec: 120,
	})
	return &agentv1.SignedOperation{Body: body, KeyId: panelKeyID, Signature: ed25519.Sign(p.panel, verify.Input(verify.ContextOperation, body))}
}

// confirm — SignedConfirm операции op (панель шлёт его после нового соединения агента; заглушке хватает этого).
func (p *panel) confirm(op string) *agentv1.SignedConfirm {
	n := make([]byte, 16)
	_, _ = rand.Read(n)
	body, _ := proto.Marshal(&agentv1.ConfirmBody{OperationId: op, ServerId: serverID, Nonce: n, NotAfterMs: time.Now().Add(time.Minute).UnixMilli()})
	return &agentv1.SignedConfirm{Body: body, KeyId: panelKeyID, Signature: ed25519.Sign(p.panel, verify.Input(verify.ContextConfirm, body))}
}

// ciRuleset — SSH и веб; канал заглушки идёт по lo и фильтром не затрагивается.
func ciRuleset() *agentv1.FirewallRuleset {
	return &agentv1.FirewallRuleset{SshPort: 22, Rules: []*agentv1.FirewallRule{
		{Target: agentv1.FirewallTarget_FIREWALL_TARGET_HOST, Protocol: "tcp", Port: 22, Comment: "SSH"},
		{Target: agentv1.FirewallTarget_FIREWALL_TARGET_BOTH, Protocol: "tcp", Port: 443},
		{Target: agentv1.FirewallTarget_FIREWALL_TARGET_CONTAINERS, Protocol: "tcp", Port: 8080, Sources: []string{"203.0.113.0/24"}},
	}}
}

func (p *panel) signFirewallApply(hash string) *agentv1.SignedOperation {
	now := time.Now()
	n := make([]byte, 16)
	_, _ = rand.Read(n)
	body, _ := proto.Marshal(&agentv1.OperationBody{
		OperationId: fwApply, ServerId: serverID, Type: "firewall.apply", Nonce: n,
		Params: &agentv1.OperationParams{Params: &agentv1.OperationParams_FirewallApply{FirewallApply: &agentv1.FirewallApplyParams{
			Ruleset: ciRuleset(), RulesetHash: hash, Mode: agentv1.FirewallApplyMode_FIREWALL_APPLY_MODE_APPLY}}},
		NotAfterMs: now.Add(5 * time.Minute).UnixMilli(), IssuedAtMs: now.UnixMilli(),
		Rollback: agentv1.RollbackKind_ROLLBACK_KIND_CONFIG, ConfirmWithinSec: 120,
	})
	return &agentv1.SignedOperation{Body: body, KeyId: panelKeyID, Signature: ed25519.Sign(p.panel, verify.Input(verify.ContextOperation, body))}
}

// ownIPv4 — первый адрес IPv4 интерфейса контейнера, не loopback.
func ownIPv4() string {
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil && !n.IP.IsLoopback() && !n.IP.IsLinkLocalUnicast() {
			return n.IP.String()
		}
	}
	return "192.0.2.1"
}

// wireguardFlow — хаб wg0 10.77.0.1/24 с пересылкой и двумя узлами (их ключи CI кладёт в wg-peers.txt); после
// проверок CI (файл wg-remove) — удаление. Оба шага с автооткатом и подтверждением.
func (p *panel) wireguardFlow(ctx context.Context, c *conn, hub string) {
	wait := func(name string) []byte {
		for i := 0; i < 300; i++ {
			if b, err := os.ReadFile(filepath.Join(p.out, name)); err == nil && len(b) > 0 {
				return b
			}
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(time.Second):
			}
		}
		return nil
	}
	keys := strings.Fields(string(wait("wg-peers.txt")))
	if len(keys) != 2 {
		log.Printf("wg-peers.txt: %v", keys)
		return
	}
	params := &agentv1.WireguardApplyParams{IfaceName: "wg0", Address: "10.77.0.1/24", ListenPort: 51820, ExpectPublicKey: hub, Forwarding: true,
		Peers: []*agentv1.WireguardPeer{
			{PublicKey: keys[0], AllowedIps: []string{"10.77.0.2/32"}},
			{PublicKey: keys[1], AllowedIps: []string{"10.77.0.3/32"}},
		},
		Hosts: []*agentv1.HostEntry{{Fqdn: "a.ci.internal", Address: "10.77.0.2"}, {Fqdn: "b.ci.internal", Address: "10.77.0.3"}}}
	if err := c.send(ctx, &agentv1.GatewayMessage{Payload: &agentv1.GatewayMessage_Operation{Operation: p.signConfirm(wgApplyOp, "wireguard.apply",
		&agentv1.OperationParams{Params: &agentv1.OperationParams_WireguardApply{WireguardApply: params}})}}); err != nil {
		return
	}
	if wait("wg-remove") == nil {
		return
	}
	_ = c.send(ctx, &agentv1.GatewayMessage{Payload: &agentv1.GatewayMessage_Operation{Operation: p.signConfirm(wgRemoveOp, "wireguard.remove",
		&agentv1.OperationParams{Params: &agentv1.OperationParams_WireguardRemove{WireguardRemove: &agentv1.WireguardRemoveParams{IfaceName: "wg0"}}})}})
}

// signConfirm — операция CONFIG с автооткатом 120 с.
func (p *panel) signConfirm(id, typ string, params *agentv1.OperationParams) *agentv1.SignedOperation {
	now := time.Now()
	n := make([]byte, 16)
	_, _ = rand.Read(n)
	body, _ := proto.Marshal(&agentv1.OperationBody{
		OperationId: id, ServerId: serverID, Type: typ, Nonce: n, Params: params,
		NotAfterMs: now.Add(5 * time.Minute).UnixMilli(), IssuedAtMs: now.UnixMilli(),
		Rollback: agentv1.RollbackKind_ROLLBACK_KIND_CONFIG, ConfirmWithinSec: 120,
	})
	return &agentv1.SignedOperation{Body: body, KeyId: panelKeyID, Signature: ed25519.Sign(p.panel, verify.Input(verify.ContextOperation, body))}
}
