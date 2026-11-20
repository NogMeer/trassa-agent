// SPDX-License-Identifier: AGPL-3.0-only

// Заглушка панели для матрицы ОС в CI (E05-T28). Только для одноразового контейнера CI: свой УЦ, тестовый ключ
// выпуска и тестовый ключ панели создаются при запуске и живут до конца прогона. Отдаёт то же, что настоящая панель:
// install.sh, манифест выпуска, файлы выпуска с подписью minisign, регистрацию и шлюз WSS. Шлюз проводит рукопожатие,
// отправляет подписанную операцию system.info и записывает итог в <out>/result.json.
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
	"github.com/NogMeer/trassa-agent/internal/verify"
)

const (
	serverID   = "01a1f4b6-f327-7a5d-ac23-e95c272c0fe8"
	operation  = "01a1f4b6-f2f2-7e66-85b4-000000000001"
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
	seq uint64
}

func (c *conn) send(ctx context.Context, m *agentv1.GatewayMessage) error {
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
	for {
		m, err := c.read(ctx)
		if err != nil {
			log.Printf("соединение: %v", err)
			return
		}
		if a := m.GetOperationAck(); a != nil && !a.GetAccepted() {
			p.result(h, nil, "отказ помощника: "+a.GetRejectCode())
			return
		}
		res := m.GetOperationResult()
		if res == nil || res.GetOperationId() != operation {
			continue
		}
		_ = c.send(ctx, &agentv1.GatewayMessage{Payload: &agentv1.GatewayMessage_InboundAck{InboundAck: &agentv1.InboundAck{Seq: m.GetSeq()}}})
		p.result(h, res, "")
		// Соединение держится: агент продолжает пульс, пока CI не удалит его.
		for {
			if _, err := c.read(ctx); err != nil {
				return
			}
		}
	}
}

func (p *panel) systemInfo() *agentv1.SignedOperation {
	now := time.Now()
	n := make([]byte, 16)
	_, _ = rand.Read(n)
	body, _ := proto.Marshal(&agentv1.OperationBody{
		OperationId: operation, ServerId: serverID, Type: "system.info", Nonce: n,
		Params:     &agentv1.OperationParams{Params: &agentv1.OperationParams_SystemInfo{SystemInfo: &agentv1.SystemInfoParams{}}},
		NotAfterMs: now.Add(5 * time.Minute).UnixMilli(), IssuedAtMs: now.UnixMilli(), Rollback: agentv1.RollbackKind_ROLLBACK_KIND_NONE,
	})
	return &agentv1.SignedOperation{Body: body, KeyId: panelKeyID, Signature: ed25519.Sign(p.panel, verify.Input(verify.ContextOperation, body))}
}

// result пишет итог прогона: hello, итог операции и ошибку, если была.
func (p *panel) result(h *agentv1.Hello, res *agentv1.OperationResult, problem string) {
	mo := protojson.MarshalOptions{UseProtoNames: true}
	hello, _ := mo.Marshal(&agentv1.Hello{Os: h.GetOs(), OsVersion: h.GetOsVersion(), Arch: h.GetArch(),
		AgentVersion: h.GetAgentVersion(), HelperVersion: h.GetHelperVersion(), Capabilities: h.GetCapabilities()})
	var resJSON json.RawMessage = []byte("null")
	if res != nil {
		resJSON, _ = mo.Marshal(res)
	}
	b, _ := json.MarshalIndent(map[string]any{"problem": problem, "hello": json.RawMessage(hello), "result": resJSON}, "", "  ")
	if err := os.WriteFile(filepath.Join(p.out, "result.json"), append(b, '\n'), 0o600); err != nil {
		log.Printf("result.json: %v", err)
	}
	log.Printf("итог записан: %s", b)
}
