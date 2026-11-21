// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

const (
	tokA = "trc_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	tokB = "trc_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
	dev  = "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD"
	wsID = "11111111-1111-1111-1111-111111111111"
	srvA = "22222222-2222-2222-2222-222222222222"
)

// fakeKeyring — системное хранилище в памяти; fail — хранилища нет (сервер без D-Bus).
type fakeKeyring struct {
	mu   sync.Mutex
	m    map[string]string
	fail error
}

func (k *fakeKeyring) Get(s, u string) (string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.fail != nil {
		return "", k.fail
	}
	v, ok := k.m[s+"|"+u]
	if !ok {
		return "", ErrKeyringNotFound
	}
	return v, nil
}

func (k *fakeKeyring) Set(s, u, p string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.fail != nil {
		return k.fail
	}
	if k.m == nil {
		k.m = map[string]string{}
	}
	k.m[s+"|"+u] = p
	return nil
}

func (k *fakeKeyring) Delete(s, u string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.fail != nil {
		return k.fail
	}
	if _, ok := k.m[s+"|"+u]; !ok {
		return ErrKeyringNotFound
	}
	delete(k.m, s+"|"+u)
	return nil
}

// panel — поддельная панель: маршруты CLI и доступа.
type panel struct {
	t        *testing.T
	mu       sync.Mutex
	srv      *httptest.Server
	polls    []func(w http.ResponseWriter) // ответы /v1/cli/token по очереди
	tokens   map[string]string             // токен → id входа CLI
	revoked  []string
	servers  []myServer
	cert     func(pub string) certReply
	wsHello  []map[string]any
	ws       func(n int, c *websocket.Conn)
	tickets  int
	renewals int
	renew    func(w http.ResponseWriter)
	lastBody map[string]any
}

func newPanel(t *testing.T) *panel {
	p := &panel{t: t, tokens: map[string]string{tokA: "cs-a", tokB: "cs-b"}}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/cli/login", func(w http.ResponseWriter, r *http.Request) {
		var b map[string]any
		_ = json.NewDecoder(r.Body).Decode(&b)
		p.lastBody = b
		writeJSON(w, 200, map[string]any{"deviceCode": dev, "userCode": "CDFG-2347",
			"verifyUrl": p.srv.URL + "/cli/approve?code=CDFG-2347", "interval": 5, "expiresAt": time.Now().Add(10 * time.Minute)})
	})
	mux.HandleFunc("POST /v1/cli/token", func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		defer p.mu.Unlock()
		if len(p.polls) == 0 {
			writeJSON(w, 410, map[string]any{"code": "CLI_CODE_EXPIRED", "message": "expired"})
			return
		}
		f := p.polls[0]
		p.polls = p.polls[1:]
		f(w)
	})
	mux.HandleFunc("GET /v1/cli/me", func(w http.ResponseWriter, r *http.Request) {
		id, ok := p.auth(w, r)
		if !ok {
			return
		}
		writeJSON(w, 200, map[string]any{
			"user":       map[string]any{"id": "u1", "name": "Анна", "email": "anna@example.com"},
			"cliSession": map[string]any{"id": id, "name": "MacBook", "createdAt": time.Now(), "expiresAt": time.Now().Add(90 * 24 * time.Hour)},
			"workspaces": []map[string]any{{"id": wsID, "name": "Мои", "slug": "mine", "role": "OWNER"}},
		})
	})
	mux.HandleFunc("DELETE /v1/cli/sessions/{id}", func(w http.ResponseWriter, r *http.Request) {
		id, ok := p.auth(w, r)
		if !ok {
			return
		}
		if r.PathValue("id") != id {
			writeJSON(w, 404, map[string]any{"code": "NOT_FOUND"})
			return
		}
		p.mu.Lock()
		p.revoked = append(p.revoked, id)
		for k, v := range p.tokens {
			if v == id {
				delete(p.tokens, k)
			}
		}
		p.mu.Unlock()
		w.WriteHeader(204)
	})
	mux.HandleFunc("GET /v1/workspaces/{ws}/access/my-servers", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := p.auth(w, r); !ok {
			return
		}
		writeJSON(w, 200, map[string]any{"items": p.servers})
	})
	mux.HandleFunc("POST /v1/workspaces/{ws}/access/certificates", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := p.auth(w, r); !ok {
			return
		}
		var b map[string]string
		_ = json.NewDecoder(r.Body).Decode(&b)
		writeJSON(w, 201, p.cert(b["publicKey"]))
	})
	mux.HandleFunc("POST /v1/workspaces/{ws}/access/sessions", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := p.auth(w, r); !ok {
			return
		}
		var b map[string]any
		_ = json.NewDecoder(r.Body).Decode(&b)
		p.lastBody = b
		writeJSON(w, 201, map[string]any{"sessionId": "s1", "ticket": "t0", "recording": true, "passExpiresAt": time.Now().Add(10 * time.Minute),
			"unixUser": "ops", "sudo": false, "server": map[string]any{"id": srvA, "name": "web-1"}})
	})
	mux.HandleFunc("POST /v1/workspaces/{ws}/access/sessions/{id}/ticket", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := p.auth(w, r); !ok {
			return
		}
		p.mu.Lock()
		p.tickets++
		n := p.tickets
		p.mu.Unlock()
		writeJSON(w, 200, map[string]any{"ticket": "t" + string(rune('0'+n)), "ticketExpiresAt": time.Now().Add(30 * time.Second)})
	})
	mux.HandleFunc("POST /v1/workspaces/{ws}/access/sessions/{id}/renew", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := p.auth(w, r); !ok {
			return
		}
		p.mu.Lock()
		p.renewals++
		p.mu.Unlock()
		p.renew(w)
	})
	mux.HandleFunc("POST /v1/workspaces/{ws}/access/sessions/{id}/terminate", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(204)
	})
	mux.HandleFunc("GET /v1/ws/terminal", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Origin") != "" || r.Header.Get("Authorization") != "" {
			t.Errorf("окно терминала: Origin %q, Authorization %q", r.Header.Get("Origin"), r.Header.Get("Authorization"))
		}
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer c.CloseNow()
		_, data, err := c.Read(r.Context())
		if err != nil {
			return
		}
		var hello map[string]any
		_ = json.Unmarshal(data, &hello)
		p.mu.Lock()
		p.wsHello = append(p.wsHello, hello)
		n := len(p.wsHello)
		p.mu.Unlock()
		p.ws(n, c)
	})
	p.srv = httptest.NewServer(mux)
	t.Cleanup(p.srv.Close)
	return p
}

func (p *panel) auth(w http.ResponseWriter, r *http.Request) (string, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	id, ok := p.tokens[tok]
	if !ok {
		writeJSON(w, 401, map[string]any{"code": "CLI_SESSION_REVOKED", "message": "revoked"})
	}
	return id, ok
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func pending(w http.ResponseWriter) { writeJSON(w, 200, map[string]any{"pending": true}) }

func newApp(t *testing.T, p *panel) (*App, *bytes.Buffer, *bytes.Buffer, *[]time.Duration) {
	t.Helper()
	var out, errb bytes.Buffer
	var sleeps []time.Duration
	a := &App{
		Stdout: &out, Stderr: &errb,
		Env:       func(string) string { return "" },
		ConfigDir: t.TempDir(),
		Keyring:   &fakeKeyring{},
		HTTP:      NewHTTPClient(),
		Version:   "test",
		Lang:      LangRU,
		Sleep: func(ctx context.Context, d time.Duration) error {
			sleeps = append(sleeps, d)
			return ctx.Err()
		},
		Hostname: func() (string, error) { return "MacBook\x1b[31m Анны", nil },
		GOOS:     runtime.GOOS,
	}
	return a, &out, &errb, &sleeps
}

func loggedIn(t *testing.T, a *App, p *panel, tok string) {
	t.Helper()
	u, _ := normalizeBase(p.srv.URL)
	if _, _, err := a.store().set(u.String(), tok); err != nil {
		t.Fatal(err)
	}
	if err := saveConfig(a.ConfigDir, &Config{URL: u.String(), Workspace: "mine"}); err != nil {
		t.Fatal(err)
	}
}

func TestNormalizeBase(t *testing.T) {
	ok := map[string]string{
		"app.example.com":              "https://app.example.com",
		"https://App.Example.com/":     "https://app.example.com",
		"https://app.example.com:8443": "https://app.example.com:8443",
		"http://localhost:3000":        "http://localhost:3000",
		"http://127.0.0.1:4000":        "http://127.0.0.1:4000",
		"http://[::1]:4000":            "http://[::1]:4000",
	}
	for in, want := range ok {
		u, err := normalizeBase(in)
		if err != nil || u.String() != want {
			t.Errorf("%s: %v %v, нужно %s", in, u, err, want)
		}
	}
	for _, in := range []string{"", "http://app.example.com", "https://u:p@app.example.com", "https://app.example.com/panel",
		"https://app.example.com/?x=1", "https://app.example.com/#f", "ftp://app.example.com", "https://", "http://10.0.0.1"} {
		if _, err := normalizeBase(in); err == nil {
			t.Errorf("%s: принят", in)
		}
	}
}

func TestLoginApprove(t *testing.T) {
	p := newPanel(t)
	p.polls = []func(http.ResponseWriter){pending, pending, func(w http.ResponseWriter) {
		writeJSON(w, 200, map[string]any{"token": tokA, "expiresAt": time.Now().Add(90 * 24 * time.Hour)})
	}}
	a, out, errb, sleeps := newApp(t, p)
	if err := a.Login(context.Background(), p.srv.URL, ""); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(errb.String(), "CDFG-2347") || !strings.Contains(errb.String(), "/cli/approve?code=CDFG-2347") {
		t.Fatalf("нет кода и ссылки: %q", errb.String())
	}
	if p.lastBody["name"] != "MacBook[31m Анны" {
		t.Fatalf("имя компьютера без управляющих символов: %q", p.lastBody["name"])
	}
	if len(*sleeps) != 3 || (*sleeps)[0] != 5*time.Second {
		t.Fatalf("опрос: %v", *sleeps)
	}
	u, _ := normalizeBase(p.srv.URL)
	if tok, err := a.store().get(u.String()); err != nil || tok != tokA {
		t.Fatalf("токен: %q %v", tok, err)
	}
	if _, err := os.Stat(filepath.Join(a.ConfigDir, credentialsFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("при системном хранилище файла токенов нет: %v", err)
	}
	cfg, _ := loadConfig(a.ConfigDir)
	if cfg.URL != u.String() || cfg.Workspace != "mine" {
		t.Fatalf("настройки: %+v", cfg)
	}
	if strings.Contains(out.String()+errb.String(), tokA) {
		t.Fatal("токен напечатан")
	}
}

func TestLoginSlowDownDeniedExpired(t *testing.T) {
	p := newPanel(t)
	p.polls = []func(http.ResponseWriter){
		func(w http.ResponseWriter) {
			writeJSON(w, 429, map[string]any{"code": "CLI_SLOW_DOWN", "message": "slow", "details": map[string]any{"interval": 5}})
		},
		pending,
		func(w http.ResponseWriter) {
			writeJSON(w, 403, map[string]any{"code": "CLI_DENIED", "message": "denied"})
		},
	}
	a, _, _, sleeps := newApp(t, p)
	err := a.Login(context.Background(), p.srv.URL, "pc")
	if err == nil || a.Explain(err) != a.t("err.denied") {
		t.Fatalf("отказ: %v", err)
	}
	if want := []time.Duration{5 * time.Second, 5 * time.Second, 10 * time.Second}; len(*sleeps) != 3 || (*sleeps)[2] != want[2] {
		t.Fatalf("после slow_down интервал +5 с: %v", *sleeps)
	}

	p.polls = nil // 410
	a2, _, _, _ := newApp(t, p)
	if err := a2.Login(context.Background(), p.srv.URL, "pc"); err == nil || a2.Explain(err) != a2.t("err.code_expired") {
		t.Fatalf("просрочка: %v", err)
	}
	u, _ := normalizeBase(p.srv.URL)
	if _, err := a2.store().get(u.String()); err == nil {
		t.Fatal("токен сохранён без входа")
	}
}

func TestLoginRejectsBadToken(t *testing.T) {
	p := newPanel(t)
	p.polls = []func(http.ResponseWriter){func(w http.ResponseWriter) {
		writeJSON(w, 200, map[string]any{"token": "trc_short", "expiresAt": time.Now()})
	}}
	a, _, _, _ := newApp(t, p)
	if err := a.Login(context.Background(), p.srv.URL, "pc"); !errors.Is(err, errBadResponse) {
		t.Fatalf("токен не по формату: %v", err)
	}
}

func TestLoginRevokesPrevious(t *testing.T) {
	p := newPanel(t)
	p.polls = []func(http.ResponseWriter){func(w http.ResponseWriter) {
		writeJSON(w, 200, map[string]any{"token": tokB, "expiresAt": time.Now().Add(time.Hour)})
	}}
	a, _, _, _ := newApp(t, p)
	loggedIn(t, a, p, tokA)
	if err := a.Login(context.Background(), "", "pc"); err != nil {
		t.Fatal(err)
	}
	if len(p.revoked) != 1 || p.revoked[0] != "cs-a" {
		t.Fatalf("прежний вход не отозван: %v", p.revoked)
	}
}

func TestTokenStoreFileFallback(t *testing.T) {
	dir := t.TempDir()
	s := &tokenStore{kr: &fakeKeyring{fail: errors.New("no dbus")}, dir: dir}
	inFile, kerr, err := s.set("https://a", tokA)
	if err != nil || !inFile || kerr == nil {
		t.Fatalf("set: %v %v %v", inFile, kerr, err)
	}
	st, err := os.Stat(s.path())
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && st.Mode().Perm() != 0o600 {
		t.Fatalf("права %o", st.Mode().Perm())
	}
	if tok, err := s.get("https://a"); err != nil || tok != tokA {
		t.Fatalf("get: %q %v", tok, err)
	}
	if runtime.GOOS != "windows" {
		_ = os.Chmod(s.path(), 0o644)
		if _, err := s.get("https://a"); err == nil {
			t.Fatal("файл с правами 0644 прочитан")
		}
		_ = os.Chmod(s.path(), 0o600)
	}
	if err := s.delete("https://a"); err != nil {
		t.Fatal(err)
	}
	var nt *noToken
	if _, err := s.get("https://a"); !errors.As(err, &nt) {
		t.Fatalf("после удаления: %v", err)
	}
	if _, err := os.Stat(s.path()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("пустой файл токенов не удалён")
	}
	if _, _, err := s.set("https://a", "not-a-token"); err == nil {
		t.Fatal("не токен сохранён")
	}
}

func TestLogout(t *testing.T) {
	p := newPanel(t)
	a, out, _, _ := newApp(t, p)
	loggedIn(t, a, p, tokA)
	if err := a.Logout(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(p.revoked) != 1 || !strings.Contains(out.String(), "отозван") {
		t.Fatalf("logout: %v %q", p.revoked, out.String())
	}
	u, _ := normalizeBase(p.srv.URL)
	if _, err := a.store().get(u.String()); err == nil {
		t.Fatal("токен остался")
	}

	// Панель недоступна: токен удаляется, человеку сказано, где отозвать вход.
	a2, out2, _, _ := newApp(t, p)
	loggedIn(t, a2, p, tokB)
	p.srv.Close()
	if err := a2.Logout(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := a2.store().get(u.String()); err == nil || !strings.Contains(out2.String(), "Со своего компьютера") {
		t.Fatalf("без панели: %v %q", err, out2.String())
	}
}

func TestRevokedTokenAsksRelogin(t *testing.T) {
	p := newPanel(t)
	a, _, _, _ := newApp(t, p)
	loggedIn(t, a, p, "trc_CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC")
	err := a.Servers(context.Background(), "")
	if err == nil || a.Explain(err) != a.t("err.relogin") {
		t.Fatalf("отозванный вход: %v", err)
	}
}

func TestServersAndResolve(t *testing.T) {
	p := newPanel(t)
	p.servers = []myServer{
		{ServerID: srvA, Name: "web-1", Online: true, Logins: []login{{UnixUser: "ops", Ready: true}, {UnixUser: "deploy", Sudo: true, Ready: true}}},
		{ServerID: "33333333-3333-3333-3333-333333333333", Name: "Web-1", Logins: []login{{UnixUser: "ops"}}},
		{ServerID: "44444444-4444-4444-4444-444444444444", Name: "evil\x1b]0;x\x07", Logins: []login{{UnixUser: "ops"}}},
	}
	a, out, _, _ := newApp(t, p)
	loggedIn(t, a, p, tokA)
	if err := a.Servers(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "\x1b") || !strings.Contains(out.String(), "deploy (sudo)") {
		t.Fatalf("список: %q", out.String())
	}
	if s, err := a.resolveServer(p.servers, "web-1"); err != nil || s.ServerID != srvA {
		t.Fatalf("точное имя важнее совпадения без регистра: %v %v", s, err)
	}
	if s, err := a.resolveServer(p.servers, "44444444-4444-4444-4444-444444444444"); err != nil || s.Name == "" {
		t.Fatalf("точное имя: %v %v", s, err)
	}
	if _, err := a.resolveServer(p.servers, "WEB-1"); err == nil {
		t.Fatal("два совпадения без учёта регистра — нужна ошибка")
	}
	if _, err := a.resolveServer(p.servers, "db"); err == nil || err.Error() != a.t("err.no_grant") {
		t.Fatalf("нет сервера: %v", err)
	}
	if _, err := a.pickLogin(p.servers[0], ""); err == nil {
		t.Fatal("несколько логинов без -l — нужен выбор")
	}
	if u, err := a.pickLogin(p.servers[0], "deploy"); err != nil || u != "deploy" {
		t.Fatalf("-l deploy: %v %v", u, err)
	}
	if _, err := a.pickLogin(p.servers[0], "root"); err == nil {
		t.Fatal("чужой логин принят")
	}
}

// testCA — сертификат как у панели (ca/ssh-cert.ts).
func testCert(t *testing.T, subject ssh.PublicKey, typ uint32, valid time.Duration) string {
	t.Helper()
	_, caPriv, _ := ed25519Key(t)
	signer, err := ssh.NewSignerFromKey(caPriv)
	if err != nil {
		t.Fatal(err)
	}
	c := &ssh.Certificate{Key: subject, CertType: typ, KeyId: "trassa:w:m:1", ValidPrincipals: []string{"trassa:w:m-abc"},
		ValidAfter: uint64(time.Now().Add(-30 * time.Second).Unix()), ValidBefore: uint64(time.Now().Add(valid).Unix()),
		Permissions: ssh.Permissions{Extensions: map[string]string{"permit-pty": ""}}}
	if err := c.SignCert(rand.Reader, signer); err != nil {
		t.Fatal(err)
	}
	return string(ssh.MarshalAuthorizedKey(c))
}

func hostKey(t *testing.T) string {
	pub, _, _ := ed25519Key(t)
	k, _ := ssh.NewPublicKey(pub)
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k)))
}

func TestCheckCert(t *testing.T) {
	pub, _, _ := ed25519Key(t)
	me, _ := ssh.NewPublicKey(pub)
	other, _, _ := ed25519Key(t)
	otherKey, _ := ssh.NewPublicKey(other)
	host := "203.0.113.7"
	good := func() *certReply {
		return &certReply{Certificate: testCert(t, me, ssh.UserCert, 10*time.Minute), UnixUser: "ops", Host: &host, Port: 2222,
			HostKeys: []string{hostKey(t)}}
	}
	tg, err := checkCert(good(), me, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	kh := string(knownHosts(tg))
	if !strings.HasPrefix(kh, "[203.0.113.7]:2222 ssh-ed25519 ") {
		t.Fatalf("known_hosts: %q", kh)
	}
	cases := map[string]func(r *certReply){
		"чужой ключ":           func(r *certReply) { r.Certificate = testCert(t, otherKey, ssh.UserCert, time.Minute) },
		"сертификат хоста":     func(r *certReply) { r.Certificate = testCert(t, me, ssh.HostCert, time.Minute) },
		"истёк":                func(r *certReply) { r.Certificate = testCert(t, me, ssh.UserCert, -time.Second) },
		"нет ключей хоста":     func(r *certReply) { r.HostKeys = nil },
		"ключ хоста — мусор":   func(r *certReply) { r.HostKeys = []string{"ssh-ed25519 AAAA"} },
		"ключ хоста с хвостом": func(r *certReply) { r.HostKeys = []string{hostKey(t) + "\nssh-ed25519 x"} },
		"имя вместо адреса":    func(r *certReply) { h := "-oProxyCommand=x"; r.Host = &h },
		"нет адреса":           func(r *certReply) { r.Host = nil },
		"логин":                func(r *certReply) { r.UnixUser = "-oProxyCommand" },
		"порт":                 func(r *certReply) { r.Port = 0 },
	}
	for name, mut := range cases {
		r := good()
		mut(r)
		if _, err := checkCert(r, me, time.Now()); err == nil {
			t.Errorf("%s: принят", name)
		}
	}
	h6 := "2001:db8::1"
	r := good()
	r.Host, r.Port = &h6, 22
	tg, err = checkCert(r, me, time.Now())
	if err != nil || !strings.HasPrefix(string(knownHosts(tg)), "2001:db8::1 ssh-ed25519 ") {
		t.Fatalf("IPv6, порт 22: %v %q", err, knownHosts(tg))
	}
	args := strings.Join(sshArgs(tg, "/tmp/d", []string{"uptime"}), " ")
	for _, want := range []string{"-F none", "StrictHostKeyChecking=yes", "UserKnownHostsFile=/tmp/d/known_hosts",
		"IdentitiesOnly=yes", "IdentityFile=/tmp/d/id.pub", "CertificateFile=/tmp/d/id-cert.pub", "PasswordAuthentication=no",
		"ForwardAgent=no", "ControlPath=none", "IdentityAgent=SSH_AUTH_SOCK", "-p 22 -l ops -- 2001:db8::1 uptime"} {
		if !strings.Contains(args, want) {
			t.Errorf("ssh: нет %q в %q", want, args)
		}
	}
}

func TestDirect(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("--direct на Windows не поддерживается")
	}
	p := newPanel(t)
	host := "203.0.113.7"
	p.servers = []myServer{{ServerID: srvA, Name: "web-1", Online: true, Logins: []login{{UnixUser: "ops", Ready: true}}}}
	p.cert = func(line string) certReply {
		k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil {
			t.Errorf("ключ в запросе: %v", err)
		}
		return certReply{Certificate: testCert(t, k, ssh.UserCert, 10*time.Minute), UnixUser: "ops", Host: &host, Port: 22,
			HostKeys: []string{hostKey(t)}, KeyID: "trassa:w:m:1"}
	}
	a, _, _, _ := newApp(t, p)
	loggedIn(t, a, p, tokA)
	a.LookPath = func(string) (string, error) { return "/usr/bin/ssh", nil }
	var gotArgs []string
	a.RunSSH = func(ctx context.Context, path string, args, env []string) (int, error) {
		gotArgs = args
		var sock string
		for _, e := range env {
			if v, ok := strings.CutPrefix(e, "SSH_AUTH_SOCK="); ok {
				sock = v
			}
		}
		st, err := os.Stat(filepath.Dir(sock))
		if err != nil || st.Mode().Perm() != 0o700 {
			t.Errorf("каталог агента: %v %v", st, err)
		}
		conn, err := net.Dial("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		ag := agent.NewClient(conn)
		keys, err := ag.List()
		if err != nil || len(keys) != 2 || !strings.HasPrefix(keys[0].Format, "ssh-ed25519-cert") || keys[1].Format != "ssh-ed25519" {
			t.Errorf("ключи агента: %v %v", keys, err)
		}
		if _, err := ag.Sign(keys[0], []byte("challenge")); err != nil {
			t.Errorf("подпись: %v", err)
		}
		_, priv, _ := ed25519Key(t)
		if err := ag.Add(agent.AddedKey{PrivateKey: priv}); err == nil {
			t.Error("агент принял чужой ключ")
		}
		if err := ag.RemoveAll(); err == nil {
			t.Error("агент дал удалить ключи")
		}
		return 7, nil
	}
	code, err := a.SSH(context.Background(), SSHOptions{Server: "web-1", Direct: true, Remote: []string{"uptime"}}, nil)
	if err != nil || code != 7 {
		t.Fatalf("код %d %v", code, err)
	}
	if gotArgs[len(gotArgs)-2] != "203.0.113.7" || gotArgs[len(gotArgs)-1] != "uptime" {
		t.Fatalf("аргументы ssh: %v", gotArgs)
	}
	// Временный каталог с ключами хоста и сокетом удалён.
	for _, a := range gotArgs {
		if v, ok := strings.CutPrefix(a, "UserKnownHostsFile="); ok {
			if _, err := os.Stat(filepath.Dir(v)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("временный каталог остался: %v", err)
			}
		}
	}
	a.GOOS = "windows"
	if _, err := a.SSH(context.Background(), SSHOptions{Server: "web-1", Direct: true}, nil); err == nil || err.Error() != a.t("err.direct_windows") {
		t.Fatalf("Windows: %v", err)
	}
}

func ed25519Key(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv, nil
}

type fakeTerm struct{}

func (fakeTerm) Size() (int, int)                            { return 100, 30 }
func (fakeTerm) Raw() (func(), error)                        { return func() {}, nil }
func (fakeTerm) Resized(ctx context.Context) <-chan struct{} { return make(chan struct{}) }

func frame(off uint64, s string) []byte {
	b := make([]byte, 8, 8+len(s))
	binary.BigEndian.PutUint64(b, off)
	return append(b, s...)
}

func TestRelayResumeAndExit(t *testing.T) {
	p := newPanel(t)
	p.servers = []myServer{{ServerID: srvA, Name: "web-1", Online: true, Logins: []login{{UnixUser: "ops", Ready: true}}}}
	gotInput := make(chan string, 4)
	p.ws = func(n int, c *websocket.Conn) {
		ctx := context.Background()
		_ = c.Write(ctx, websocket.MessageText, []byte(`{"type":"hello","sessionId":"s1"}`))
		if n == 1 {
			_ = c.Write(ctx, websocket.MessageBinary, frame(0, "abc"))
			_, in, err := c.Read(ctx)
			if err == nil {
				gotInput <- string(in)
			}
			// Обрыв без кадра закрытия: клиент возвращается по новому билету.
			c.CloseNow()
			return
		}
		// Повтор хвоста с начала: напечатано должно быть только новое.
		_ = c.Write(ctx, websocket.MessageBinary, frame(0, "abcdef"))
		_ = c.Write(ctx, websocket.MessageText, []byte(`{"type":"exit","reason":"CLIENT","code":3}`))
		_ = c.Close(websocket.StatusNormalClosure, "CLIENT")
	}
	a, out, errb, _ := newApp(t, p)
	loggedIn(t, a, p, tokA)
	r, w, _ := os.Pipe()
	defer r.Close()
	a.Stdin = r
	_, _ = w.Write([]byte("ls\r"))
	code, err := a.SSH(context.Background(), SSHOptions{Server: srvA}, fakeTerm{})
	w.Close()
	if err != nil || code != 3 {
		t.Fatalf("код %d %v; stderr %q", code, err, errb.String())
	}
	if out.String() != "abcdef" {
		t.Fatalf("вывод %q", out.String())
	}
	if in := <-gotInput; in != "ls\r" {
		t.Fatalf("ввод %q", in)
	}
	if len(p.wsHello) != 2 || p.wsHello[0]["ticket"] != "t0" || p.wsHello[1]["ticket"] != "t1" || p.wsHello[1]["resumeFrom"] != float64(3) {
		t.Fatalf("hello: %v", p.wsHello)
	}
	if p.lastBody["clientType"] != "CLI" || p.lastBody["cols"] != float64(100) || p.lastBody["lang"] != "ru_RU.UTF-8" {
		t.Fatalf("открытие сессии: %v", p.lastBody)
	}
	if !strings.Contains(errb.String(), "записывается") || !strings.Contains(errb.String(), "Пробуем снова") {
		t.Fatalf("сообщения: %q", errb.String())
	}
}

func TestRelayRevoked(t *testing.T) {
	p := newPanel(t)
	p.servers = []myServer{{ServerID: srvA, Name: "web-1", Logins: []login{{UnixUser: "ops"}}}}
	p.ws = func(n int, c *websocket.Conn) {
		_ = c.Write(context.Background(), websocket.MessageText, []byte(`{"type":"close","reason":"REVOKED"}`))
		_ = c.Close(closeRevoked, "REVOKED")
	}
	a, _, errb, _ := newApp(t, p)
	loggedIn(t, a, p, tokA)
	code, err := a.SSH(context.Background(), SSHOptions{Server: "web-1"}, fakeTerm{})
	if err != nil || code != 1 || !strings.Contains(errb.String(), a.t("err.revoked")) {
		t.Fatalf("отзыв: %d %v %q", code, err, errb.String())
	}
	if _, err := a.SSH(context.Background(), SSHOptions{Server: "web-1", Remote: []string{"ls"}}, fakeTerm{}); err == nil {
		t.Fatal("команда без --direct принята")
	}
}

func TestExplain(t *testing.T) {
	a := &App{Lang: LangRU}
	for code, key := range map[string]string{"ACCESS_NO_GRANT": "err.no_grant", "ACCESS_DIRECT_DISABLED": "err.direct_disabled",
		"STEP_UP_REQUIRED": "err.step_up", "ACCESS_NOT_READY": "err.not_ready"} {
		if got := a.Explain(&APIError{Status: 403, Code: code}); got != a.t(key) {
			t.Errorf("%s: %q", code, got)
		}
	}
	if got := a.Explain(&APIError{Status: 500, Code: "X\x1b[2J", Message: "m"}); strings.Contains(got, "\x1b") {
		t.Fatalf("управляющие символы от панели: %q", got)
	}
	for k, v := range messages {
		if v[0] == "" || v[1] == "" {
			t.Errorf("%s: нет перевода", k)
		}
	}
	if DetectLang(func(k string) string { return map[string]string{"LANG": "ru_RU.UTF-8"}[k] }) != LangRU ||
		DetectLang(func(k string) string { return map[string]string{"LC_ALL": "C", "LANG": "ru_RU.UTF-8"}[k] }) != LangEN {
		t.Fatal("язык")
	}
}

func TestRelayRenewRefused(t *testing.T) {
	old := renewEvery
	renewEvery = 20 * time.Millisecond
	t.Cleanup(func() { renewEvery = old })
	p := newPanel(t)
	p.servers = []myServer{{ServerID: srvA, Name: "web-1", Logins: []login{{UnixUser: "ops"}}}}
	n := 0
	p.renew = func(w http.ResponseWriter) {
		n++
		if n == 1 {
			// Сбой панели — временно: сессия живёт, следующая попытка позже.
			writeJSON(w, 503, map[string]any{"code": "DEPENDENCY_UNAVAILABLE"})
			return
		}
		writeJSON(w, 403, map[string]any{"code": "ACCESS_GRANT_EXPIRED", "message": "ended"})
	}
	p.ws = func(n int, c *websocket.Conn) {
		_ = c.Write(context.Background(), websocket.MessageText, []byte(`{"type":"ready","user":"ops"}`))
		for {
			if _, _, err := c.Read(context.Background()); err != nil {
				return
			}
		}
	}
	a, _, errb, _ := newApp(t, p)
	loggedIn(t, a, p, tokA)
	code, err := a.SSH(context.Background(), SSHOptions{Server: "web-1"}, fakeTerm{})
	if err != nil || code != 1 || !strings.Contains(errb.String(), a.t("err.pass_expired")) {
		t.Fatalf("отказ в продлении: %d %v %q", code, err, errb.String())
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.renewals < 2 {
		t.Fatalf("продлений %d", p.renewals)
	}
}
