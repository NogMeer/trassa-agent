// SPDX-License-Identifier: AGPL-3.0-only

package vpnprobe

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/tools"
)

const (
	uuidA  = "0b5d3c2e-1f4a-4c8e-9d2b-7a6f5e4d3c2b"
	pbk    = "Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw"
	entry1 = "203.0.113.10"
)

func TestParseLink(t *testing.T) {
	ok := map[string]func(*Link) bool{
		"vless://" + uuidA + "@" + entry1 + ":443?type=tcp&security=reality&sni=www.example.com&fp=chrome&pbk=" + pbk + "&sid=6ba85179e30d4fc2&flow=xtls-rprx-vision#n": func(l *Link) bool {
			return l.Protocol == "vless" && l.Network == "raw" && l.Security == "reality" && l.PBK == pbk && l.SPX == "/" && l.Flow == "xtls-rprx-vision"
		},
		"vless://" + uuidA + "@entry.example.com:8443?type=ws&security=tls&path=%2Fws&host=cdn.example.com": func(l *Link) bool {
			return l.Network == "ws" && l.SNI == "entry.example.com" && l.Path == "/ws" && l.HostHeader == "cdn.example.com"
		},
		"trojan://secret-pass@[2001:db8::1]:443?type=grpc&serviceName=svc&mode=multi&sni=t.example.com": func(l *Link) bool {
			return l.Protocol == "trojan" && l.Security == "tls" && l.GRPCMulti && l.Host == "2001:db8::1"
		},
		"vless://" + uuidA + "@" + entry1 + ":443?type=xhttp&security=tls&sni=x.example.com&mode=stream-one": func(l *Link) bool {
			return l.Network == "xhttp" && l.Mode == "stream-one"
		},
		"ss://YWVzLTI1Ni1nY206cGFzcw@" + entry1 + ":8388#x": func(l *Link) bool {
			return l.Protocol == "shadowsocks" && l.Method == "aes-256-gcm" && l.Password == "pass"
		},
		"ss://2022-blake3-aes-128-gcm:AAAAAAAAAAAAAAAAAAAAAA%3D%3D@" + entry1 + ":8388": func(l *Link) bool {
			return l.Method == "2022-blake3-aes-128-gcm" && l.Password == "AAAAAAAAAAAAAAAAAAAAAA=="
		},
	}
	for in, check := range ok {
		l, err := ParseLink(in)
		if err != nil || !check(l) {
			t.Errorf("%s: %+v %v", in, l, err)
		}
	}
	bad := []string{
		"", "vmess://eyJ2IjoiMiJ9", "http://" + entry1,
		"vless://" + uuidA + "@" + entry1 + ":443?type=tcp",                    // без защиты
		"vless://" + uuidA + "@" + entry1 + ":443?type=kcp&security=tls",       // транспорт
		"vless://not-a-uuid@" + entry1 + ":443?security=tls",                   // id
		"vless://" + uuidA + "@" + entry1 + ":443?security=reality&sni=a.b",    // нет pbk
		"vless://" + uuidA + "@" + entry1 + ":443?security=tls&fp=unsafe",      // fp
		"vless://" + uuidA + "@" + entry1 + ":443?security=tls&type=ws&path=x", // path
		"vless://" + uuidA + "@" + entry1 + ":443?security=tls&type=xhttp&extra=%7B%7D",
		"vless://" + uuidA + "@" + entry1 + ":443?security=tls&encryption=mlkem768x25519plus.x",
		"vless://" + uuidA + "@" + entry1 + ":443?security=tls\nvless://" + uuidA + "@1.1.1.1:443?security=tls",
		"trojan://pw@" + entry1 + ":443?flow=xtls-rprx-vision",
		"ss://YWVzLTI1Ni1nY206cGFzcw@" + entry1 + ":8388?plugin=v2ray-plugin",
		"ss://cmM0LW1kNTpwYXNz@" + entry1 + ":8388",                     // rc4-md5
		"ss://MjAyMi1ibGFrZTMtYWVzLTEyOC1nY206a2V5@" + entry1 + ":8388", // 2022 в base64
		"vless://" + uuidA + "@-oProxy:443?security=tls",
		"vless://" + uuidA + "@" + entry1 + ":0?security=tls",
	}
	for _, in := range bad {
		if l, err := ParseLink(in); err == nil || !errors.Is(err, ErrConfigInvalid) {
			t.Errorf("%q: принят %+v (%v)", in, l, err)
		}
	}
}

func TestXrayConfig(t *testing.T) {
	l, err := ParseLink("vless://" + uuidA + "@entry.example.com:443?type=ws&security=tls&path=%2Fws")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := XrayConfig(l, net.ParseIP(entry1), 10808)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"routing", "dns", "api", "metrics", "policy"} {
		if _, ok := cfg[k]; ok {
			t.Errorf("лишняя секция %s", k)
		}
	}
	in := cfg["inbounds"].([]any)
	out := cfg["outbounds"].([]any)
	if len(in) != 1 || len(out) != 1 || in[0].(map[string]any)["listen"] != "127.0.0.1" {
		t.Fatalf("входы и выходы: %s", raw)
	}
	s := string(raw)
	if !strings.Contains(s, `"address": "`+entry1+`"`) || strings.Contains(s, `"address": "entry.example.com"`) ||
		!strings.Contains(s, `"serverName": "entry.example.com"`) || !strings.Contains(s, `"udp": false`) {
		t.Fatalf("адрес закреплён IP, имя — только в SNI: %s", raw)
	}
}

func TestValidate(t *testing.T) {
	good := func() *agentv1.OperationBody {
		return &agentv1.OperationBody{Params: &agentv1.OperationParams{Params: &agentv1.OperationParams_VpnProbeRun{VpnProbeRun: &agentv1.VpnProbeRunParams{
			CheckId: "11111111-1111-1111-1111-111111111111", RouteId: "22222222-2222-2222-2222-222222222222", Engine: EngineXray,
			HoldSeconds: 60, TimeoutSeconds: 120, TargetUrl: "https://www.example.com/", HopCount: 3,
			Config: &agentv1.SealedSecret{Kid: "k", EncCt: []byte{1}}, AllowedEndpoints: []string{entry1, "2001:db8::1"},
		}}}}
	}
	if err := ValidateRun(good()); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(p *agentv1.VpnProbeRunParams){
		"hold":          func(p *agentv1.VpnProbeRunParams) { p.HoldSeconds = 10 },
		"timeout":       func(p *agentv1.VpnProbeRunParams) { p.TimeoutSeconds = 60 },
		"timeout max":   func(p *agentv1.VpnProbeRunParams) { p.TimeoutSeconds = 601 },
		"hops":          func(p *agentv1.VpnProbeRunParams) { p.HopCount = 13 },
		"engine":        func(p *agentv1.VpnProbeRunParams) { p.Engine = "sing-box" },
		"target ip":     func(p *agentv1.VpnProbeRunParams) { p.TargetUrl = "https://1.1.1.1/" },
		"target port":   func(p *agentv1.VpnProbeRunParams) { p.TargetUrl = "https://www.example.com:8443/" },
		"target scheme": func(p *agentv1.VpnProbeRunParams) { p.TargetUrl = "ftp://www.example.com/" },
		"target user":   func(p *agentv1.VpnProbeRunParams) { p.TargetUrl = "https://u:p@www.example.com/" },
		"no endpoints":  func(p *agentv1.VpnProbeRunParams) { p.AllowedEndpoints = nil },
		"private":       func(p *agentv1.VpnProbeRunParams) { p.AllowedEndpoints = []string{"10.0.0.1"} },
		"loopback":      func(p *agentv1.VpnProbeRunParams) { p.AllowedEndpoints = []string{"127.0.0.1"} },
		"cgnat":         func(p *agentv1.VpnProbeRunParams) { p.AllowedEndpoints = []string{"100.64.1.1"} },
		"link-local":    func(p *agentv1.VpnProbeRunParams) { p.AllowedEndpoints = []string{"169.254.169.254"} },
		"name":          func(p *agentv1.VpnProbeRunParams) { p.AllowedEndpoints = []string{"vpn.example.com"} },
		"route":         func(p *agentv1.VpnProbeRunParams) { p.RouteId = "x" },
		"no config":     func(p *agentv1.VpnProbeRunParams) { p.Config = nil },
	}
	for name, mut := range cases {
		b := good()
		mut(b.GetParams().GetVpnProbeRun())
		if err := ValidateRun(b); err == nil {
			t.Errorf("%s: принято", name)
		}
	}
	b := good()
	b.DryRun = true
	if ValidateRun(b) == nil {
		t.Error("dry_run принят")
	}
	if ValidateEnsure(&agentv1.VpnProbeEnsureParams{Engine: "xray", Version: "26.10.31", Sha256: strings.Repeat("a", 64), Url: "http://x/y"}) == nil {
		t.Error("http-источник принят")
	}
	if !errors.Is(ValidateEnsure(&agentv1.VpnProbeEnsureParams{Engine: "v2ray"}), ErrEngineUnknown) {
		t.Error("неизвестный движок")
	}
}

func TestSystemdProperties(t *testing.T) {
	s := Systemd{SystemdRun: "/usr/bin/systemd-run", Systemctl: "/usr/bin/systemctl", User: "trassa",
		Hidden: []string{"/var/lib/trassa", "/run/trassa"}, EngineDir: "/var/lib/trassa/vpn-probe"}
	a := strings.Join(s.args(Unit{Name: "trassa-vpnprobe-x", Exec: []string{"/bin/xray", "run"}, AllowIPs: []string{entry1},
		Visible: []string{"/run/trassa-vpnprobe/x"}, Timeout: 90}), "\n")
	for _, want := range []string{"--uid=trassa", "--gid=trassa", "--wait", "--pipe", "--collect", "IPAddressDeny=any",
		"IPAddressAllow=localhost " + entry1, "NoNewPrivileges=yes", "CapabilityBoundingSet=", "ProtectSystem=strict",
		"TemporaryFileSystem=/var/lib/trassa:ro /run/trassa:ro", "BindReadOnlyPaths=/var/lib/trassa/vpn-probe /run/trassa-vpnprobe/x",
		"MemoryMax=256M", "RuntimeMaxSec=90", "SystemCallFilter=~@privileged @debug", "ProtectProc=invisible", "\n--\n/bin/xray\nrun"} {
		if !strings.Contains(a, want) {
			t.Errorf("нет %q", want)
		}
	}
	if _, err := s.Start(context.Background(), Unit{Name: "trassa-vpnprobe-X;rm"}); err == nil {
		t.Fatal("имя службы не проверено")
	}
}

// ---------- установка ----------

func zipWith(t *testing.T, files map[string]string) []byte {
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	for n, c := range files {
		f, _ := w.Create(n)
		_, _ = f.Write([]byte(c))
	}
	_ = w.Close()
	return b.Bytes()
}

// fakeSandbox — песочница без systemd: version отвечает заданной строкой, Start запускает engine в горутине.
type fakeSandbox struct {
	version string
	engine  func(u Unit, stop <-chan struct{}) (out string)
	units   []Unit
	mu      sync.Mutex
}

func (f *fakeSandbox) Run(ctx context.Context, u Unit) ([]byte, error) {
	f.mu.Lock()
	f.units = append(f.units, u)
	f.mu.Unlock()
	return []byte(f.version), nil
}

type fakeProc struct {
	done chan struct{}
	stop chan struct{}
	out  atomic.Value
	once sync.Once
}

func (p *fakeProc) Exited() <-chan struct{} { return p.done }
func (p *fakeProc) Output() []byte {
	if v, ok := p.out.Load().(string); ok {
		return []byte(v)
	}
	return nil
}
func (p *fakeProc) Stop(context.Context) error {
	p.once.Do(func() { close(p.stop) })
	<-p.done
	return nil
}

func (f *fakeSandbox) Start(ctx context.Context, u Unit) (Process, error) {
	f.mu.Lock()
	f.units = append(f.units, u)
	f.mu.Unlock()
	p := &fakeProc{done: make(chan struct{}), stop: make(chan struct{})}
	go func() {
		p.out.Store(f.engine(u, p.stop))
		close(p.done)
	}()
	return p, nil
}

func withTool(t *testing.T, version string, sum string) {
	old := tools.Known["xray"]
	m := map[string]map[string]string{}
	for v, a := range old {
		m[v] = a
	}
	m[version] = map[string]string{runtime.GOARCH: sum}
	tools.Known["xray"] = m
	t.Cleanup(func() { tools.Known["xray"] = old })
}

func stage(t *testing.T, archive []byte) string {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, Staged), archive, 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func sum(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func TestEnsure(t *testing.T) {
	e := &Env{Dir: t.TempDir()}
	sb := &fakeSandbox{}
	e.Sandbox = sb
	for i, v := range []string{"1.0.0", "1.1.0", "1.2.0"} {
		arc := zipWith(t, map[string]string{"xray": "bin-" + v, "geoip.dat": "x", "README.md": "r"})
		withTool(t, v, sum(arc))
		sb.version = "Xray " + v + " (Xray, Penetrates Everything.) abc (go1.26 linux/amd64)\nA unified platform"
		res, err := e.Ensure(context.Background(), stage(t, arc), &agentv1.VpnProbeEnsureParams{Engine: "xray", Version: v, Sha256: sum(arc)})
		if err != nil {
			t.Fatal(err)
		}
		if res.GetVersion() != v || (i > 0) != (res.GetPreviousVersion() != "") || res.GetSizeBytes() != uint64(len(arc)) {
			t.Fatalf("%s: %+v", v, res)
		}
		if err := e.Prune("xray", v, res.GetPreviousVersion()); err != nil {
			t.Fatal(err)
		}
	}
	got, bin, err := e.Installed("xray")
	if err != nil || got != "1.2.0" {
		t.Fatalf("установлена %s %v", got, err)
	}
	if b, _ := os.ReadFile(bin); string(b) != "bin-1.2.0" {
		t.Fatalf("бинарник %q", b)
	}
	if _, err := os.Stat(filepath.Join(e.Dir, "xray-1.0.0")); !os.IsNotExist(err) {
		t.Fatal("старая версия не удалена")
	}
	if _, err := os.Stat(filepath.Join(e.Dir, "xray-1.1.0")); err != nil {
		t.Fatal("прежняя версия удалена — откату нечего вернуть")
	}
	// Пробный запуск — в песочнице, без сети.
	if u := sb.units[len(sb.units)-1]; len(u.AllowIPs) != 0 || u.Exec[1] != "version" {
		t.Fatalf("version: %+v", u)
	}

	arc := zipWith(t, map[string]string{"xray": "x"})
	withTool(t, "2.0.0", sum(arc))
	if _, err := e.Ensure(context.Background(), stage(t, arc), &agentv1.VpnProbeEnsureParams{Engine: "xray", Version: "2.0.0", Sha256: strings.Repeat("0", 64)}); !errors.Is(err, ErrEngineUnknown) {
		t.Fatalf("сумма не из таблицы: %v", err)
	}
	other := zipWith(t, map[string]string{"xray": "подмена"})
	if _, err := e.Ensure(context.Background(), stage(t, other), &agentv1.VpnProbeEnsureParams{Engine: "xray", Version: "2.0.0", Sha256: sum(arc)}); !errors.Is(err, ErrSHA256) {
		t.Fatalf("подменённый архив: %v", err)
	}
	sb.version = "Xray 9.9.9 (Xray)"
	if _, err := e.Ensure(context.Background(), stage(t, arc), &agentv1.VpnProbeEnsureParams{Engine: "xray", Version: "2.0.0", Sha256: sum(arc)}); !errors.Is(err, ErrEngineFailed) {
		t.Fatalf("версия не та: %v", err)
	}
	for name, files := range map[string]map[string]string{"нет файла": {"bin/xray": "x"}, "чужое имя": {"xray.exe": "x"}} {
		a := zipWith(t, files)
		withTool(t, "3.0.0", sum(a))
		if _, err := e.Ensure(context.Background(), stage(t, a), &agentv1.VpnProbeEnsureParams{Engine: "xray", Version: "3.0.0", Sha256: sum(a)}); err == nil {
			t.Errorf("%s: принят", name)
		}
	}
	if v, _, _ := e.Installed("xray"); v != "1.2.0" {
		t.Fatalf("неудачные установки сменили версию: %s", v)
	}
}

// ---------- замер ----------

// socks5 — поддельный движок: socks5 на порту из конфигурации, соединения — на backend (как будто через цепочку).
func socks5(t *testing.T, port int, backend string, accept func(n int) bool, cut time.Duration, stop <-chan struct{}) {
	l, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Errorf("socks: %v", err)
		return
	}
	go func() { <-stop; l.Close() }()
	n := 0
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		n++
		go func(c net.Conn, n int) {
			defer c.Close()
			buf := make([]byte, 262)
			if _, err := io.ReadFull(c, buf[:2]); err != nil {
				return
			}
			if _, err := io.ReadFull(c, buf[:buf[1]]); err != nil {
				return
			}
			_, _ = c.Write([]byte{5, 0})
			if _, err := io.ReadFull(c, buf[:4]); err != nil {
				return
			}
			switch buf[3] {
			case 1:
				_, _ = io.ReadFull(c, buf[:6])
			case 3:
				_, _ = io.ReadFull(c, buf[:1])
				_, _ = io.ReadFull(c, buf[:int(buf[0])+2])
			case 4:
				_, _ = io.ReadFull(c, buf[:18])
			}
			if !accept(n) {
				_, _ = c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
				return
			}
			b, err := net.Dial("tcp", backend)
			if err != nil {
				return
			}
			defer b.Close()
			_, _ = c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
			if cut > 0 {
				// Цепочка рвёт поток через cut (как DPI на N-й секунде).
				time.AfterFunc(cut, func() { c.Close(); b.Close() })
			}
			go func() { _, _ = io.Copy(b, c) }()
			_, _ = io.Copy(c, b)
		}(c, n)
	}
}

type probeCase struct {
	e      *Env
	sb     *fakeSandbox
	params *agentv1.VpnProbeRunParams
	conns  atomic.Int32
	cfg    atomic.Value
}

func newProbe(t *testing.T, accept func(n int) bool, cut ...time.Duration) *probeCase {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "www.example.com" {
			t.Errorf("Host %q — имя должно идти в туннель", r.Host)
		}
		_, _ = w.Write([]byte("hello"))
	}))
	t.Cleanup(backend.Close)
	pc := &probeCase{}
	pc.sb = &fakeSandbox{engine: func(u Unit, stop <-chan struct{}) string {
		raw, err := os.ReadFile(u.Exec[3])
		if err != nil {
			return "Failed to start: нет конфигурации"
		}
		pc.cfg.Store(string(raw))
		var cfg struct {
			Inbounds []struct {
				Port int `json:"port"`
			} `json:"inbounds"`
		}
		_ = json.Unmarshal(raw, &cfg)
		// Счёт — по запросам socks5 (проверка готовности порта открывает соединение без рукопожатия).
		socks5(t, cfg.Inbounds[0].Port, backend.Listener.Addr().String(), func(int) bool {
			return accept(int(pc.conns.Add(1)))
		}, append(cut, 0)[0], stop)
		return ""
	}}
	dir := t.TempDir()
	e := &Env{Dir: dir, RunDir: filepath.Join(t.TempDir(), "run"), Sandbox: pc.sb, Interval: 50 * time.Millisecond,
		Owner:    func() (int, int, error) { return os.Getuid(), os.Getgid(), nil },
		LookupIP: func(ctx context.Context, h string) ([]net.IP, error) { return []net.IP{net.ParseIP(entry1)}, nil },
		DialEntry: func(ctx context.Context, addr string) (net.Conn, error) {
			if addr != net.JoinHostPort(entry1, "443") {
				t.Errorf("проверка порта не того адреса: %s", addr)
			}
			a, b := net.Pipe()
			b.Close()
			return a, nil
		},
	}
	// Установленный движок.
	withTool(t, "1.0.0", "s")
	_ = os.MkdirAll(filepath.Join(dir, "xray-1.0.0"), 0o755)
	_ = os.WriteFile(filepath.Join(dir, "xray-1.0.0", "xray"), []byte("x"), 0o755)
	_ = os.WriteFile(filepath.Join(dir, stateName), []byte(`{"xray":"1.0.0"}`), 0o644)
	pc.e = e
	pc.params = &agentv1.VpnProbeRunParams{CheckId: "11111111-1111-1111-1111-111111111111", RouteId: "22222222-2222-2222-2222-222222222222",
		Engine: "xray", HoldSeconds: 1, TimeoutSeconds: 20, TargetUrl: "http://www.example.com/", HopCount: 3,
		AllowedEndpoints: []string{entry1}}
	return pc
}

var linkOK = "vless://" + uuidA + "@entry.example.com:443?type=tcp&security=tls"

func TestProbeOK(t *testing.T) {
	pc := newProbe(t, func(int) bool { return true })
	res, err := pc.e.Probe(context.Background(), pc.params, []byte(linkOK))
	if err != nil {
		t.Fatal(err)
	}
	if res.GetStatus() != agentv1.VpnProbeStatus_VPN_PROBE_STATUS_OK || res.GetHeldSeconds() != 1 || !res.GetEntryPortOpen() ||
		len(res.GetHops()) != 3 || res.FirstBrokenHop != nil || res.GetBytesTransferred() == 0 || res.GetCheckId() != pc.params.GetCheckId() ||
		res.GetEngineVersion() != "1.0.0" {
		t.Fatalf("итог: %+v", res)
	}
	cfg := pc.cfg.Load().(string)
	if !strings.Contains(cfg, entry1) || strings.Contains(cfg, `"address": "entry.example.com"`) {
		t.Fatalf("движок получил не закреплённый IP: %s", cfg)
	}
	u := pc.sb.units[0]
	if len(u.AllowIPs) != 1 || u.AllowIPs[0] != entry1 || !strings.HasPrefix(u.Name, "trassa-vpnprobe-") || u.Timeout != 50 {
		t.Fatalf("песочница: %+v", u)
	}
	if _, err := os.Stat(filepath.Dir(u.Exec[3])); !os.IsNotExist(err) {
		t.Fatal("каталог с доступом не удалён")
	}
}

func TestProbeResetAndFailed(t *testing.T) {
	// Поток рвётся через 700 мс, новое соединение цепочка не пускает.
	pc := newProbe(t, func(n int) bool { return n <= 1 }, 700*time.Millisecond)
	pc.params.HoldSeconds = 2
	res, err := pc.e.Probe(context.Background(), pc.params, []byte(linkOK))
	if err != nil {
		t.Fatal(err)
	}
	if res.GetStatus() != agentv1.VpnProbeStatus_VPN_PROBE_STATUS_RESET || res.GetHeldSeconds() >= 2 || len(res.GetHops()) != 1 {
		t.Fatalf("обрыв: %+v", res)
	}

	pc = newProbe(t, func(int) bool { return false })
	res, err = pc.e.Probe(context.Background(), pc.params, []byte(linkOK))
	if err != nil {
		t.Fatal(err)
	}
	if res.GetStatus() != agentv1.VpnProbeStatus_VPN_PROBE_STATUS_FAILED || res.GetHops()[0].GetNote() != NoteTunnel || res.FirstBrokenHop != nil {
		t.Fatalf("туннель: %+v", res)
	}

	pc = newProbe(t, func(int) bool { return true })
	pc.e.DialEntry = func(context.Context, string) (net.Conn, error) {
		return nil, &net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}
	}
	res, err = pc.e.Probe(context.Background(), pc.params, []byte(linkOK))
	if err != nil {
		t.Fatal(err)
	}
	if res.GetStatus() != agentv1.VpnProbeStatus_VPN_PROBE_STATUS_FAILED || res.GetFirstBrokenHop() != 0 || res.FirstBrokenHop == nil ||
		res.GetHops()[0].GetNote() != NoteTCPRefused || res.GetEntryPortOpen() || len(pc.sb.units) != 0 {
		t.Fatalf("порт входа закрыт: %+v; запусков %d", res, len(pc.sb.units))
	}
}

func TestProbeRefusals(t *testing.T) {
	pc := newProbe(t, func(int) bool { return true })
	// Вход не из серверов цепочки — ни проверки порта, ни движка.
	pc.e.LookupIP = func(context.Context, string) ([]net.IP, error) { return []net.IP{net.ParseIP("198.51.100.7")}, nil }
	if _, err := pc.e.Probe(context.Background(), pc.params, []byte(linkOK)); !errors.Is(err, ErrEndpointForbid) {
		t.Fatalf("имя на чужой адрес: %v", err)
	}
	if _, err := pc.e.Probe(context.Background(), pc.params, []byte("trojan://p@198.51.100.7:443?sni=a.example.com")); !errors.Is(err, ErrEndpointForbid) {
		t.Fatalf("чужой IP: %v", err)
	}
	if len(pc.sb.units) != 0 {
		t.Fatal("движок запущен для чужого адреса")
	}
	if _, err := pc.e.Probe(context.Background(), pc.params, []byte(`{"outbounds":[{"protocol":"freedom"}]}`)); !errors.Is(err, ErrConfigInvalid) {
		t.Fatalf("JSON движка: %v", err)
	}
	// Движок не принял конфигурацию.
	pc.e.LookupIP = func(context.Context, string) ([]net.IP, error) { return []net.IP{net.ParseIP(entry1)}, nil }
	pc.sb.engine = func(Unit, <-chan struct{}) string { return "Failed to start: bad" }
	if _, err := pc.e.Probe(context.Background(), pc.params, []byte(linkOK)); !errors.Is(err, ErrConfigInvalid) {
		t.Fatalf("отказ движка: %v", err)
	}
	// Движок не установлен.
	_ = os.Remove(filepath.Join(pc.e.Dir, stateName))
	if _, err := pc.e.Probe(context.Background(), pc.params, []byte(linkOK)); !errors.Is(err, ErrEngineMissing) {
		t.Fatalf("без ensure: %v", err)
	}
	// Предел одновременных замеров.
	pc.e.once.Do(func() { pc.e.sem = make(chan struct{}, MaxParallel) })
	for i := 0; i < MaxParallel; i++ {
		pc.e.sem <- struct{}{}
	}
	if _, err := pc.e.Probe(context.Background(), pc.params, []byte(linkOK)); !errors.Is(err, ErrBusy) {
		t.Fatalf("пятый замер: %v", err)
	}
}

func TestCleanup(t *testing.T) {
	e := &Env{RunDir: t.TempDir()}
	_ = os.MkdirAll(filepath.Join(e.RunDir, "old"), 0o700)
	_ = os.WriteFile(filepath.Join(e.RunDir, "old", "config.json"), []byte("secret"), 0o600)
	if err := e.Cleanup(); err != nil {
		t.Fatal(err)
	}
	if entries, _ := os.ReadDir(e.RunDir); len(entries) != 0 {
		t.Fatal("каталоги замеров остались")
	}
	if err := (&Env{RunDir: filepath.Join(t.TempDir(), "none")}).Cleanup(); err != nil {
		t.Fatal(err)
	}
}

// Текст отказа уходит в итог операции: значений из ссылки (ключи, пароли) в нём нет.
func TestParseLinkErrorsHideSecrets(t *testing.T) {
	for _, in := range []string{
		"vless://" + uuidA + "@" + entry1 + ":443?security=tls&encryption=mlkem768x25519plus.SECRETKEY",
		"ss://U0VDUkVUS0VZOnBhc3M@" + entry1 + ":8388", // «SECRETKEY:pass» — неверный метод
		"vless://" + uuidA + "@" + entry1 + ":443?type=SECRETKEY&security=tls",
		"SECRETKEY://x@" + entry1 + ":443",
	} {
		_, err := ParseLink(in)
		if err == nil || strings.Contains(err.Error(), "SECRETKEY") {
			t.Errorf("%q: %v", in, err)
		}
	}
}
