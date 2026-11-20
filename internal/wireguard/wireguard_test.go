// SPDX-License-Identifier: AGPL-3.0-only

package wireguard

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
)

// fakeKernel — устройства в памяти.
type fakeKernel struct {
	unsupported bool
	links       map[string]*fakeLink
}

type fakeLink struct {
	addr string
	mtu  int
	dev  wgtypes.Device
}

func (k *fakeKernel) Probe() error {
	if k.unsupported {
		return precond(CodeUnsupported, "ядро без WireGuard")
	}
	return nil
}

func (k *fakeKernel) Devices() ([]*wgtypes.Device, error) {
	var out []*wgtypes.Device
	for n, l := range k.links {
		d := l.dev
		d.Name = n
		out = append(out, &d)
	}
	return out, nil
}

func (k *fakeKernel) Device(n string) (*wgtypes.Device, error) {
	l, ok := k.links[n]
	if !ok {
		return nil, os.ErrNotExist
	}
	d := l.dev
	return &d, nil
}

func (k *fakeKernel) Ensure(n, addr string, mtu int) error {
	if k.unsupported {
		return precond(CodeUnsupported, "нет")
	}
	l, ok := k.links[n]
	if !ok {
		l = &fakeLink{}
		k.links[n] = l
	}
	l.addr, l.mtu = addr, mtu
	return nil
}

func (k *fakeKernel) Configure(n string, c wgtypes.Config) error {
	l := k.links[n]
	l.dev.PrivateKey = *c.PrivateKey
	l.dev.PublicKey = c.PrivateKey.PublicKey()
	l.dev.ListenPort = *c.ListenPort
	l.dev.Peers = nil
	for _, p := range c.Peers {
		l.dev.Peers = append(l.dev.Peers, wgtypes.Peer{PublicKey: p.PublicKey, AllowedIPs: p.AllowedIPs, Endpoint: p.Endpoint,
			LastHandshakeTime: time.Unix(1_800_000_000, 0), ReceiveBytes: 100, TransmitBytes: 200})
	}
	return nil
}

func (k *fakeKernel) Delete(n string) error { delete(k.links, n); return nil }
func (k *fakeKernel) Exists(n string) bool  { _, ok := k.links[n]; return ok }
func (k *fakeKernel) Address(n string) (string, int, error) {
	l, ok := k.links[n]
	if !ok {
		return "", 0, os.ErrNotExist
	}
	return l.addr, l.mtu, nil
}

// fakeIptables — цепочка DOCKER-USER в памяти.
type fakeIptables struct {
	chain bool
	rules []string
}

func (f *fakeIptables) run(_ context.Context, name string, args ...string) ([]byte, error) {
	if name != "iptables" || !f.chain {
		return nil, errors.New("No chain/target/match by that name")
	}
	switch args[0] {
	case "-S":
		out := "-N DOCKER-USER\n"
		for _, r := range f.rules {
			out += "-A DOCKER-USER " + r + "\n"
		}
		return []byte(out + "-A DOCKER-USER -j RETURN\n"), nil
	case "-I":
		f.rules = append([]string{strings.Join(args[3:], " ")}, f.rules...)
	case "-D":
		want := strings.Join(args[2:], " ")
		for i, r := range f.rules {
			if r == want {
				f.rules = append(f.rules[:i], f.rules[i+1:]...)
				break
			}
		}
	}
	return nil, nil
}

func env(t *testing.T) (*Env, *fakeKernel, *fakeIptables) {
	t.Helper()
	root := t.TempDir()
	for _, d := range []string{"etc", "proc/net", "proc/sys/net/ipv4/conf/wg0", "proc/sys/net/ipv6/conf/wg0"} {
		_ = os.MkdirAll(filepath.Join(root, d), 0o755)
	}
	_ = os.WriteFile(filepath.Join(root, "etc/hosts"), []byte("127.0.0.1 localhost\n"), 0o644)
	_ = os.WriteFile(filepath.Join(root, "proc/sys/net/ipv4/conf/wg0/forwarding"), []byte("0\n"), 0o644)
	_ = os.WriteFile(filepath.Join(root, "proc/sys/net/ipv6/conf/wg0/forwarding"), []byte("0\n"), 0o644)
	_ = os.WriteFile(filepath.Join(root, "proc/net/udp"), []byte("  sl  local_address rem_address   st\n"), 0o644)
	_ = os.WriteFile(filepath.Join(root, "proc/net/route"), []byte("Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\neth0\t00000000\t0101A8C0\t0003\t0\t0\t0\t00000000\neth0\t0001A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\n"), 0o644)
	k := &fakeKernel{links: map[string]*fakeLink{}}
	ipt := &fakeIptables{}
	e := &Env{
		System: &System{Store: Store{Dir: filepath.Join(root, "etc/trassa/wireguard")}, Kernel: k, Run: ipt.run,
			Hosts: filepath.Join(root, "etc/hosts"), ProcSys: filepath.Join(root, "proc/sys"), DockerPresent: func() bool { return false }},
		Root: root, HelperPath: "/usr/local/bin/trassa-helper",
		Addrs: func() ([]netip.Prefix, []string, error) {
			return []netip.Prefix{netip.MustParsePrefix("203.0.113.10/24"), netip.MustParsePrefix("192.168.1.5/24")}, []string{"eth0", "eth0"}, nil
		},
	}
	return e, k, ipt
}

func pub(t *testing.T) string {
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k.PublicKey().String()
}

func applyParams(t *testing.T, key string, peers ...string) *agentv1.WireguardApplyParams {
	p := &agentv1.WireguardApplyParams{IfaceName: "wg0", Address: "10.77.0.1/24", ListenPort: 51820, ExpectPublicKey: key,
		Hosts: []*agentv1.HostEntry{{Fqdn: "db.prod.internal", Address: "10.77.0.2"}}}
	for i, pk := range peers {
		p.Peers = append(p.Peers, &agentv1.WireguardPeer{PublicKey: pk, AllowedIps: []string{netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 77, 0, byte(i + 2)}), 32).String()},
			Endpoint: "198.51.100." + string(rune('1'+i)) + ":51820", KeepaliveSeconds: 25})
	}
	return p
}

func TestValidate(t *testing.T) {
	key := pub(t)
	a, b := pub(t), pub(t)
	if err := ValidateApply(applyParams(t, key, a, b)); err != nil {
		t.Fatal(err)
	}
	bad := map[string]func(*agentv1.WireguardApplyParams){
		"имя длиннее 15":      func(p *agentv1.WireguardApplyParams) { p.IfaceName = "wireguard-trassa-0" },
		"имя с двоеточием":    func(p *agentv1.WireguardApplyParams) { p.IfaceName = "wg:0" },
		"одинаковые адреса":   func(p *agentv1.WireguardApplyParams) { p.Peers[1].AllowedIps = p.Peers[0].AllowedIps },
		"пересечение адресов": func(p *agentv1.WireguardApplyParams) { p.Peers[1].AllowedIps = []string{"10.77.0.0/24"} },
		"пир повторяется":     func(p *agentv1.WireguardApplyParams) { p.Peers[1].PublicKey = p.Peers[0].PublicKey },
		"пир — сам сервер":    func(p *agentv1.WireguardApplyParams) { p.Peers[0].PublicKey = p.ExpectPublicKey },
		"кривой ключ":         func(p *agentv1.WireguardApplyParams) { p.Peers[0].PublicKey = "abc" },
		"MTU":                 func(p *agentv1.WireguardApplyParams) { p.Mtu = 100 },
		"имя хоста":           func(p *agentv1.WireguardApplyParams) { p.Hosts[0].Fqdn = "bad host" },
		"endpoint":            func(p *agentv1.WireguardApplyParams) { p.Peers[0].Endpoint = "host.example:51820" },
		"без allowed_ips":     func(p *agentv1.WireguardApplyParams) { p.Peers[0].AllowedIps = nil },
	}
	for name, mut := range bad {
		p := applyParams(t, key, a, b)
		mut(p)
		if ValidateApply(p) == nil {
			t.Errorf("%s: принято", name)
		}
	}
}

func TestKeygenAndRotation(t *testing.T) {
	e, _, _ := env(t)
	p1, next, err := e.Store.Keygen("wg0", false)
	if err != nil || next {
		t.Fatal(err)
	}
	again, _, _ := e.Store.Keygen("wg0", false)
	if again != p1 {
		t.Fatal("повтор keygen дал другой ключ")
	}
	st, _ := os.Stat(filepath.Join(e.Store.Dir, "wg0.key"))
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("права ключа %o", st.Mode().Perm())
	}
	p2, next, err := e.Store.Keygen("wg0", true)
	if err != nil || !next || p2 == p1 {
		t.Fatal(err)
	}
	if f, err := e.Store.MatchKey("wg0", p2); err != nil || f != "wg0.key.next" {
		t.Fatal(f, err)
	}
	var pe *ErrPrecondition
	if _, err := e.Store.MatchKey("wg0", pub(t)); !errors.As(err, &pe) || pe.Code != CodeKeyMismatch {
		t.Fatal(err)
	}
}

func TestApplyAndRemove(t *testing.T) {
	e, k, ipt := env(t)
	key, _, _ := e.Store.Keygen("wg0", false)
	a, b := pub(t), pub(t)
	p := applyParams(t, key, a, b)
	p.Forwarding = true
	plan, err := e.PlanApply(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Paths) != 4 || len(plan.State.Commands) != 1 || plan.State.Commands[0][1] != "wireguard-sync" {
		t.Fatalf("%+v", plan)
	}
	if err := plan.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Без udp-порта в /proc проверка порта падает — порт «слушается», когда устройство поднято.
	_ = os.WriteFile(filepath.Join(e.Root, "proc/net/udp"), []byte("  sl  local_address rem_address   st\n   0: 00000000:CA6C 00000000:0000 07 x\n"), 0o644)
	if err := plan.Verify(context.Background()); err != nil {
		t.Fatal(err)
	}
	if dev := k.links["wg0"]; len(dev.dev.Peers) != 2 || dev.addr != "10.77.0.1/24" || dev.mtu != DefaultMTU {
		t.Fatalf("%+v", dev)
	}
	hosts, _ := os.ReadFile(e.Hosts)
	if !strings.Contains(string(hosts), "10.77.0.2 db.prod.internal") || !strings.HasPrefix(string(hosts), "127.0.0.1 localhost\n") {
		t.Fatalf("%s", hosts)
	}
	fw, _ := os.ReadFile(filepath.Join(e.ProcSys, "net/ipv4/conf/wg0/forwarding"))
	if strings.TrimSpace(string(fw)) != "1" {
		t.Fatal("пересылка не включена")
	}
	if len(ipt.rules) != 0 {
		t.Fatal("правило Docker без Docker")
	}
	// Статистика пиров.
	ms, err := e.Stats(time.Unix(1_800_000_060, 0))
	if err != nil || len(ms) != 6 || ms[0].GetName() != "wg_peer_handshake_age_seconds" || ms[0].GetValue() != 60 {
		t.Fatalf("%v %v", ms, err)
	}
	// Удаление: интерфейса, блока имён нет; ключ живёт до подтверждения.
	rp, _ := e.PlanRemove(context.Background(), &agentv1.WireguardRemoveParams{IfaceName: "wg0"})
	if err := rp.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := rp.Verify(context.Background()); err != nil {
		t.Fatal(err)
	}
	hosts, _ = os.ReadFile(e.Hosts)
	if string(hosts) != "127.0.0.1 localhost\n" {
		t.Fatalf("%q", hosts)
	}
	if _, err := os.Stat(filepath.Join(e.Store.Dir, "wg0.key")); err != nil {
		t.Fatal("ключ удалён до подтверждения")
	}
	if err := e.Store.AfterConfirm(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(e.Store.Dir, "wg0.key")); !os.IsNotExist(err) {
		t.Fatal("ключ не удалён после подтверждения")
	}
}

func TestDockerUserRule(t *testing.T) {
	e, _, ipt := env(t)
	e.DockerPresent = func() bool { return true }
	key, _, _ := e.Store.Keygen("wg0", false)
	p := applyParams(t, key, pub(t))
	p.Forwarding = true
	// Нет DOCKER-USER — отказ до изменений.
	var pe *ErrPrecondition
	if _, err := e.PlanApply(context.Background(), p); !errors.As(err, &pe) || pe.Code != "FIX_PRECONDITION" {
		t.Fatalf("%v", err)
	}
	ipt.chain = true
	plan, err := e.PlanApply(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ { // повтор не дублирует правило
		if err := plan.Apply(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if len(ipt.rules) != 1 || !strings.Contains(ipt.rules[0], "--comment trassa:e14:wg0") || !strings.HasPrefix(ipt.rules[0], "-i wg0 -o wg0") {
		t.Fatalf("%v", ipt.rules)
	}
	// Лишняя копия (вставлена руками) убирается до одной.
	ipt.rules = append(ipt.rules, ipt.rules[0])
	if err := e.Sync(context.Background(), "wg0"); err != nil || len(ipt.rules) != 1 {
		t.Fatalf("%v %v", ipt.rules, err)
	}
	rp, _ := e.PlanRemove(context.Background(), &agentv1.WireguardRemoveParams{IfaceName: "wg0"})
	if err := rp.Apply(context.Background()); err != nil || len(ipt.rules) != 0 {
		t.Fatalf("после remove: %v %v", ipt.rules, err)
	}
}

func TestInspectAndPreconditions(t *testing.T) {
	e, k, _ := env(t)
	r := e.Inspect(context.Background(), &agentv1.WireguardInspectParams{IfaceName: "wg0", Cidr: "192.168.1.0/24", ListenPort: 51820})
	if !r.GetSupported() || !r.GetPortFree() || len(r.GetConflicts()) == 0 || !r.GetHasPublicIpv4() {
		t.Fatalf("%+v", r)
	}
	k.unsupported = true
	if r := e.Inspect(context.Background(), &agentv1.WireguardInspectParams{IfaceName: "wg0", Cidr: "10.77.0.0/24", ListenPort: 51820}); r.GetSupported() {
		t.Fatal("ядро без WireGuard не замечено")
	}
	k.unsupported = false
	key, _, _ := e.Store.Keygen("wg0", false)
	p := applyParams(t, key)
	p.Address = "192.168.1.9/24"
	var pe *ErrPrecondition
	if _, err := e.PlanApply(context.Background(), p); !errors.As(err, &pe) || pe.Code != CodeConflict {
		t.Fatalf("пересечение: %v", err)
	}
	p.Address = "10.77.0.1/24"
	_ = os.WriteFile(filepath.Join(e.Root, "proc/net/udp"), []byte("  sl\n   0: 00000000:CA6C 00000000:0000 07 x\n"), 0o644)
	if _, err := e.PlanApply(context.Background(), p); !errors.As(err, &pe) || pe.Code != CodePortBusy {
		t.Fatalf("порт: %v", err)
	}
}

func TestRenderHosts(t *testing.T) {
	old := "127.0.0.1 localhost\n# BEGIN trassa:wg0 (управляет Trassa)\n10.0.0.1 old.internal\n# END trassa:wg0\n::1 ip6-localhost\n"
	got := RenderHosts(old, "wg0", []Host{{FQDN: "new.internal", Address: "10.0.0.2"}})
	if strings.Contains(got, "old.internal") || !strings.Contains(got, "::1 ip6-localhost\n") || strings.Count(got, "# BEGIN trassa:wg0") != 1 {
		t.Fatalf("%s", got)
	}
}
