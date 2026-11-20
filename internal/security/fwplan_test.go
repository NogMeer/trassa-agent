// SPDX-License-Identifier: AGPL-3.0-only

package security

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
)

func sampleRuleset() *agentv1.FirewallRuleset {
	return &agentv1.FirewallRuleset{SshPort: 22, Rules: []*agentv1.FirewallRule{
		{Target: agentv1.FirewallTarget_FIREWALL_TARGET_HOST, Protocol: "tcp", Port: 22},
		{Target: agentv1.FirewallTarget_FIREWALL_TARGET_BOTH, Protocol: "tcp", Port: 443, Comment: "веб \"https\""},
		{Target: agentv1.FirewallTarget_FIREWALL_TARGET_CONTAINERS, Protocol: "udp", Port: 3000, PortTo: 3010,
			Sources: []string{"10.0.0.0/8", "2001:db8::/32"}},
	}}
}

// Вектор для панели: canonical — ожидаемый канонический JSON (RFC 8785), sha256 — ruleset_hash.
func TestRulesetHashVector(t *testing.T) {
	rs := &agentv1.FirewallRuleset{SshPort: 22, Rules: []*agentv1.FirewallRule{{Target: agentv1.FirewallTarget_FIREWALL_TARGET_HOST, Protocol: "tcp", Port: 22}}}
	want := `{"rules":[{"port":22,"protocol":"tcp","target":"FIREWALL_TARGET_HOST"}],"sshPort":22}`
	sum := sha256.Sum256([]byte(want))
	got, err := RulesetHash(rs)
	if err != nil || got != hex.EncodeToString(sum[:]) {
		t.Fatalf("%s, %v", got, err)
	}
	// Общий вектор с панелью: test/vectors/firewall-ruleset.json.
	raw, err := os.ReadFile(filepath.Join("..", "..", "test", "vectors", "firewall-ruleset.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vec []struct {
		Ruleset   json.RawMessage `json:"ruleset"`
		Canonical string          `json:"canonical"`
		Hash      string          `json:"sha256"`
	}
	if err := json.Unmarshal(raw, &vec); err != nil || len(vec) == 0 {
		t.Fatal(err)
	}
	for i, v := range vec {
		var r agentv1.FirewallRuleset
		if err := protojson.Unmarshal(v.Ruleset, &r); err != nil {
			t.Fatal(err)
		}
		h, err := RulesetHash(&r)
		sum := sha256.Sum256([]byte(v.Canonical))
		if err != nil || h != v.Hash || hex.EncodeToString(sum[:]) != v.Hash {
			t.Errorf("вектор %d: %s, ждали %s (%v)", i, h, v.Hash, err)
		}
	}
	// Порядок правил входит в хэш, порядок полей — нет.
	a, _ := RulesetHash(sampleRuleset())
	r := sampleRuleset()
	r.Rules[0], r.Rules[1] = r.Rules[1], r.Rules[0]
	b, _ := RulesetHash(r)
	if a == b {
		t.Fatal("перестановка правил не меняет хэш")
	}
}

func TestValidateRuleset(t *testing.T) {
	if err := ValidateRuleset(sampleRuleset()); err != nil {
		t.Fatal(err)
	}
	bad := map[string]func(*agentv1.FirewallRuleset){
		"нет ssh_port":    func(r *agentv1.FirewallRuleset) { r.SshPort = 0 },
		"протокол":        func(r *agentv1.FirewallRuleset) { r.Rules[0].Protocol = "icmp" },
		"диапазон":        func(r *agentv1.FirewallRuleset) { r.Rules[2].PortTo = 2999 },
		"источник":        func(r *agentv1.FirewallRuleset) { r.Rules[2].Sources = []string{"10.0.0.1/8"} },
		"target":          func(r *agentv1.FirewallRuleset) { r.Rules[0].Target = 0 },
		"комментарий nft": func(r *agentv1.FirewallRuleset) { r.Rules[0].Comment = "a\nb" },
	}
	for name, mut := range bad {
		r := sampleRuleset()
		mut(r)
		if ValidateRuleset(r) == nil {
			t.Errorf("%s: принято", name)
		}
	}
}

func TestGenerateNft(t *testing.T) {
	text, err := GenerateNft(sampleRuleset(), strings.Repeat("a", 64), []string{"eth0"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"table inet trassa {\n}\ndelete table inet trassa\ntable inet trassa {",
		`comment "trassa:` + strings.Repeat("a", 64) + `"`,
		"type filter hook input priority filter - 1; policy drop;",
		`iifname != { "eth0" } accept`,
		"tcp dport 22 accept",
		`tcp dport 443 accept comment "веб 'https'"`,
		"type filter hook forward priority filter - 1; policy accept;",
		`iifname { "eth0" } ct status dnat meta l4proto tcp ct original proto-dst 443 accept`,
		`iifname { "eth0" } ct status dnat ip saddr { 10.0.0.0/8 } meta l4proto udp ct original proto-dst 3000-3010 accept`,
		`iifname { "eth0" } ct status dnat ip6 saddr { 2001:db8::/32 } meta l4proto udp ct original proto-dst 3000-3010 accept`,
		`iifname { "eth0" } ct status dnat drop`,
		"udp sport 67 udp dport 68 accept",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("нет %q в\n%s", want, text)
		}
	}
	if strings.Contains(text, "flush ruleset") || strings.Contains(text, "destroy") {
		t.Fatal("набор трогает чужие таблицы")
	}
	if strings.Contains(text, "dport 3000") && strings.Contains(text, "\t\tudp dport 3000") {
		t.Fatal("правило CONTAINERS попало в input")
	}
	if _, err := GenerateNft(sampleRuleset(), "x", []string{`eth0"; flush ruleset`}); err == nil {
		t.Fatal("имя интерфейса с кавычкой принято")
	}
}

func TestLockoutAndIfaces(t *testing.T) {
	sys := build(t, tree{
		"proc/net/route":      "Iface\tDestination\tGateway\nens3\t00000000\t0101A8C0\nens3\t0001A8C0\t00000000\ndocker0\t000011AC\t00000000\n",
		"proc/net/ipv6_route": strings.Repeat("0", 32) + " 00 " + strings.Repeat("0", 32) + " 00 fe800000000000000000000000000001 00000400 00000000 00000000 00000003 ens4\n",
	})
	ext, err := ExternalIfaces(sys)
	if err != nil || strings.Join(ext, ",") != "ens3,ens4" {
		t.Fatalf("%v %v", ext, err)
	}
	sys.Run = func(_ context.Context, name string, _ ...string) ([]byte, error) {
		if name == "sshd" {
			return []byte("port 22\nport 2222\n"), nil
		}
		return nil, errors.New("нет")
	}
	rs := sampleRuleset()
	if err := checkLockout(context.Background(), newScan(sys), rs); !errors.Is(err, ErrWouldLockSSH) {
		t.Fatalf("2222 закрыт: %v", err)
	}
	rs.Rules = append(rs.Rules, &agentv1.FirewallRule{Target: agentv1.FirewallTarget_FIREWALL_TARGET_HOST, Protocol: "tcp", Port: 2000, PortTo: 3000})
	if err := checkLockout(context.Background(), newScan(sys), rs); err != nil {
		t.Fatal(err)
	}
	if _, err := ExternalIfaces(build(t, tree{"proc/net/route": "Iface\tDestination\n"})); !errors.Is(err, ErrPrecondition) {
		t.Fatal(err)
	}
}

func TestImportUfw(t *testing.T) {
	sys := build(t, tree{
		"etc/ufw/user.rules": "*filter\n### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in\n-A ufw-user-input -p tcp --dport 22 -j ACCEPT\n" +
			"### tuple ### allow any 80,443 0.0.0.0/0 any 203.0.113.0/24 in comment=7765620a\n" +
			"### tuple ### deny tcp 25 0.0.0.0/0 any 0.0.0.0/0 in\n### tuple ### allow tcp 6000:6010 0.0.0.0/0 any 198.51.100.7 in\n### tuple ### broken\n",
		"etc/ufw/user6.rules": "### tuple ### allow udp 51820 ::/0 any ::/0 in\n",
	})
	rules, warns := ImportUfw(sys)
	var got []string
	for _, r := range rules {
		got = append(got, r.GetProtocol()+"/"+itoa(r.GetPort())+"-"+itoa(r.GetPortTo())+strings.Join(r.GetSources(), ","))
	}
	want := "tcp/22-0,tcp/80-0203.0.113.0/24,udp/80-0203.0.113.0/24,tcp/443-0203.0.113.0/24,udp/443-0203.0.113.0/24,tcp/6000-6010198.51.100.7/32,udp/51820-0"
	if strings.Join(got, ",") != want {
		t.Fatalf("%s", strings.Join(got, ","))
	}
	if len(warns) != 2 {
		t.Fatalf("%v", warns)
	}
}

func itoa(n uint32) string { return strconv.FormatUint(uint64(n), 10) }
