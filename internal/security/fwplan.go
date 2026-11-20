// SPDX-License-Identifier: AGPL-3.0-only

package security

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"google.golang.org/protobuf/encoding/protojson"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
)

// Файлы firewall Trassa (decisions E10, п. 5–7): свой набор и своя служба, штатные nftables.conf и
// nftables.service не трогаются.
const (
	FirewallFile = "/etc/trassa/firewall.nft"
	FirewallUnit = "trassa-firewall.service"
	// FirewallUnitFile — служба загружает набор при старте системы.
	FirewallUnitFile = "/etc/systemd/system/" + FirewallUnit
)

// Пределы набора.
const (
	MaxFirewallRules   = 500
	MaxFirewallSources = 100
	maxRuleComment     = 200
)

// ErrWouldLockSSH — набор закрыл бы SSH: помощник повторяет проверку панели по своим данным (E10, раздел 6).
var ErrWouldLockSSH = errors.New("FIREWALL_WOULD_LOCK_SSH")

// RulesetHash — sha256 (hex) канонического JSON набора: JSON по правилам proto3 (имена lowerCamelCase,
// значения по умолчанию опущены, enum — именами), затем канонизация RFC 8785. Так же считает панель
// (`toJson` + canonicalize), как planHash в E05.
func RulesetHash(rs *agentv1.FirewallRuleset) (string, error) {
	raw, err := protojson.Marshal(rs)
	if err != nil {
		return "", err
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return "", err
	}
	var b strings.Builder
	if err := canonical(&b, v); err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:]), nil
}

// canonical — RFC 8785 для значений набора: ключи по кодовым единицам UTF-16, строки как JSON.stringify,
// числа — только целые (в наборе других нет).
func canonical(b *strings.Builder, v any) error {
	switch x := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return utf16Less(keys[i], keys[j]) })
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			quote(b, k)
			b.WriteByte(':')
			if err := canonical(b, x[k]); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	case []any:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := canonical(b, e); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case string:
		quote(b, x)
	case float64:
		if x != float64(int64(x)) {
			return fmt.Errorf("дробное число %v в наборе", x)
		}
		b.WriteString(strconv.FormatInt(int64(x), 10))
	case bool:
		b.WriteString(strconv.FormatBool(x))
	case nil:
		b.WriteString("null")
	default:
		return fmt.Errorf("тип %T", v)
	}
	return nil
}

func utf16Less(a, b string) bool {
	ra, rb := []rune(a), []rune(b)
	ua, ub := utf16Units(ra), utf16Units(rb)
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

func utf16Units(rs []rune) []uint16 {
	var out []uint16
	for _, r := range rs {
		if r >= 0x10000 {
			r -= 0x10000
			out = append(out, uint16(0xD800+(r>>10)), uint16(0xDC00+(r&0x3FF)))
		} else {
			out = append(out, uint16(r))
		}
	}
	return out
}

// quote — строка как JSON.stringify (ECMAScript): \" \\ \b \f \n \r \t, прочие управляющие — \u00xx.
func quote(b *strings.Builder, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
}

// ValidateRuleset — схема набора.
func ValidateRuleset(rs *agentv1.FirewallRuleset) error {
	if rs.GetSshPort() < 1 || rs.GetSshPort() > 65535 {
		return errors.New("ssh_port: от 1 до 65535")
	}
	if len(rs.GetRules()) > MaxFirewallRules {
		return fmt.Errorf("правил больше %d", MaxFirewallRules)
	}
	for i, r := range rs.GetRules() {
		if err := validateRule(r); err != nil {
			return fmt.Errorf("правило %d: %w", i+1, err)
		}
	}
	return nil
}

func validateRule(r *agentv1.FirewallRule) error {
	switch r.GetTarget() {
	case agentv1.FirewallTarget_FIREWALL_TARGET_HOST, agentv1.FirewallTarget_FIREWALL_TARGET_CONTAINERS, agentv1.FirewallTarget_FIREWALL_TARGET_BOTH:
	default:
		return errors.New("target")
	}
	if r.GetProtocol() != "tcp" && r.GetProtocol() != "udp" {
		return errors.New("protocol: tcp или udp")
	}
	if r.GetPort() < 1 || r.GetPort() > 65535 || (r.GetPortTo() != 0 && (r.GetPortTo() <= r.GetPort() || r.GetPortTo() > 65535)) {
		return errors.New("порт или диапазон")
	}
	if len(r.GetSources()) > MaxFirewallSources {
		return fmt.Errorf("источников больше %d", MaxFirewallSources)
	}
	for _, s := range r.GetSources() {
		p, err := netip.ParsePrefix(s)
		if err != nil || p.Masked() != p {
			return fmt.Errorf("источник %q: нужен CIDR без лишних битов", s)
		}
	}
	if utf8.RuneCountInString(r.GetComment()) > maxRuleComment || strings.IndexFunc(r.GetComment(), func(c rune) bool {
		return !unicode.IsPrint(c)
	}) >= 0 {
		return errors.New("comment: до 200 печатных символов")
	}
	return nil
}

func covers(r *agentv1.FirewallRule, port uint32) bool {
	if r.GetProtocol() != "tcp" || r.GetTarget() == agentv1.FirewallTarget_FIREWALL_TARGET_CONTAINERS {
		return false
	}
	return port == r.GetPort() || (r.GetPortTo() != 0 && port >= r.GetPort() && port <= r.GetPortTo())
}

// checkLockout — каждый порт, на котором sshd слушает по настройкам, и ssh_port набора открыты правилом HOST.
func checkLockout(ctx context.Context, s *Scan, rs *agentv1.FirewallRuleset) error {
	ports := []uint32{rs.GetSshPort()}
	if e, err := s.SSH(ctx); err == nil {
		ports = append(ports, e.GetPorts()...)
	}
	for _, p := range ports {
		ok := false
		for _, r := range rs.GetRules() {
			if covers(r, p) {
				ok = true
				break
			}
		}
		if !ok {
			return fmt.Errorf("%w: порт SSH %d не открыт ни одному источнику", ErrWouldLockSSH, p)
		}
	}
	return nil
}

// ExternalIfaces — интерфейсы маршрутов по умолчанию (IPv4 и IPv6), без lo. Фильтр Trassa действует на них:
// внутренние сети и бриджи контейнеров не закрываются (их правила — E14).
func ExternalIfaces(sys *System) ([]string, error) {
	set := map[string]bool{}
	if b, err := os.ReadFile(sys.path("/proc/net/route")); err == nil {
		for i, l := range strings.Split(string(b), "\n") {
			f := strings.Fields(l)
			if i > 0 && len(f) >= 2 && f[1] == "00000000" && f[0] != "lo" {
				set[f[0]] = true
			}
		}
	} else {
		return nil, err
	}
	if b, err := os.ReadFile(sys.path("/proc/net/ipv6_route")); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			f := strings.Fields(l)
			if len(f) == 10 && f[0] == strings.Repeat("0", 32) && f[1] == "00" && f[9] != "lo" {
				set[f[9]] = true
			}
		}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: нет маршрута по умолчанию — внешний интерфейс не определить", ErrPrecondition)
	}
	return out, nil
}

var ifaceNameRe = func(s string) bool {
	if s == "" || len(s) > 15 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.' || c == '@') {
			return false
		}
	}
	return true
}

// GenerateNft — набор nftables: замена своей таблицы одним `nft -f` (пустое объявление, delete, определение),
// input с policy drop на внешних интерфейсах, forward закрывает опубликованные порты контейнеров (ct status dnat,
// ct original proto-dst) раньше цепочек Docker (priority filter - 1). Хэш набора — в комментарии таблицы.
func GenerateNft(rs *agentv1.FirewallRuleset, hash string, ext []string) (string, error) {
	for _, i := range ext {
		if !ifaceNameRe(i) {
			return "", fmt.Errorf("имя интерфейса %q", i)
		}
	}
	quoted := make([]string, len(ext))
	for i, x := range ext {
		quoted[i] = `"` + x + `"`
	}
	extSet := "{ " + strings.Join(quoted, ", ") + " }"
	var b strings.Builder
	b.WriteString("# Trassa: межсетевой экран. Файл пишет Trassa; чужие таблицы не меняются.\n")
	b.WriteString("table inet trassa {\n}\ndelete table inet trassa\n")
	b.WriteString("table inet trassa {\n")
	fmt.Fprintf(&b, "\tcomment \"trassa:%s\"\n", hash)
	b.WriteString("\tchain input {\n\t\ttype filter hook input priority filter - 1; policy drop;\n")
	fmt.Fprintf(&b, "\t\tiifname != %s accept\n", extSet)
	b.WriteString("\t\tct state vmap { established : accept, related : accept, invalid : drop }\n")
	b.WriteString("\t\ticmp type echo-request limit rate 5/second accept\n")
	b.WriteString("\t\ticmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, nd-router-advert } accept\n")
	b.WriteString("\t\ticmpv6 type echo-request limit rate 5/second accept\n")
	// Ответы DHCP на адрес сервера: без них аренда адреса у хостера не продлится.
	b.WriteString("\t\tudp sport 67 udp dport 68 accept\n\t\tudp sport 547 udp dport 546 accept\n")
	for _, r := range rs.GetRules() {
		if r.GetTarget() == agentv1.FirewallTarget_FIREWALL_TARGET_CONTAINERS {
			continue
		}
		for _, l := range ruleLines(r, false) {
			b.WriteString("\t\t" + l + "\n")
		}
	}
	b.WriteString("\t}\n")
	b.WriteString("\tchain forward {\n\t\ttype filter hook forward priority filter - 1; policy accept;\n")
	for _, r := range rs.GetRules() {
		if r.GetTarget() == agentv1.FirewallTarget_FIREWALL_TARGET_HOST {
			continue
		}
		for _, l := range ruleLines(r, true) {
			fmt.Fprintf(&b, "\t\tiifname %s ct status dnat %s\n", extSet, l)
		}
	}
	fmt.Fprintf(&b, "\t\tiifname %s ct status dnat drop\n", extSet)
	b.WriteString("\t}\n}\n")
	return b.String(), nil
}

// ruleLines — строки nft для правила; источники IPv4 и IPv6 — отдельными строками.
func ruleLines(r *agentv1.FirewallRule, forward bool) []string {
	port := strconv.Itoa(int(r.GetPort()))
	if r.GetPortTo() != 0 {
		port += "-" + strconv.Itoa(int(r.GetPortTo()))
	}
	match := r.GetProtocol() + " dport " + port
	if forward {
		match = "meta l4proto " + r.GetProtocol() + " ct original proto-dst " + port
	}
	comment := ""
	if c := r.GetComment(); c != "" {
		comment = ` comment "` + strings.NewReplacer(`"`, `'`, `\`, `/`).Replace(c) + `"`
	}
	if len(r.GetSources()) == 0 {
		return []string{match + " accept" + comment}
	}
	var v4, v6 []string
	for _, s := range r.GetSources() {
		p := netip.MustParsePrefix(s)
		if p.Addr().Is4() {
			v4 = append(v4, p.String())
		} else {
			v6 = append(v6, p.String())
		}
	}
	var out []string
	if len(v4) > 0 {
		out = append(out, "ip saddr { "+strings.Join(v4, ", ")+" } "+match+" accept"+comment)
	}
	if len(v6) > 0 {
		out = append(out, "ip6 saddr { "+strings.Join(v6, ", ")+" } "+match+" accept"+comment)
	}
	return out
}

// ImportUfw — правила ufw (только «allow … in» из /etc/ufw/user.rules и user6.rules) в формате Trassa.
// Нераспознанные строки возвращаются предупреждениями, а не пропускаются молча.
func ImportUfw(sys *System) ([]*agentv1.FirewallRule, []string) {
	var rules []*agentv1.FirewallRule
	var warns []string
	for _, f := range []string{"/etc/ufw/user.rules", "/etc/ufw/user6.rules"} {
		b, err := os.ReadFile(sys.path(f))
		if err != nil {
			continue
		}
		for _, l := range strings.Split(string(b), "\n") {
			if !strings.HasPrefix(l, "### tuple ###") {
				continue
			}
			body, _, _ := strings.Cut(strings.TrimSpace(strings.TrimPrefix(l, "### tuple ###")), " comment=")
			fl := strings.Fields(body)
			if len(fl) < 6 || len(fl) > 9 {
				warns = append(warns, "ufw: строка не распознана: "+l)
				continue
			}
			action, proto, dport, src := fl[0], fl[1], fl[2], fl[5]
			dir := "in"
			if len(fl) >= 7 {
				dir = fl[len(fl)-1]
			}
			if action != "allow" || !strings.HasPrefix(dir, "in") {
				warns = append(warns, "ufw: правило не переносится (только allow для входящих): "+body)
				continue
			}
			protos := []string{proto}
			if proto == "any" {
				protos = []string{"tcp", "udp"}
			}
			var sources []string
			if src != "0.0.0.0/0" && src != "::/0" && src != "any" {
				p, err := netip.ParsePrefix(src)
				if err != nil {
					if a, aerr := netip.ParseAddr(src); aerr == nil {
						p = netip.PrefixFrom(a, a.BitLen())
					} else {
						warns = append(warns, "ufw: источник не распознан: "+body)
						continue
					}
				}
				sources = []string{p.Masked().String()}
			}
			for _, part := range strings.Split(dport, ",") {
				lo, hi, rng := strings.Cut(part, ":")
				pl, err1 := strconv.ParseUint(lo, 10, 16)
				var ph uint64
				var err2 error
				if rng {
					ph, err2 = strconv.ParseUint(hi, 10, 16)
				}
				if part == "any" || err1 != nil || err2 != nil || pl == 0 {
					warns = append(warns, "ufw: порт не распознан: "+body)
					continue
				}
				for _, pr := range protos {
					if pr != "tcp" && pr != "udp" {
						warns = append(warns, "ufw: протокол не переносится: "+body)
						continue
					}
					rules = append(rules, &agentv1.FirewallRule{Target: agentv1.FirewallTarget_FIREWALL_TARGET_HOST, Protocol: pr,
						Port: uint32(pl), PortTo: uint32(ph), Sources: sources, Comment: "из ufw"})
				}
			}
		}
	}
	return rules, warns
}
