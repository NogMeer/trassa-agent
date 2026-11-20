// SPDX-License-Identifier: AGPL-3.0-only

package security

import (
	"context"
	"fmt"
	"os"
	"strings"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
)

// TrassaTable — своя таблица nftables (E10, раздел 6; decisions E10, firewall). Чужие таблицы не меняются.
const TrassaTable = "inet trassa"

func init() {
	register(Check{Code: "FIREWALL_INACTIVE", Run: checkFirewallInactive})
	register(Check{Code: "FIREWALL_UFW_DOCKER", Run: checkUfwDocker})
	register(Check{Code: "FIREWALL_DOCKER_BYPASS", Run: checkDockerBypass})
	snapshotParts = append(snapshotParts, func(ctx context.Context, s *Scan, res *agentv1.SecurityScanResult) {
		if fw, err := s.Firewall(ctx); err == nil {
			res.Firewall = fw.state
		}
	})
}

type firewall struct {
	state *agentv1.FirewallState
	// ruleset — вывод `nft list ruleset` (пусто без nftables); inputFiltered — входящий трафик чем-то режется.
	ruleset       string
	inputFiltered bool
	dockerPresent bool
}

// Firewall — состояние фильтрации (читается один раз за скан).
func (s *Scan) Firewall(ctx context.Context) (*firewall, error) {
	s.mu.Lock()
	if s.fw != nil || s.fwErr != nil {
		defer s.mu.Unlock()
		return s.fw, s.fwErr
	}
	s.mu.Unlock()
	fw, err := readFirewall(ctx, s)
	s.mu.Lock()
	s.fw, s.fwErr = fw, err
	s.mu.Unlock()
	return fw, err
}

func readFirewall(ctx context.Context, s *Scan) (*firewall, error) {
	fw := &firewall{state: &agentv1.FirewallState{Backend: "none", DockerBackend: "none"}}
	if out, err := s.sys.run(ctx, "nft", "list", "ruleset"); err == nil {
		fw.state.Backend = "nftables"
		fw.ruleset = string(out)
		fw.inputFiltered = nftInputFiltered(fw.ruleset)
		fw.state.TrassaTable = strings.Contains(fw.ruleset, "table "+TrassaTable+" {")
		if _, rest, ok := strings.Cut(fw.ruleset, `comment "trassa:`); ok && fw.state.TrassaTable {
			if h, _, ok := strings.Cut(rest, `"`); ok && len(h) == 64 {
				fw.state.TrassaRulesetHash = h
			}
		}
	}
	// iptables-legacy живёт мимо nftables: его правила nft не видит.
	if out, err := s.sys.run(ctx, "iptables-legacy", "-S", "INPUT"); err == nil && iptablesFiltered(string(out)) {
		fw.state.Backend = "iptables-legacy"
		fw.inputFiltered = true
	}
	fw.state.UfwActive = ufwEnabled(s.sys)
	fw.state.FirewalldActive = unitActive(ctx, s.sys, "firewalld.service")
	if fw.state.UfwActive || fw.state.FirewalldActive {
		fw.inputFiltered = fw.inputFiltered || fw.state.Backend != "none"
	}
	cs, err := s.Containers(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(s.sys.path("/var/run/docker.sock")); err == nil || cs != nil {
		fw.dockerPresent = true
		// Нативный бэкенд Docker (29.0+, experimental) создаёт таблицы ip/ip6 docker-bridges; иначе — iptables.
		fw.state.DockerBackend = "iptables"
		if strings.Contains(fw.ruleset, "table ip docker-bridges {") {
			fw.state.DockerBackend = "nftables"
		}
	}
	return fw, nil
}

// nftInputFiltered — в базовой цепочке hook input есть policy drop или правило drop/reject.
func nftInputFiltered(ruleset string) bool {
	inInput := false
	for _, l := range strings.Split(ruleset, "\n") {
		t := strings.TrimSpace(l)
		switch {
		case strings.HasPrefix(t, "chain "):
			inInput = false
		case strings.Contains(t, "hook input"):
			inInput = true
			if strings.Contains(t, "policy drop") {
				return true
			}
		case inInput && (strings.HasSuffix(t, " drop") || t == "drop" || strings.Contains(t, " reject")):
			return true
		}
	}
	return false
}

func iptablesFiltered(out string) bool {
	return strings.Contains(out, "-P INPUT DROP") || strings.Contains(out, "-j DROP") || strings.Contains(out, "-j REJECT")
}

// ufwEnabled — ENABLED=yes в /etc/ufw/ufw.conf (так проверяет сам ufw, is_enabled()).
func ufwEnabled(sys *System) bool {
	ls, err := sys.lines("/etc/ufw/ufw.conf")
	if err != nil {
		return false
	}
	for _, l := range ls {
		if strings.ReplaceAll(l, " ", "") == "ENABLED=yes" {
			return true
		}
	}
	return false
}

func fwOr(ctx context.Context, s *Scan) (*firewall, []Finding) {
	fw, err := s.Firewall(ctx)
	if err != nil {
		return nil, []Finding{failed(ErrReadFailed, err)}
	}
	return fw, nil
}

func checkFirewallInactive(ctx context.Context, s *Scan) []Finding {
	fw, f := fwOr(ctx, s)
	if f != nil {
		return f
	}
	if !fw.inputFiltered {
		return []Finding{fail("", "входящий трафик ничем не фильтруется (бэкенд "+fw.state.GetBackend()+")")}
	}
	return []Finding{pass("", "входящий трафик фильтруется")}
}

func checkUfwDocker(ctx context.Context, s *Scan) []Finding {
	fw, f := fwOr(ctx, s)
	if f != nil {
		return f
	}
	if !fw.state.GetUfwActive() || !fw.dockerPresent {
		return []Finding{na("нет пары ufw и Docker")}
	}
	return []Finding{fail("", "включены ufw и Docker: опубликованные порты контейнеров идут мимо правил ufw")}
}

// checkDockerBypass — порт контейнера опубликован на внешнем адресе, а входящая фильтрация сервера его не
// касается: Docker пропускает такой трафик через forward, мимо input. Таблица Trassa с цепочкой forward это
// закрывает; есть ли в ней правило для порта, панель знает по назначенному набору.
func checkDockerBypass(ctx context.Context, s *Scan) []Finding {
	fw, f := fwOr(ctx, s)
	if f != nil {
		return f
	}
	if !fw.dockerPresent {
		return []Finding{na("Docker не установлен")}
	}
	if !fw.inputFiltered || fw.state.GetTrassaTable() {
		return nil
	}
	ls, f := listenersOr(ctx, s)
	if f != nil {
		return f
	}
	var out []Finding
	seen := map[string]bool{}
	for _, l := range ls {
		if l.GetContainer() == "" || !l.GetPublic() || seen[portSubject(l)] {
			continue
		}
		seen[portSubject(l)] = true
		out = append(out, fail(portSubject(l), fmt.Sprintf("порт контейнера %s доступен снаружи в обход firewall сервера: %s", l.GetContainer(), describe(l))))
	}
	return out
}
