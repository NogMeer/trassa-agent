// SPDX-License-Identifier: AGPL-3.0-only

package security

import (
	"context"
	"errors"
	"strings"
	"testing"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
)

const rulesetOpen = `table ip nat {
	chain DOCKER {
	}
}
`

const rulesetUfw = `table ip filter {
	chain ufw-before-input {
	}
	chain INPUT {
		type filter hook input priority filter; policy drop;
		counter packets 1 bytes 2 jump ufw-before-input
	}
}
`

func fwSystem(t *testing.T, ruleset string, ufw bool, docker bool) *System {
	files := tree{"proc/net/tcp": procTCP, "proc/net/udp": "  sl\n",
		"proc/20/fd/5": "->socket:[1003]", "proc/20/comm": "redis-server\n",
		"proc/20/cgroup": "0::/system.slice/docker-" + strings.Repeat("ab", 32) + ".scope\n"}
	if ufw {
		files["etc/ufw/ufw.conf"] = "# comment\nENABLED=yes\nLOGLEVEL=low\n"
	}
	sys := build(t, files)
	if docker {
		sys.Docker = &fakeDocker{body: `[{"Id":"` + strings.Repeat("ab", 32) + `","Names":["/cache"],"Ports":[{"PublicPort":6379,"Type":"tcp"}]}]`}
	}
	sys.Run = func(_ context.Context, name string, args ...string) ([]byte, error) {
		switch name {
		case "nft":
			return []byte(ruleset), nil
		case "systemctl":
			return []byte("inactive\n"), errors.New("exit 3")
		}
		return nil, errors.New("нет программы")
	}
	return sys
}

func TestFirewall(t *testing.T) {
	r := scan(t, fwSystem(t, rulesetOpen, false, false), "FIREWALL_INACTIVE", "FIREWALL_UFW_DOCKER", "FIREWALL_DOCKER_BYPASS")
	if states(r["FIREWALL_INACTIVE"]) != "FAIL:" || states(r["FIREWALL_UFW_DOCKER"]) != "NA:" || states(r["FIREWALL_DOCKER_BYPASS"]) != "NA:" {
		t.Fatalf("открытый: %s %s %s", states(r["FIREWALL_INACTIVE"]), states(r["FIREWALL_UFW_DOCKER"]), states(r["FIREWALL_DOCKER_BYPASS"]))
	}
	sys := fwSystem(t, rulesetUfw, true, true)
	res := Run(context.Background(), sys, &agentv1.SecurityScanParams{Checks: []string{"FIREWALL_INACTIVE", "FIREWALL_UFW_DOCKER", "FIREWALL_DOCKER_BYPASS"}})
	got := map[string]string{}
	for _, c := range res.GetChecks() {
		got[c.GetCode()] += strings.TrimPrefix(c.GetState().String(), "CHECK_STATE_") + ":" + c.GetSubject()
	}
	if got["FIREWALL_INACTIVE"] != "PASS:" || got["FIREWALL_UFW_DOCKER"] != "FAIL:" || got["FIREWALL_DOCKER_BYPASS"] != "FAIL:tcp/6379" {
		t.Fatalf("ufw и Docker: %v", got)
	}
	fw := res.GetFirewall()
	if fw.GetBackend() != "nftables" || !fw.GetUfwActive() || fw.GetDockerBackend() != "iptables" || fw.GetTrassaTable() {
		t.Fatalf("снимок: %+v", fw)
	}
	// Таблица Trassa есть — обход закрыт её цепочкой forward.
	r = scan(t, fwSystem(t, rulesetUfw+"table inet trassa {\n}\n", true, true), "FIREWALL_DOCKER_BYPASS")
	if states(r["FIREWALL_DOCKER_BYPASS"]) != "PASS:" {
		t.Fatal(states(r["FIREWALL_DOCKER_BYPASS"]))
	}
}
