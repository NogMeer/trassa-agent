// SPDX-License-Identifier: AGPL-3.0-only

package security

import (
	"context"
	"errors"
	"strings"
	"testing"
)

const simUbuntu = `Reading package lists...
Building dependency tree...
Calculating upgrade...
The following packages will be upgraded:
  libc6 tzdata
Inst libc6 [2.35-0ubuntu3.1] (2.35-0ubuntu3.4 Ubuntu:22.04/jammy-updates, Ubuntu:22.04/jammy-security [amd64])
Inst tzdata [2023c-0ubuntu0.22.04.1] (2024a-0ubuntu0.22.04 Ubuntu:22.04/jammy-updates [all])
Inst libnew (1.0-1 Ubuntu:22.04/jammy-updates [amd64])
Conf libc6 (2.35-0ubuntu3.4 Ubuntu:22.04/jammy-updates, Ubuntu:22.04/jammy-security [amd64])
`

const simDebian = `Inst openssl [3.0.11-1~deb12u2] (3.0.15-1~deb12u1 Debian-Security:12/oldstable-security [amd64])
Inst curl [8.14.1-2] (8.14.1-2+deb13u1 Debian:13.1/stable [arm64])
`

func TestParseSimulate(t *testing.T) {
	u := ParseSimulate([]byte(simUbuntu))
	if len(u) != 3 || !u[0].GetSecurity() || u[1].GetSecurity() || u[2].GetCurrent() != "" || u[0].GetCandidate() != "2.35-0ubuntu3.4" {
		t.Fatalf("%+v", u)
	}
	d := ParseSimulate([]byte(simDebian))
	if len(d) != 2 || !d[0].GetSecurity() || d[1].GetSecurity() {
		t.Fatalf("%+v", d)
	}
}

func TestUpdatesChecks(t *testing.T) {
	sys := build(t, tree{
		"var/lib/dpkg/status": "Package: unattended-upgrades\nStatus: install ok installed\nVersion: 2.9\n\nPackage: x\nStatus: deinstall ok config-files\n",
	})
	apt := map[string]string{"apt-get": simUbuntu, "apt-config": "APT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Unattended-Upgrade \"0\";\n"}
	var argv []string
	sys.Run = func(_ context.Context, name string, args ...string) ([]byte, error) {
		argv = append(argv, name+" "+strings.Join(args, " "))
		if out, ok := apt[name]; ok {
			return []byte(out), nil
		}
		return nil, errors.New("нет программы")
	}
	r := scan(t, sys, "UPDATES_SECURITY_PENDING", "UPDATES_AUTO_DISABLED")
	if states(r["UPDATES_SECURITY_PENDING"]) != "FAIL:" || !strings.Contains(r["UPDATES_SECURITY_PENDING"][0].GetEvidence(), "libc6") {
		t.Errorf("%+v", r["UPDATES_SECURITY_PENDING"])
	}
	if states(r["UPDATES_AUTO_DISABLED"]) != "FAIL:" {
		t.Errorf("%+v", r["UPDATES_AUTO_DISABLED"])
	}
	if !strings.Contains(strings.Join(argv, ";"), "apt-get -s ") {
		t.Fatalf("apt-get без -s: %v", argv)
	}
	apt["apt-config"] = "APT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Unattended-Upgrade \"1\";\n"
	if got := states(scan(t, sys, "UPDATES_AUTO_DISABLED")["UPDATES_AUTO_DISABLED"]); got != "PASS:" {
		t.Error(got)
	}
	sys2 := build(t, tree{"var/lib/dpkg/status": "Package: x\nStatus: install ok installed\n"})
	sys2.Run = sys.Run
	if got := states(scan(t, sys2, "UPDATES_AUTO_DISABLED")["UPDATES_AUTO_DISABLED"]); got != "FAIL:" {
		t.Error("без пакета:", got)
	}
}

func TestBruteforce(t *testing.T) {
	sys := build(t, tree{})
	log := strings.Repeat("Failed password for root from 203.0.113.9 port 22 ssh2\n", 250) + "Accepted publickey for alice\n"
	active := ""
	sys.Run = func(_ context.Context, name string, args ...string) ([]byte, error) {
		switch name {
		case "journalctl":
			return []byte(log), nil
		case "systemctl":
			if args[1] == active {
				return []byte("active\n"), nil
			}
			return []byte("inactive\n"), errors.New("exit 3")
		}
		return nil, errors.New("нет")
	}
	r := scan(t, sys, "BRUTEFORCE_NO_PROTECTION", "BRUTEFORCE_ACTIVE")
	if states(r["BRUTEFORCE_NO_PROTECTION"]) != "FAIL:" || states(r["BRUTEFORCE_ACTIVE"]) != "FAIL:" {
		t.Fatalf("%v %v", r["BRUTEFORCE_NO_PROTECTION"], r["BRUTEFORCE_ACTIVE"])
	}
	active = "fail2ban.service"
	log = "Failed password for root\n"
	r = scan(t, sys, "BRUTEFORCE_NO_PROTECTION", "BRUTEFORCE_ACTIVE")
	if states(r["BRUTEFORCE_NO_PROTECTION"]) != "PASS:" || states(r["BRUTEFORCE_ACTIVE"]) != "PASS:" {
		t.Fatalf("%v %v", r["BRUTEFORCE_NO_PROTECTION"], r["BRUTEFORCE_ACTIVE"])
	}
}
