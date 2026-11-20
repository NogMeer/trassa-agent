// SPDX-License-Identifier: AGPL-3.0-only

package security

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
)

func init() {
	register(Check{Code: "UPDATES_SECURITY_PENDING", Run: checkSecurityUpdates})
	register(Check{Code: "UPDATES_AUTO_DISABLED", Run: checkAutoUpdates})
}

// instRe — строка `apt-get -s dist-upgrade`: «Inst <pkg> [<текущая>] (<кандидат> <Label:Version/Archive>, … [<arch>])»
// (apt-pkg/algorithms.cc, pkgSimulate::Describe). Текущей версии нет у нового пакета.
var instRe = regexp.MustCompile(`^Inst (\S+)(?: \[([^\]]+)\])? \((\S+) (.*)\)\s*$`)

// ParseSimulate разбирает вывод `LC_ALL=C apt-get -s dist-upgrade`. Признак обновления безопасности — у одного из
// источников кандидата архив оканчивается на «-security» (Ubuntu jammy-security, noble-security, ESM
// *-apps-security, *-infra-security; Debian stable-security, oldstable-security) или метка Debian-Security.
func ParseSimulate(out []byte) []*agentv1.PackageUpdate {
	var res []*agentv1.PackageUpdate
	for _, l := range strings.Split(string(out), "\n") {
		m := instRe.FindStringSubmatch(strings.TrimSpace(l))
		if m == nil {
			continue
		}
		u := &agentv1.PackageUpdate{Name: m[1], Current: m[2], Candidate: m[3]}
		rel := m[4]
		if i := strings.LastIndex(rel, " ["); i >= 0 {
			rel = rel[:i]
		}
		for _, src := range strings.Split(rel, ", ") {
			label, rest, _ := strings.Cut(src, ":")
			_, archive, _ := strings.Cut(rest, "/")
			if label == "Debian-Security" || strings.HasSuffix(archive, "-security") {
				u.Security = true
			}
		}
		res = append(res, u)
	}
	return res
}

// ListUpdates — packages.list_updates: только кэш apt, без сети и без блокировки (-s).
func ListUpdates(ctx context.Context, sys *System) (*agentv1.PackagesListUpdatesResult, error) {
	out, err := sys.run(ctx, "apt-get", "-s", "-o", "Debug::NoLocking=true", "dist-upgrade")
	if err != nil {
		return nil, fmt.Errorf("apt-get -s dist-upgrade: %w", err)
	}
	res := &agentv1.PackagesListUpdatesResult{Packages: ParseSimulate(out)}
	if _, err := os.Stat(sys.path("/run/reboot-required")); err == nil {
		res.RebootRequired = true
		if b, err := os.ReadFile(sys.path("/run/reboot-required.pkgs")); err == nil {
			res.RebootPackages = strings.Fields(string(b))
		}
	}
	return res, nil
}

func checkSecurityUpdates(ctx context.Context, s *Scan) []Finding {
	res, err := ListUpdates(ctx, s.sys)
	if err != nil {
		return []Finding{failed(ErrReadFailed, err)}
	}
	var names []string
	for _, p := range res.GetPackages() {
		if p.GetSecurity() {
			names = append(names, p.GetName())
		}
	}
	if len(names) == 0 {
		return nil
	}
	shown := names[:min(len(names), 30)]
	return []Finding{fail("", fmt.Sprintf("обновлений безопасности: %d (%s)", len(names), strings.Join(shown, ", ")))}
}

// aptConfig — значения `apt-config dump` (действующие, с учётом всех файлов apt.conf.d).
func aptConfig(ctx context.Context, sys *System) (map[string]string, error) {
	out, err := sys.run(ctx, "apt-config", "dump")
	if err != nil {
		return nil, fmt.Errorf("apt-config dump: %w", err)
	}
	cfg := map[string]string{}
	for _, l := range strings.Split(string(out), "\n") {
		k, v, ok := strings.Cut(strings.TrimSuffix(strings.TrimSpace(l), ";"), " ")
		if ok {
			cfg[k] = strings.Trim(v, `"`)
		}
	}
	return cfg, nil
}

// installed — пакет установлен по /var/lib/dpkg/status («Status: install ok installed»).
func installed(sys *System, pkg string) (bool, error) {
	b, err := os.ReadFile(sys.path("/var/lib/dpkg/status"))
	if err != nil {
		return false, err
	}
	for _, para := range strings.Split(string(b), "\n\n") {
		if strings.HasPrefix(para, "Package: "+pkg+"\n") && strings.Contains(para, "\nStatus: install ok installed") {
			return true, nil
		}
	}
	return false, nil
}

func checkAutoUpdates(ctx context.Context, s *Scan) []Finding {
	ok, err := installed(s.sys, "unattended-upgrades")
	if err != nil {
		return []Finding{failed(ErrReadFailed, err)}
	}
	if !ok {
		return []Finding{fail("", "пакет unattended-upgrades не установлен")}
	}
	cfg, err := aptConfig(ctx, s.sys)
	if err != nil {
		return []Finding{failed(ErrReadFailed, err)}
	}
	for _, k := range []string{"APT::Periodic::Update-Package-Lists", "APT::Periodic::Unattended-Upgrade"} {
		if v := cfg[k]; v == "" || v == "0" {
			return []Finding{fail("", k+" выключен")}
		}
	}
	return nil
}
