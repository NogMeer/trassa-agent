// SPDX-License-Identifier: AGPL-3.0-only

package security

import (
	"context"
	"fmt"
	"strings"
)

func init() {
	register(Check{Code: "BRUTEFORCE_NO_PROTECTION", Run: checkBruteforceProtection})
	register(Check{Code: "BRUTEFORCE_ACTIVE", Run: checkBruteforceActive})
}

// unitActive — служба активна (systemctl is-active печатает состояние и без прав).
func unitActive(ctx context.Context, sys *System, unit string) bool {
	out, _ := sys.run(ctx, "systemctl", "is-active", unit)
	return strings.TrimSpace(string(out)) == "active"
}

func checkBruteforceProtection(ctx context.Context, s *Scan) []Finding {
	for _, u := range []string{"crowdsec.service", "fail2ban.service"} {
		if unitActive(ctx, s.sys, u) {
			return []Finding{pass("", u+" работает")}
		}
	}
	return []Finding{fail("", "нет работающей защиты от перебора (CrowdSec или fail2ban)")}
}

// BruteforceThreshold — неудачных входов SSH за сутки, после которых перебор считается активным. Порог —
// решение продукта (E10, раздел 13, вопрос 16), на парке не сверен.
var BruteforceThreshold = 200

// Строки sshd о неудачном входе.
var failedMarkers = []string{"Failed password for", "Invalid user ", "authentication failure", "Failed publickey for"}

func checkBruteforceActive(ctx context.Context, s *Scan) []Finding {
	// По идентификатору, а не по службе: при запуске через ssh.socket у каждого входа своя служба ssh@….service;
	// с OpenSSH 9.8 вход обслуживает отдельная программа sshd-session.
	out, err := s.sys.run(ctx, "journalctl", "--no-pager", "--quiet", "--output=cat", "--since=-24h",
		"--identifier=sshd", "--identifier=sshd-session")
	if err != nil && len(out) == 0 {
		return []Finding{failed(ErrReadFailed, fmt.Errorf("journalctl: %w", err))}
	}
	n := 0
	for _, l := range strings.Split(string(out), "\n") {
		for _, m := range failedMarkers {
			if strings.Contains(l, m) {
				n++
				break
			}
		}
	}
	ev := fmt.Sprintf("неудачных входов SSH за сутки: %d", n)
	if n >= BruteforceThreshold {
		return []Finding{fail("", ev)}
	}
	return []Finding{pass("", ev)}
}
