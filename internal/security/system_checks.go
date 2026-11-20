// SPDX-License-Identifier: AGPL-3.0-only

package security

import (
	"context"
	"fmt"
	"strings"
	"time"
)

func init() {
	register(Check{Code: "TIME_SYNC_OFF", Run: checkTimeSync})
	register(Check{Code: "OS_EOL", Run: checkEOL})
}

// maxSyncError — ядро считает часы синхронизированными, пока maxerror меньше 16 с (так считает systemd
// NTPSynchronized; adjtimex с modes=0 читается без прав).
const maxSyncError = 16_000_000

func checkTimeSync(ctx context.Context, s *Scan) []Finding {
	if s.sys.Adjtimex == nil {
		return []Finding{failed(ErrUnsupported, fmt.Errorf("adjtimex недоступен"))}
	}
	maxErr, err := s.sys.Adjtimex()
	if err != nil {
		return []Finding{failed(ErrReadFailed, err)}
	}
	if maxErr < maxSyncError {
		return []Finding{pass("", fmt.Sprintf("часы синхронизированы, погрешность до %d мс", maxErr/1000))}
	}
	svc := "ни systemd-timesyncd, ни chrony не работают"
	for _, u := range []string{"systemd-timesyncd.service", "chrony.service", "chronyd.service"} {
		if unitActive(ctx, s.sys, u) {
			svc = u + " работает, но синхронизации нет"
			break
		}
	}
	return []Finding{fail("", "часы не синхронизированы: "+svc)}
}

// Сроки поддержки (decisions E10, OS_EOL): Ubuntu — стандартная поддержка (ESM — платная подписка Ubuntu Pro);
// Debian — конец LTS (до него обновления безопасности выходят бесплатно). Месяц Ubuntu — его последний день.
var eol = map[string]struct {
	end  string
	note string
}{
	"ubuntu 22.04": {"2027-05-31", "стандартная поддержка до мая 2027, дальше ESM (Ubuntu Pro) до мая 2032"},
	"ubuntu 24.04": {"2029-05-31", "стандартная поддержка до мая 2029, дальше ESM (Ubuntu Pro) до мая 2034"},
	"debian 12":    {"2028-06-30", "основная поддержка закончилась 2026-07-11, LTS до 2028-06-30"},
	"debian 13":    {"2030-06-30", "основная поддержка до 2028-08-09, LTS до 2030-06-30"},
}

func checkEOL(_ context.Context, s *Scan) []Finding {
	ls, err := s.sys.lines("/etc/os-release")
	if err != nil {
		return []Finding{failed(ErrReadFailed, err)}
	}
	kv := map[string]string{}
	for _, l := range ls {
		if k, v, ok := strings.Cut(l, "="); ok {
			kv[k] = strings.Trim(v, `"`)
		}
	}
	key := kv["ID"] + " " + kv["VERSION_ID"]
	e, ok := eol[key]
	if !ok {
		return []Finding{na("срок поддержки " + key + " неизвестен")}
	}
	end, _ := time.Parse("2006-01-02", e.end)
	if !s.sys.Now().Before(end.Add(24 * time.Hour)) {
		return []Finding{fail(key, key+": поддержка закончилась ("+e.note+")")}
	}
	return []Finding{pass(key, key+": "+e.note)}
}
