// SPDX-License-Identifier: AGPL-3.0-only

package security

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
)

type detClock struct{ t time.Time }

func (c *detClock) now() time.Time { return c.t }

func detSystem(t *testing.T) (*System, *Detector, *detClock) {
	sys := build(t, tree{
		"etc/passwd": "root:x:0:0::/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n", "etc/shadow": "",
		"home/alice/.ssh/authorized_keys":     "ssh-ed25519 " + sshBlob("ssh-ed25519", make([]byte, 32)) + " alice\n",
		"etc/crontab":                         "SHELL=/bin/sh\n17 * * * * root cd / && run-parts --report /etc/cron.hourly\n",
		"etc/systemd/system/app.service":      "[Service]\nExecStart=/usr/local/bin/app\n",
		"etc/systemd/system/trassa-x.service": "[Service]\n",
		"proc/1/exe":                          "->/usr/lib/systemd/systemd", "proc/1/comm": "systemd\n", "proc/1/stat": "1 (systemd) S 0 1 1 0 -1 0 0 0 0 0 10 5 0 0 20 0 1 0\n",
		"proc/net/tcp": "  sl\n",
	})
	clk := &detClock{t: time.Unix(1_800_000_000, 0)}
	sys.Now = clk.now
	d := &Detector{Sys: sys, Path: filepath.Join(t.TempDir(), "baseline.json")}
	sys.Detector = d
	return sys, d, clk
}

func steps(t *testing.T, d *Detector, clk *detClock, n int, each func(i int)) []*agentv1.Event {
	return stepsBy(t, d, clk, n, FastInterval, each)
}

func stepsBy(t *testing.T, d *Detector, clk *detClock, n int, by time.Duration, each func(i int)) []*agentv1.Event {
	t.Helper()
	var evs []*agentv1.Event
	for i := 0; i < n; i++ {
		if each != nil {
			each(i)
		}
		if err := d.Step(context.Background()); err != nil {
			t.Fatal(err)
		}
		evs = append(evs, d.Drain()...)
		clk.t = clk.t.Add(by)
	}
	return evs
}

// Чистая система: 24 часа модельного времени без событий.
func TestDetectorQuiet24h(t *testing.T) {
	_, d, clk := detSystem(t)
	if evs := stepsBy(t, d, clk, 24*12, 5*time.Minute, nil); len(evs) != 0 {
		t.Fatalf("событий %d: %v", len(evs), evs[0])
	}
}

func TestDetectorNewKeyAndAccept(t *testing.T) {
	sys, d, clk := detSystem(t)
	steps(t, d, clk, 1, nil) // базовый список
	f, _ := os.OpenFile(filepath.Join(sys.Root, "home/alice/.ssh/authorized_keys"), os.O_APPEND|os.O_WRONLY, 0)
	fmt.Fprintf(f, "ssh-ed25519 %s intruder\n", sshBlob("ssh-ed25519", []byte("01234567890123456789012345678901")))
	f.Close()
	evs := steps(t, d, clk, 30, nil)
	if len(evs) != 1 {
		t.Fatalf("за 30 минут событий %d, ждали 1 (раз в час)", len(evs))
	}
	a := evs[0].GetAttributes()
	if evs[0].GetKind() != "security.suspicious" || a["code"] != "COMPROMISE_KEYS_CHANGED" || a["baseline_kind"] != KindAuthorizedKey || len(a["fingerprint"]) != 64 {
		t.Fatalf("%+v", evs[0])
	}
	// Скан видит ожидающий объект.
	r := scan(t, sys, "COMPROMISE_KEYS_CHANGED")
	if len(r["COMPROMISE_KEYS_CHANGED"]) != 1 || r["COMPROMISE_KEYS_CHANGED"][0].GetState() != agentv1.CheckState_CHECK_STATE_FAIL {
		t.Fatalf("%v", r)
	}
	// Через час — повтор, пока не принят.
	if evs := steps(t, d, clk, 31, nil); len(evs) != 1 {
		t.Fatalf("повтор через час: %d", len(evs))
	}
	if _, err := d.Accept([]string{"00" + a["fingerprint"][2:]}); err == nil {
		t.Fatal("чужой отпечаток принят")
	}
	digest, err := d.Accept([]string{a["fingerprint"]})
	if err != nil || len(digest) != 64 {
		t.Fatal(err)
	}
	if evs := steps(t, d, clk, 120, nil); len(evs) != 0 {
		t.Fatalf("после принятия: %v", evs)
	}
	res := Run(context.Background(), sys, &agentv1.SecurityScanParams{Checks: []string{"COMPROMISE_KEYS_CHANGED"}})
	if res.GetBaselineDigest() != digest || states(res.GetChecks()) != "PASS:" {
		t.Fatalf("%s %s", res.GetBaselineDigest(), states(res.GetChecks()))
	}
}

// Процесс из /tmp с нагрузкой: TMP_EXEC сразу, MINER_CPU — после 15 минут нагрузки (событие к 16-й минуте).
func TestDetectorMiner(t *testing.T) {
	sys, d, clk := detSystem(t)
	steps(t, d, clk, 1, nil)
	exe := filepath.Join(sys.Root, "proc/4242/exe")
	_ = os.MkdirAll(filepath.Dir(exe), 0o755)
	_ = os.Symlink("/tmp/.x/xmrig", exe)
	_ = os.WriteFile(filepath.Join(sys.Root, "proc/4242/comm"), []byte("xmrig\n"), 0o644)
	ticks := 0
	minute := -1
	evs := steps(t, d, clk, 20, func(i int) {
		_ = os.WriteFile(filepath.Join(sys.Root, "proc/4242/stat"), []byte(fmt.Sprintf("4242 (xmr ig) R 1 1 1 0 -1 0 0 0 0 0 %d 0 0 0 20 0 1 0\n", ticks)), 0o644)
		ticks += 60 * clkTck * 95 / 100 // 95% одного ядра
	})
	var tmp, miner bool
	for i, e := range evs {
		switch e.GetAttributes()["code"] {
		case "COMPROMISE_TMP_EXEC":
			tmp = true
		case "COMPROMISE_MINER_CPU":
			miner = true
			minute = int(time.UnixMilli(e.GetAtMs()).Sub(time.Unix(1_800_000_000, 0)).Minutes())
			_ = i
		}
	}
	if !tmp || !miner || minute > 17 || minute < 15 {
		t.Fatalf("tmp=%v miner=%v на минуте %d: %v", tmp, miner, minute, evs)
	}
}

// Новые пользователи: из реестра доступа Trassa — не находка; чужой trassa-x и trassa-rescue, созданный не
// Trassa, — находка.
func TestDetectorAccessUsers(t *testing.T) {
	sys, d, clk := detSystem(t)
	steps(t, d, clk, 1, nil)
	passwd := filepath.Join(sys.Root, "etc/passwd")
	f, _ := os.OpenFile(passwd, os.O_APPEND|os.O_WRONLY, 0)
	fmt.Fprint(f, "ops:x:1001:1001::/home/ops:/bin/bash\ntrassa-x:x:1002:1002::/home/x:/bin/bash\ntrassa-rescue:x:1003:1003::/home/r:/bin/bash\n")
	f.Close()
	_ = os.MkdirAll(filepath.Join(sys.Root, "etc/trassa/access"), 0o700)
	_ = os.WriteFile(filepath.Join(sys.Root, "etc/trassa/access/state.json"), []byte(`{"users":{"ops":{"sudo":true}}}`), 0o600)
	got := map[string]bool{}
	for _, ev := range steps(t, d, clk, 30, nil) {
		if ev.GetAttributes()["code"] == "COMPROMISE_NEW_USER" {
			got[ev.GetAttributes()["subject"]] = true
		}
	}
	if got["ops"] || !got["trassa-x"] || !got["trassa-rescue"] {
		t.Fatalf("находки: %v", got)
	}
}

// Прод MeerGuard, 2026-11-26: /etc/cron.d/geoipupdate.dpkg-new (остаток dpkg) давал «новое задание», хотя cron и
// run-parts файлы с точкой в имени не исполняют. Настоящее новое задание — находка.
func TestDetectorCronSkipsDpkgLeftovers(t *testing.T) {
	sys, d, clk := detSystem(t)
	steps(t, d, clk, 1, nil)
	for p, body := range map[string]string{
		"etc/cron.d/geoipupdate.dpkg-new": "47 6 * * 3 root /usr/bin/geoipupdate\n",
		"etc/cron.daily/man-db.dpkg-old":  "#!/bin/sh\n",
		"etc/cron.d/backup":               "0 3 * * * root /usr/local/bin/backup\n",
	} {
		full := filepath.Join(sys.Root, p)
		_ = os.MkdirAll(filepath.Dir(full), 0o755)
		_ = os.WriteFile(full, []byte(body), 0o644)
	}
	var got []string
	for _, ev := range steps(t, d, clk, 2, nil) {
		if ev.GetAttributes()["code"] == "COMPROMISE_NEW_CRON" {
			got = append(got, ev.GetAttributes()["subject"])
		}
	}
	if len(got) != 1 || got[0] != "/etc/cron.d/backup: 0 3 * * * root /usr/local/bin/backup" {
		t.Fatalf("%v", got)
	}
}
