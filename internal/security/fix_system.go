// SPDX-License-Identifier: AGPL-3.0-only

package security

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/fsutil"
	"github.com/NogMeer/trassa-agent/internal/rollback"
)

// Файлы Trassa для исправлений: свои, рядом с системными, чужие не правятся.
const (
	AutoUpgradesFile = "/etc/apt/apt.conf.d/99trassa-auto-upgrades"
	Fail2banJail     = "/etc/fail2ban/jail.d/90-trassa.local"
)

func init() {
	registerFix(Fix{Code: "USER_EMPTY_PASSWORD", Plan: func(ctx context.Context, s *Scan, subjects []string) (*FixPlan, error) {
		return usermodPlan(ctx, s, "USER_EMPTY_PASSWORD", subjects, []string{"/etc/shadow", "/etc/shadow-"},
			"Заблокировать вход по паролю", func(u string) []string { return []string{"-L", "--", u} })
	}})
	registerFix(Fix{Code: "USER_SERVICE_SHELL", Plan: func(ctx context.Context, s *Scan, subjects []string) (*FixPlan, error) {
		return usermodPlan(ctx, s, "USER_SERVICE_SHELL", subjects, []string{"/etc/passwd", "/etc/passwd-"},
			"Оболочка без входа /usr/sbin/nologin", func(u string) []string { return []string{"-s", "/usr/sbin/nologin", "--", u} })
	}})
	registerFix(Fix{Code: "UPDATES_AUTO_DISABLED", Plan: planAutoUpdates})
	registerFix(Fix{Code: "TIME_SYNC_OFF", Plan: planTimeSync})
	registerFix(Fix{Code: "BRUTEFORCE_NO_PROTECTION", Plan: planFail2ban})
}

// usermodPlan — usermod для каждой записи из находок; файлы учётных записей — в точку отката.
func usermodPlan(ctx context.Context, s *Scan, code string, subjects, files []string, what string, args func(string) []string) (*FixPlan, error) {
	found, err := pick(ctx, s, code, subjects)
	if err != nil {
		return nil, err
	}
	p := &FixPlan{Summary: fmt.Sprintf("%s: записей %d", what, len(found))}
	for _, f := range files {
		p.Paths = append(p.Paths, s.sys.path(f))
	}
	var names []string
	for _, f := range found {
		names = append(names, f.Subject)
		p.Changes = append(p.Changes, &agentv1.FileChange{Path: files[0], Kind: agentv1.FileChangeKind_FILE_CHANGE_KIND_MODIFY, Diff: what + ": " + f.Subject})
	}
	p.Apply = func(ctx context.Context) error {
		for _, n := range names {
			if out, err := s.sys.run(ctx, "usermod", args(n)...); err != nil {
				return fmt.Errorf("usermod %s: %v %s", n, err, strings.TrimSpace(string(out)))
			}
		}
		return nil
	}
	return p, nil
}

func planAutoUpdates(ctx context.Context, s *Scan, subjects []string) (*FixPlan, error) {
	if _, err := pick(ctx, s, "UPDATES_AUTO_DISABLED", subjects); err != nil {
		return nil, err
	}
	ok, err := installed(s.sys, "unattended-upgrades")
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("%w: пакет unattended-upgrades не установлен", ErrPrecondition)
	}
	// Имя на 99: apt читает apt.conf.d по порядку, и последнее значение побеждает.
	content := "// Trassa: автоустановка обновлений безопасности (центр безопасности).\n" +
		"APT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Unattended-Upgrade \"1\";\n"
	return fileWritePlan(s.sys, AutoUpgradesFile, content, "Включить автоустановку обновлений безопасности", nil, rollback.State{}), nil
}

// fileWritePlan — записать свой файл целиком.
func fileWritePlan(sys *System, path, content, summary string, services []string, st rollback.State) *FixPlan {
	real := sys.path(path)
	kind := agentv1.FileChangeKind_FILE_CHANGE_KIND_CREATE
	old, err := os.ReadFile(real)
	if err == nil {
		kind = agentv1.FileChangeKind_FILE_CHANGE_KIND_MODIFY
	}
	return &FixPlan{
		Summary: summary, Paths: []string{real}, Services: services, State: st,
		Changes: []*agentv1.FileChange{{Path: path, Kind: kind, Diff: lineDiff(string(old), content)}},
		Apply: func(context.Context) error {
			if err := os.MkdirAll(dirOf(real), 0o755); err != nil {
				return err
			}
			return fsutil.WriteFileAtomic(real, []byte(content), 0o644, fsutil.Keep)
		},
	}
}

func dirOf(p string) string { return p[:strings.LastIndex(p, "/")] }

func lineDiff(a, b string) string {
	var sb strings.Builder
	for _, l := range strings.Split(strings.TrimSuffix(a, "\n"), "\n") {
		if a != "" {
			sb.WriteString("-" + l + "\n")
		}
	}
	for _, l := range strings.Split(strings.TrimSuffix(b, "\n"), "\n") {
		sb.WriteString("+" + l + "\n")
	}
	return sb.String()
}

// unitState — включена ли и работает ли служба сейчас (для отката).
func unitState(ctx context.Context, sys *System, unit string) rollback.UnitState {
	en, _ := sys.run(ctx, "systemctl", "is-enabled", "--", unit)
	return rollback.UnitState{Name: unit, Enabled: strings.TrimSpace(string(en)) == "enabled", Active: unitActive(ctx, sys, unit)}
}

// unitExists — юнит известен systemd (LoadState не not-found).
func unitExists(ctx context.Context, sys *System, unit string) bool {
	out, _ := sys.run(ctx, "systemctl", "show", "--property=LoadState", "--value", "--", unit)
	v := strings.TrimSpace(string(out))
	return v != "" && v != "not-found"
}

func planTimeSync(ctx context.Context, s *Scan, subjects []string) (*FixPlan, error) {
	if _, err := pick(ctx, s, "TIME_SYNC_OFF", subjects); err != nil {
		return nil, err
	}
	// Штатная служба: chrony, если стоит, иначе systemd-timesyncd (decisions E10, время).
	unit := ""
	for _, u := range []string{"chrony.service", "systemd-timesyncd.service"} {
		if unitExists(ctx, s.sys, u) {
			unit = u
			break
		}
	}
	if unit == "" {
		return nil, fmt.Errorf("%w: служба синхронизации времени не установлена", ErrPrecondition)
	}
	st := unitState(ctx, s.sys, unit)
	return &FixPlan{
		Summary: "Включить синхронизацию времени: " + unit,
		State:   rollback.State{Units: []rollback.UnitState{st}},
		Notes:   []string{"Служба " + unit + " будет включена и запущена"},
		Apply: func(ctx context.Context) error {
			out, err := s.sys.run(ctx, "systemctl", "enable", "--now", "--", unit)
			if err != nil {
				return fmt.Errorf("systemctl enable --now %s: %v %s", unit, err, strings.TrimSpace(string(out)))
			}
			return nil
		},
		// Синхронизация занимает время: проверяется, что служба работает, а не что часы уже сошлись.
		Verify: func(ctx context.Context) error {
			if !unitActive(ctx, s.sys, unit) {
				return fmt.Errorf("%s не запустилась", unit)
			}
			return nil
		},
	}, nil
}

func planFail2ban(ctx context.Context, s *Scan, subjects []string) (*FixPlan, error) {
	if _, err := pick(ctx, s, "BRUTEFORCE_NO_PROTECTION", subjects); err != nil {
		return nil, err
	}
	// backend = systemd читает журнал через python3-systemd: без него сервер fail2ban не стартует.
	var missing []string
	for _, pkg := range []string{"fail2ban", "python3-systemd"} {
		ok, err := installed(s.sys, pkg)
		if err != nil {
			return nil, err
		}
		if !ok {
			missing = append(missing, pkg)
		}
	}
	have := len(missing) == 0
	st := rollback.State{Packages: missing}
	st.Units = []rollback.UnitState{unitState(ctx, s.sys, "fail2ban.service")}
	p := fileWritePlan(s.sys, Fail2banJail, "", "Защита от перебора: fail2ban для SSH", nil, st)
	p.Notes = []string{"Только fail2ban из репозитория системы (decisions E10, п. 12)"}
	if !have {
		p.Notes = append(p.Notes, "Будут установлены пакеты: "+strings.Join(missing, ", "))
	}
	p.Apply = func(ctx context.Context) error {
		if !have {
			args := append([]string{"install", "-y", "-q", "--no-install-recommends"}, missing...)
			if out, err := s.sys.run(ctx, "apt-get", args...); err != nil {
				return fmt.Errorf("apt-get install %v: %v %s", missing, err, tail(out))
			}
		}
		content, err := fail2banJail(s.sys)
		if err != nil {
			return err
		}
		p.Changes[0].Diff = lineDiff("", content)
		real := s.sys.path(Fail2banJail)
		if err := os.MkdirAll(dirOf(real), 0o755); err != nil {
			return err
		}
		if err := fsutil.WriteFileAtomic(real, []byte(content), 0o644, fsutil.Keep); err != nil {
			return err
		}
		for _, a := range [][]string{{"enable", "--", "fail2ban.service"}, {"restart", "--", "fail2ban.service"}} {
			if out, err := s.sys.run(ctx, "systemctl", a...); err != nil {
				return fmt.Errorf("systemctl %s: %v %s", a[0], err, tail(out))
			}
		}
		return nil
	}
	// Сервер fail2ban поднимается несколько секунд после restart: ждём до 30 с.
	p.Verify = func(ctx context.Context) error {
		var last string
		for i := 0; i < 30; i++ {
			out, err := s.sys.run(ctx, "fail2ban-client", "status", "sshd")
			if err == nil {
				return nil
			}
			last = fmt.Sprintf("%v %s", err, tail(out))
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(fail2banPoll):
			}
		}
		return fmt.Errorf("fail2ban-client status sshd: %s", last)
	}
	if content, err := fail2banJail(s.sys); err == nil {
		p.Changes[0].Diff = lineDiff("", content)
	}
	return p, nil
}

// fail2banJail — jail sshd: журнал systemd (sshd пишет в journald) и действие nftables, если оно есть в этой
// версии fail2ban (nftables.conf — новее, nftables-multiport — в 0.11 Ubuntu 22.04); иначе действие по умолчанию.
func fail2banJail(sys *System) (string, error) {
	var b strings.Builder
	b.WriteString("# Trassa: защита SSH от перебора (центр безопасности).\n[sshd]\nenabled = true\nbackend = systemd\n")
	for _, a := range []string{"nftables", "nftables-multiport"} {
		if _, err := os.Stat(sys.path("/etc/fail2ban/action.d/" + a + ".conf")); err == nil {
			b.WriteString("banaction = " + a + "\n")
			return b.String(), nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
	}
	return b.String(), nil
}

// fail2banPoll — шаг ожидания сервера fail2ban (переменная: тест сокращает).
var fail2banPoll = time.Second

func tail(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 500 {
		s = s[len(s)-500:]
	}
	return s
}
