// SPDX-License-Identifier: AGPL-3.0-only

// Package uninstall — удаление агента с сервера (E05-T23): службы остановлены, файлы и пользователь удалены.
// Вызывается «trassa-agent uninstall» (root, на сервере) и операцией agent.uninstall (из временного юнита).
package uninstall

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/NogMeer/trassa-agent/internal/config"
)

// Units — службы Trassa.
var Units = []string{"trassa-agent.service", "trassa-helper.service"}

// FirewallUnit — служба набора межсетевого экрана Trassa (E10): есть, только если firewall.apply применялся.
// Удаляется вместе с агентом: её ExecStop снимает таблицу inet trassa, иначе правила остались бы без хозяина.
const FirewallUnit = "trassa-firewall.service"

// Steps — что будет удалено.
type Steps struct {
	Units         []string
	Paths         []string
	User          string
	PurgeRollback bool
}

// Plan — список для предпросмотра и для Run.
func Plan(p config.Paths, purgeRollback bool) Steps {
	s := Steps{Units: append([]string{}, Units...), User: config.UserName, PurgeRollback: purgeRollback}
	if _, err := os.Stat(filepath.Join(p.UnitDir, FirewallUnit)); err == nil {
		s.Units = append(s.Units, FirewallUnit)
	}
	for _, u := range s.Units {
		s.Paths = append(s.Paths, filepath.Join(p.UnitDir, u))
	}
	s.Paths = append(s.Paths,
		filepath.Join(p.BinDir, "trassa-agent"), filepath.Join(p.BinDir, "trassa-helper"),
		p.EtcDir, p.RunDir, p.AgentDir, p.HelperDir, p.BinPrevDir, p.CacheDir, p.TargetBin,
	)
	if purgeRollback {
		s.Paths = append(s.Paths, p.StateDir)
	}
	// Доступ (E16): CA пространства не должен пускать на сервер без Trassa. Снимаются доверие к CA, принципалы,
	// аварийный вход и правила sudo, выданные Trassa; сами учётные записи остаются.
	s.Paths = append(s.Paths, accessPaths(p)...)
	return s
}

func accessPaths(p config.Paths) []string {
	var out []string
	for _, f := range []string{"sshd_config.d/00-trassa-access.conf", "sshd_config.d/00-trassa-rescue.conf", "trassa"} {
		if fileExists(filepath.Join(p.SSHDir, f)) {
			out = append(out, filepath.Join(p.SSHDir, f))
		}
	}
	ents, _ := os.ReadDir(p.SudoersDir)
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), "trassa-") && !strings.ContainsAny(e.Name(), ".~") {
			out = append(out, filepath.Join(p.SudoersDir, e.Name()))
		}
	}
	return out
}

// Runner выполняет внешние команды (systemctl, userdel) без оболочки.
type Runner func(ctx context.Context, name string, args ...string) error

// Exec — настоящий Runner.
func Exec(ctx context.Context, name string, args ...string) error {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Run удаляет агента. Продолжает после ошибок отдельных шагов и возвращает их все: частичное удаление лучше
// остановки на полпути.
func Run(ctx context.Context, p config.Paths, purgeRollback bool, run Runner) error {
	s := Plan(p, purgeRollback)
	var errs []error
	// Приватная сеть Trassa (E14) снимается, пока помощник ещё на месте: интерфейсы, правило DOCKER-USER,
	// блоки имён и пересылка.
	if helper := filepath.Join(p.BinDir, "trassa-helper"); fileExists(helper) {
		if err := run(ctx, helper, "wireguard-purge"); err != nil {
			errs = append(errs, err)
		}
	}
	args := append([]string{"disable", "--now"}, s.Units...)
	if err := run(ctx, "/usr/bin/systemctl", args...); err != nil {
		errs = append(errs, err)
	}
	for _, path := range s.Paths {
		if err := os.RemoveAll(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	if !purgeRollback {
		// В /var/lib/trassa остаются только точки отката.
		_ = os.Remove(p.StateDir)
	}
	if err := run(ctx, "/usr/bin/systemctl", "daemon-reload"); err != nil {
		errs = append(errs, err)
	}
	// Файлы доступа сняты — sshd перечитывает настройки (запущенный ssh.service; при ssh.socket — сам).
	if len(accessPaths(p)) == 0 && hadAccess(s) {
		if err := run(ctx, "/usr/bin/systemctl", "try-reload-or-restart", "ssh.service"); err != nil {
			errs = append(errs, err)
		}
	}
	if err := run(ctx, "/usr/sbin/userdel", s.User); err != nil && !strings.Contains(err.Error(), "does not exist") {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }

// hadAccess — в плане удаления были файлы доступа sshd.
func hadAccess(s Steps) bool {
	for _, p := range s.Paths {
		if strings.Contains(p, "00-trassa-access.conf") || strings.Contains(p, "00-trassa-rescue.conf") {
			return true
		}
	}
	return false
}
