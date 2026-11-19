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

// Steps — что будет удалено.
type Steps struct {
	Units         []string
	Paths         []string
	User          string
	PurgeRollback bool
}

// Plan — список для предпросмотра и для Run.
func Plan(p config.Paths, purgeRollback bool) Steps {
	s := Steps{Units: Units, User: config.UserName, PurgeRollback: purgeRollback}
	for _, u := range Units {
		s.Paths = append(s.Paths, filepath.Join(p.UnitDir, u))
	}
	s.Paths = append(s.Paths,
		filepath.Join(p.BinDir, "trassa-agent"), filepath.Join(p.BinDir, "trassa-helper"),
		p.EtcDir, p.RunDir, p.AgentDir, p.HelperDir, p.BinPrevDir,
	)
	if purgeRollback {
		s.Paths = append(s.Paths, p.StateDir)
	}
	return s
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
	if err := run(ctx, "/usr/sbin/userdel", s.User); err != nil && !strings.Contains(err.Error(), "does not exist") {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}
