// SPDX-License-Identifier: AGPL-3.0-only

package helper

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var unitRe = regexp.MustCompile(`^[A-Za-z0-9@._-]{1,200}$`)

// SystemdServices — Services через systemctl и systemd-run, без оболочки.
type SystemdServices struct {
	SystemdRun string
	Systemctl  string
}

// DefaultSystemdServices — пути на сервере.
func DefaultSystemdServices() SystemdServices {
	return SystemdServices{SystemdRun: "/usr/bin/systemd-run", Systemctl: "/usr/bin/systemctl"}
}

func runCmd(ctx context.Context, name string, args ...string) error {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %v: %s", filepath.Base(name), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Restart перезапускает службы.
func (s SystemdServices) Restart(ctx context.Context, units ...string) error {
	for _, u := range units {
		if !unitRe.MatchString(u) {
			return fmt.Errorf("имя службы %q", u)
		}
	}
	return runCmd(ctx, s.Systemctl, append([]string{"restart"}, units...)...)
}

// Schedule запускает argv через after во временном юните unit.
func (s SystemdServices) Schedule(ctx context.Context, unit string, after time.Duration, argv ...string) error {
	if !unitRe.MatchString(unit) || len(argv) == 0 || !filepath.IsAbs(argv[0]) {
		return fmt.Errorf("юнит %q или команда %v", unit, argv)
	}
	sec := int64((after + time.Second - 1) / time.Second)
	if sec < 1 {
		sec = 1
	}
	args := []string{
		"--unit=" + unit, "--on-active=" + strconv.FormatInt(sec, 10) + "s",
		"--timer-property=AccuracySec=1s", "--service-type=oneshot", "--collect",
	}
	return runCmd(ctx, s.SystemdRun, append(args, argv...)...)
}
