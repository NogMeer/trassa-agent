// SPDX-License-Identifier: AGPL-3.0-only

package security

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
)

// Обслуживание (E10, раздел 6): обновление пакетов, перезагрузка, перезапуск службы. Точки отката CONFIG у них
// нет: откат обновления — снапшот (E12) или явное согласие человека в панели.

// MaxRebootDelay — предел отложенной перезагрузки.
const MaxRebootDelay = 3600

var serviceNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9@._:-]{0,199}\.service$`)

// ValidateServiceRestart — служба с суффиксом .service; службы самой Trassa перезапускать операцией нельзя
// (помощник оборвал бы свою же операцию).
func ValidateServiceRestart(p *agentv1.ServiceRestartParams) error {
	u := p.GetUnit()
	if !serviceNameRe.MatchString(u) {
		return fmt.Errorf("unit %q: имя службы systemd с суффиксом .service", u)
	}
	if strings.HasPrefix(u, "trassa-") {
		return errors.New("службы Trassa операцией не перезапускаются")
	}
	return nil
}

// RunningServices — работающие службы (для предпросмотра и проверки после обновления).
func RunningServices(ctx context.Context, sys *System) ([]string, error) {
	out, err := sys.run(ctx, "systemctl", "list-units", "--type=service", "--state=running", "--no-legend", "--plain", "--no-pager")
	if err != nil {
		return nil, fmt.Errorf("systemctl list-units: %w", err)
	}
	var res []string
	for _, l := range strings.Split(string(out), "\n") {
		if f := strings.Fields(l); len(f) > 0 && strings.HasSuffix(f[0], ".service") {
			res = append(res, f[0])
		}
	}
	sort.Strings(res)
	return res, nil
}

// UpgradePlan — что обновит packages.upgrade: по симуляции apt-get, только из кэша.
type UpgradePlan struct {
	Packages []*agentv1.PackageUpdate
}

// PlanUpgrade — список пакетов для scope (SECURITY — только кандидаты из источников безопасности).
func PlanUpgrade(ctx context.Context, sys *System, scope agentv1.UpgradeScope) (*UpgradePlan, error) {
	if scope != agentv1.UpgradeScope_UPGRADE_SCOPE_SECURITY && scope != agentv1.UpgradeScope_UPGRADE_SCOPE_ALL {
		return nil, errors.New("scope")
	}
	list, err := ListUpdates(ctx, sys)
	if err != nil {
		return nil, err
	}
	p := &UpgradePlan{}
	for _, u := range list.GetPackages() {
		if scope == agentv1.UpgradeScope_UPGRADE_SCOPE_ALL || u.GetSecurity() {
			p.Packages = append(p.Packages, u)
		}
	}
	return p, nil
}

// aptArgs — без вопросов, файлы настроек пользователя сохраняются (confdef/confold).
var aptArgs = []string{"-y", "-q", "-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold"}

// Upgrade обновляет списки и пакеты. SECURITY — только пакеты плана (--only-upgrade: новых не ставит).
func Upgrade(ctx context.Context, sys *System, scope agentv1.UpgradeScope) (int, error) {
	if out, err := sys.run(ctx, "apt-get", "update", "-q"); err != nil {
		return 0, fmt.Errorf("apt-get update: %v %s", err, tail(out))
	}
	plan, err := PlanUpgrade(ctx, sys, scope)
	if err != nil {
		return 0, err
	}
	if len(plan.Packages) == 0 {
		return 0, nil
	}
	var args []string
	if scope == agentv1.UpgradeScope_UPGRADE_SCOPE_ALL {
		args = append(append([]string{}, aptArgs...), "dist-upgrade")
	} else {
		args = append(append([]string{}, aptArgs...), "install", "--only-upgrade", "--")
		for _, p := range plan.Packages {
			args = append(args, p.GetName())
		}
	}
	if out, err := sys.run(ctx, "apt-get", args...); err != nil {
		return 0, fmt.Errorf("apt-get: %v %s", err, tail(out))
	}
	return len(plan.Packages), nil
}

// VerifyUpgrade — менеджер пакетов цел (dpkg --audit пуст) и все службы, что работали до обновления, работают.
func VerifyUpgrade(ctx context.Context, sys *System, before []string) error {
	if out, err := sys.run(ctx, "dpkg", "--audit"); err != nil || strings.TrimSpace(string(out)) != "" {
		return fmt.Errorf("dpkg --audit: %v %s", err, tail(out))
	}
	// Службы перезапускаются после обновления не сразу: ждём до 30 с.
	var stopped []string
	for i := 0; i < 30; i++ {
		after, err := RunningServices(ctx, sys)
		if err != nil {
			return err
		}
		now := map[string]bool{}
		for _, s := range after {
			now[s] = true
		}
		stopped = stopped[:0]
		for _, s := range before {
			if !now[s] {
				stopped = append(stopped, s)
			}
		}
		if len(stopped) == 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(upgradePoll):
		}
	}
	return fmt.Errorf("после обновления не работают: %s", strings.Join(stopped, ", "))
}

// upgradePoll — шаг ожидания служб (переменная: тест сокращает).
var upgradePoll = time.Second

// RestartService перезапускает службу и ждёт, что она активна (до 10 с).
func RestartService(ctx context.Context, sys *System, unit string) error {
	if out, err := sys.run(ctx, "systemctl", "restart", "--", unit); err != nil {
		return fmt.Errorf("systemctl restart %s: %v %s", unit, err, tail(out))
	}
	for i := 0; i < 10; i++ {
		if unitActive(ctx, sys, unit) {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(upgradePoll):
		}
	}
	return fmt.Errorf("%s не активна после перезапуска", unit)
}
