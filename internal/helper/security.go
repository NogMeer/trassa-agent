// SPDX-License-Identifier: AGPL-3.0-only

package helper

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/ops"
	"github.com/NogMeer/trassa-agent/internal/security"
)

// CodeSecurityUnavailable — проверки на этой сборке не выполняются.
const CodeSecurityUnavailable = "SECURITY_UNAVAILABLE"

// CodePackagesFailed — менеджер пакетов не ответил.
const CodePackagesFailed = "PACKAGES_FAILED"

// applySecurityScan — security.scan: проверки только чтением из зашитого списка (параметры уже сверены с ним).
func (e *Executor) applySecurityScan(ctx context.Context, r *run) *agentv1.OperationResult {
	if e.Security == nil {
		return r.failed(CodeSecurityUnavailable, "проверки безопасности на этой сборке не выполняются")
	}
	res := r.succeeded("")
	res.Data = &agentv1.OperationResult_SecurityScan{SecurityScan: security.Run(ctx, e.Security, r.body.GetParams().GetSecurityScan())}
	return res
}

// Коды итога исправлений.
const (
	CodeFixSubject      = "FIX_SUBJECT_NOT_FOUND"
	CodeFixPrecondition = "FIX_PRECONDITION"
)

func fixCode(t string) string { return strings.TrimPrefix(t, ops.FixPrefix) }

func (e *Executor) planFix(ctx context.Context, r *run) (*security.FixPlan, *agentv1.OperationResult) {
	if e.Security == nil {
		return nil, r.failed(CodeSecurityUnavailable, "проверки безопасности на этой сборке не выполняются")
	}
	p, err := security.PlanFix(ctx, e.Security, fixCode(r.body.GetType()), r.body.GetParams().GetSecurityFix().GetSubjects())
	switch {
	case errors.Is(err, security.ErrSubject):
		return nil, r.failed(CodeFixSubject, err.Error())
	case errors.Is(err, security.ErrPrecondition):
		return nil, r.failed(CodeFixPrecondition, err.Error())
	case err != nil:
		return nil, r.failed(CodeApplyFailed, err.Error())
	}
	return p, nil
}

func (e *Executor) previewFix(ctx context.Context, r *run) (*agentv1.Preview, *agentv1.OperationResult) {
	p, fail := e.planFix(ctx, r)
	if fail != nil {
		return nil, fail
	}
	return &agentv1.Preview{Summary: p.Summary, Files: p.Changes, Services: p.Services, Notes: p.Notes}, nil
}

// applyFix — security.fix.<код>: план по свежей проверке, точка отката (файлы и состояние), применение,
// повторная проверка; провал — автоматический возврат (runConfigChange).
func (e *Executor) applyFix(ctx context.Context, r *run) *agentv1.OperationResult {
	p, fail := e.planFix(ctx, r)
	if fail != nil {
		return fail
	}
	r.system("%s", p.Summary)
	return e.runConfigChange(ctx, r, configChange{
		paths: p.Paths, services: p.Services, state: p.State,
		apply:  func() error { return p.Apply(ctx) },
		verify: func() error { return p.Verify(ctx) },
	})
}

func (e *Executor) planSSH(ctx context.Context, r *run) (*security.FixPlan, *agentv1.OperationResult) {
	if e.Security == nil {
		return nil, r.failed(CodeSecurityUnavailable, "проверки безопасности на этой сборке не выполняются")
	}
	p, err := security.PlanSSHHarden(ctx, e.Security, r.body.GetParams().GetSshHarden())
	switch {
	case errors.Is(err, security.ErrPrecondition):
		return nil, r.failed(CodeFixPrecondition, err.Error())
	case err != nil:
		return nil, r.failed(CodeApplyFailed, err.Error())
	}
	return p, nil
}

func (e *Executor) previewSSH(ctx context.Context, r *run) (*agentv1.Preview, *agentv1.OperationResult) {
	p, fail := e.planSSH(ctx, r)
	if fail != nil {
		return nil, fail
	}
	return &agentv1.Preview{Summary: p.Summary, Files: p.Changes, Services: p.Services, Notes: p.Notes}, nil
}

// applySSH — ssh.harden с автооткатом: таймер заводится до записи файла, подтверждение приходит по новому
// соединению агента (как у test.config_write).
func (e *Executor) applySSH(ctx context.Context, r *run) *agentv1.OperationResult {
	p, fail := e.planSSH(ctx, r)
	if fail != nil {
		return fail
	}
	return e.runConfigChange(ctx, r, configChange{
		paths: p.Paths, services: p.Services, state: p.State,
		apply:  func() error { return p.Apply(ctx) },
		verify: func() error { return p.Verify(ctx) },
	})
}

// Коды итога firewall.
const (
	CodeFirewallWouldLockSSH = "FIREWALL_WOULD_LOCK_SSH"
	CodeFirewallHashMismatch = "FIREWALL_HASH_MISMATCH"
	CodeFirewallPlanFailed   = "FIREWALL_PLAN_FAILED"
)

func firewallFail(r *run, err error) *agentv1.OperationResult {
	switch {
	case errors.Is(err, security.ErrWouldLockSSH):
		return r.failed(CodeFirewallWouldLockSSH, err.Error())
	case errors.Is(err, security.ErrRulesetHash):
		return r.failed(CodeFirewallHashMismatch, err.Error())
	case errors.Is(err, security.ErrPrecondition):
		return r.failed(CodeFixPrecondition, err.Error())
	}
	return r.failed(CodeFirewallPlanFailed, err.Error())
}

func (e *Executor) applyFirewallPlan(ctx context.Context, r *run) *agentv1.OperationResult {
	if e.Security == nil {
		return r.failed(CodeSecurityUnavailable, "проверки безопасности на этой сборке не выполняются")
	}
	out, err := security.FirewallPlan(ctx, e.Security, r.body.GetParams().GetFirewallPlan())
	if err != nil {
		return firewallFail(r, err)
	}
	res := r.succeeded("")
	res.Data = &agentv1.OperationResult_FirewallPlan{FirewallPlan: out}
	return res
}

func (e *Executor) planFirewallApply(ctx context.Context, r *run) (*security.FixPlan, *agentv1.OperationResult) {
	if e.Security == nil {
		return nil, r.failed(CodeSecurityUnavailable, "проверки безопасности на этой сборке не выполняются")
	}
	p, err := security.PlanFirewallApply(ctx, e.Security, r.body.GetParams().GetFirewallApply())
	if err != nil {
		return nil, firewallFail(r, err)
	}
	return p, nil
}

func (e *Executor) previewFirewallApply(ctx context.Context, r *run) (*agentv1.Preview, *agentv1.OperationResult) {
	p, fail := e.planFirewallApply(ctx, r)
	if fail != nil {
		return nil, fail
	}
	return &agentv1.Preview{Summary: p.Summary, Files: p.Changes, Notes: p.Notes}, nil
}

// applyFirewallApply — firewall.apply с автооткатом (R14): таймер заводится до применения.
func (e *Executor) applyFirewallApply(ctx context.Context, r *run) *agentv1.OperationResult {
	p, fail := e.planFirewallApply(ctx, r)
	if fail != nil {
		return fail
	}
	return e.runConfigChange(ctx, r, configChange{
		paths: p.Paths, services: p.Services, state: p.State,
		apply:  func() error { return p.Apply(ctx) },
		verify: func() error { return p.Verify(ctx) },
	})
}

// Коды итога обслуживания.
const (
	// CodePackageManagerBusy — apt/dpkg занят чужим процессом (unattended-upgrades, ручной apt): операция не
	// начиналась; в сообщении — файл блокировки и процесс-держатель.
	CodePackageManagerBusy = "PACKAGE_MANAGER_BUSY"
	CodeUpgradeFailed      = "UPGRADE_FAILED"
	CodeRebootFailed       = "REBOOT_FAILED"
	CodeRestartFailed      = "SERVICE_RESTART_FAILED"
)

// aptBusy — итог PACKAGE_MANAGER_BUSY, если apt/dpkg занят; nil — свободен.
func (e *Executor) aptBusy(r *run) *agentv1.OperationResult {
	h, err := security.PackageManagerBusy(e.Security)
	if err != nil {
		return r.failed(CodePackagesFailed, "блокировки менеджера пакетов не проверены: "+err.Error())
	}
	if h != nil {
		return r.failed(CodePackageManagerBusy, "Менеджер пакетов "+h.String()+"; повторите, когда он закончит")
	}
	return nil
}

func (e *Executor) previewUpgrade(ctx context.Context, r *run) (*agentv1.Preview, *agentv1.OperationResult) {
	if e.Security == nil {
		return nil, r.failed(CodeSecurityUnavailable, "проверки безопасности на этой сборке не выполняются")
	}
	if busy := e.aptBusy(r); busy != nil {
		return nil, busy
	}
	plan, err := security.PlanUpgrade(ctx, e.Security, r.body.GetParams().GetPackagesUpgrade().GetScope())
	if err != nil {
		return nil, r.failed(CodePackagesFailed, err.Error())
	}
	pv := &agentv1.Preview{Summary: fmt.Sprintf("Обновить пакетов: %d (по кэшу apt; перед обновлением списки обновятся)", len(plan.Packages))}
	for _, p := range plan.Packages {
		pv.Notes = append(pv.Notes, fmt.Sprintf("%s %s → %s", p.GetName(), p.GetCurrent(), p.GetCandidate()))
	}
	if running, err := security.RunningServices(ctx, e.Security); err == nil {
		pv.Services = running
	}
	if list, err := security.ListUpdates(ctx, e.Security); err == nil && list.GetRebootRequired() {
		pv.Notes = append(pv.Notes, "Система уже ждёт перезагрузки")
	}
	return pv, nil
}

// applyUpgrade — packages.upgrade: службы, что работали до обновления, должны работать после.
func (e *Executor) applyUpgrade(ctx context.Context, r *run) *agentv1.OperationResult {
	if e.Security == nil {
		return r.failed(CodeSecurityUnavailable, "проверки безопасности на этой сборке не выполняются")
	}
	if busy := e.aptBusy(r); busy != nil {
		return busy
	}
	before, err := security.RunningServices(ctx, e.Security)
	if err != nil {
		return r.failed(CodeUpgradeFailed, err.Error())
	}
	r.phase = agentv1.OperationPhase_OPERATION_PHASE_APPLY
	n, err := security.Upgrade(ctx, e.Security, r.body.GetParams().GetPackagesUpgrade().GetScope())
	if err != nil {
		return r.failed(CodeUpgradeFailed, err.Error())
	}
	r.system("Обновлено пакетов: %d", n)
	r.phase = agentv1.OperationPhase_OPERATION_PHASE_VERIFY
	if err := security.VerifyUpgrade(ctx, e.Security, before); err != nil {
		return r.failed(CodeVerifyFailed, err.Error())
	}
	msg := fmt.Sprintf("Обновлено пакетов: %d", n)
	if list, err := security.ListUpdates(ctx, e.Security); err == nil && list.GetRebootRequired() {
		msg += "; нужна перезагрузка"
	}
	return r.succeeded(msg)
}

func (e *Executor) previewReboot(ctx context.Context, r *run) (*agentv1.Preview, *agentv1.OperationResult) {
	pv := &agentv1.Preview{Summary: fmt.Sprintf("Перезагрузка через %d с", rebootDelay(r))}
	if e.Security != nil {
		if running, err := security.RunningServices(ctx, e.Security); err == nil {
			pv.Services = running
		}
		if inv, _ := e.System.Inventory(ctx, []agentv1.InventoryKind{agentv1.InventoryKind_INVENTORY_KIND_CONTAINERS}); inv != nil {
			for _, c := range inv.GetContainers() {
				pv.Notes = append(pv.Notes, "Контейнер "+c.GetName()+" ("+c.GetState()+")")
			}
		}
	}
	return pv, nil
}

// rebootDelay — не раньше чем через 5 с: итог операции успевает уйти шлюзу.
func rebootDelay(r *run) uint32 {
	return max(r.body.GetParams().GetSystemReboot().GetDelaySeconds(), 5)
}

// applyReboot — перезагрузка таймером systemd; возвращение агента на связь проверяет панель (10 минут).
func (e *Executor) applyReboot(ctx context.Context, r *run) *agentv1.OperationResult {
	d := time.Duration(rebootDelay(r)) * time.Second
	if err := e.Services.Schedule(ctx, "trassa-reboot", d, "/usr/bin/systemctl", "reboot"); err != nil {
		return r.failed(CodeRebootFailed, err.Error())
	}
	return r.succeeded(fmt.Sprintf("Перезагрузка через %d с", int(d.Seconds())))
}

// CodeBaselineUnknown — отпечатка нет среди ожидающих объектов детектора.
const CodeBaselineUnknown = "BASELINE_UNKNOWN"

// applyBaselineAccept — «Это сделал я»: объекты переходят в базовый список, события по ним прекращаются.
func (e *Executor) applyBaselineAccept(_ context.Context, r *run) *agentv1.OperationResult {
	if e.Security == nil || e.Security.Detector == nil {
		return r.failed(CodeSecurityUnavailable, "детектор на этой сборке не работает")
	}
	digest, err := e.Security.Detector.Accept(r.body.GetParams().GetSecurityBaselineAccept().GetFingerprints())
	if errors.Is(err, security.ErrUnknownFingerprint) {
		return r.failed(CodeBaselineUnknown, err.Error())
	}
	if err != nil {
		return r.failed(CodeInternal, err.Error())
	}
	return r.succeeded("baseline_digest " + digest)
}

// applyListUpdates — packages.list_updates: кэш apt без сети.
func (e *Executor) applyListUpdates(ctx context.Context, r *run) *agentv1.OperationResult {
	if e.Security == nil {
		return r.failed(CodeSecurityUnavailable, "проверки безопасности на этой сборке не выполняются")
	}
	if busy := e.aptBusy(r); busy != nil {
		return busy
	}
	out, err := security.ListUpdates(ctx, e.Security)
	if err != nil {
		e.log().Warn("helper: packages.list_updates", "err", err)
		return r.failed(CodePackagesFailed, "список обновлений не получен")
	}
	res := r.succeeded("")
	res.Data = &agentv1.OperationResult_PackagesListUpdates{PackagesListUpdates: out}
	return res
}
