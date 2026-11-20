// SPDX-License-Identifier: AGPL-3.0-only

package helper

import (
	"context"
	"errors"
	"strings"

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

// applyListUpdates — packages.list_updates: кэш apt без сети.
func (e *Executor) applyListUpdates(ctx context.Context, r *run) *agentv1.OperationResult {
	if e.Security == nil {
		return r.failed(CodeSecurityUnavailable, "проверки безопасности на этой сборке не выполняются")
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
