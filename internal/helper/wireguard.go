// SPDX-License-Identifier: AGPL-3.0-only

package helper

import (
	"context"
	"errors"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/ops"
	"github.com/NogMeer/trassa-agent/internal/wireguard"
)

// CodeWireguardUnavailable — приватная сеть на этой сборке не работает.
const CodeWireguardUnavailable = "WG_UNAVAILABLE"

func wgFail(r *run, err error) *agentv1.OperationResult {
	var pe *wireguard.ErrPrecondition
	if errors.As(err, &pe) {
		return r.failed(pe.Code, pe.Msg)
	}
	return r.failed(CodeApplyFailed, err.Error())
}

func (e *Executor) applyWgInspect(ctx context.Context, r *run) *agentv1.OperationResult {
	if e.WireGuard == nil {
		return r.failed(CodeWireguardUnavailable, "приватная сеть на этой сборке не работает")
	}
	res := r.succeeded("")
	res.Data = &agentv1.OperationResult_WireguardInspect{WireguardInspect: e.WireGuard.Inspect(ctx, r.body.GetParams().GetWireguardInspect())}
	return res
}

func (e *Executor) applyWgKeygen(_ context.Context, r *run) *agentv1.OperationResult {
	if e.WireGuard == nil {
		return r.failed(CodeWireguardUnavailable, "приватная сеть на этой сборке не работает")
	}
	p := r.body.GetParams().GetWireguardKeygen()
	pub, next, err := e.WireGuard.Store.Keygen(p.GetIfaceName(), p.GetRotate())
	if err != nil {
		return r.failed(CodeApplyFailed, err.Error())
	}
	res := r.succeeded("")
	res.Data = &agentv1.OperationResult_WireguardKeygen{WireguardKeygen: &agentv1.WireguardKeygenResult{PublicKey: pub, Next: next}}
	return res
}

func (e *Executor) wgPlan(ctx context.Context, r *run) (*wireguard.Plan, *agentv1.OperationResult) {
	if e.WireGuard == nil {
		return nil, r.failed(CodeWireguardUnavailable, "приватная сеть на этой сборке не работает")
	}
	var p *wireguard.Plan
	var err error
	if r.body.GetType() == ops.TypeWireguardApply {
		p, err = e.WireGuard.PlanApply(ctx, r.body.GetParams().GetWireguardApply())
	} else {
		p, err = e.WireGuard.PlanRemove(ctx, r.body.GetParams().GetWireguardRemove())
	}
	if err != nil {
		return nil, wgFail(r, err)
	}
	return p, nil
}

func (e *Executor) previewWg(ctx context.Context, r *run) (*agentv1.Preview, *agentv1.OperationResult) {
	p, fail := e.wgPlan(ctx, r)
	if fail != nil {
		return nil, fail
	}
	return &agentv1.Preview{Summary: p.Summary, Files: p.Changes, Notes: p.Notes}, nil
}

// applyWg — wireguard.apply и wireguard.remove с автооткатом: точка отката хранит файлы состояния, имён и
// пересылки; возврат приводит ядро к ним командой wireguard-sync.
func (e *Executor) applyWg(ctx context.Context, r *run) *agentv1.OperationResult {
	p, fail := e.wgPlan(ctx, r)
	if fail != nil {
		return fail
	}
	res := e.runConfigChange(ctx, r, configChange{
		paths: p.Paths, state: p.State,
		apply:  func() error { return p.Apply(ctx) },
		verify: func() error { return p.Verify(ctx) },
	})
	if r.body.GetType() == ops.TypeWireguardApply && res.GetOutcome() == agentv1.OperationOutcome_OPERATION_OUTCOME_AWAITING_CONFIRM {
		if d, err := e.WireGuard.Store.Load(r.body.GetParams().GetWireguardApply().GetIfaceName()); err == nil && d != nil {
			res.Data = &agentv1.OperationResult_WireguardApply{WireguardApply: &agentv1.WireguardApplyResult{ConfigHash: d.Hash()}}
		}
	}
	return res
}
