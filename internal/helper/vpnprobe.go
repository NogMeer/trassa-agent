// SPDX-License-Identifier: AGPL-3.0-only

package helper

import (
	"context"
	"errors"
	"fmt"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/ops"
	secretkey "github.com/NogMeer/trassa-agent/internal/sealed"
	"github.com/NogMeer/trassa-agent/internal/vpnprobe"
)

// CodeVpnProbeUnavailable — точка замера на этой сборке не настроена.
const CodeVpnProbeUnavailable = "VPN_PROBE_UNAVAILABLE"

// FieldVpnProbeConfig — поле секрета тестового доступа в info HPKE (e25-agent-scope.md).
const FieldVpnProbeConfig = "vpn_probe_config"

func (e *Executor) vpnHandlers() map[string]handler {
	return map[string]handler{
		ops.TypeVpnProbeEnsure: {preview: e.previewVpnEnsure, apply: e.applyVpnEnsure},
		ops.TypeVpnProbeRun:    {apply: e.applyVpnRun},
	}
}

func vpnCode(err error) string {
	for _, known := range vpnprobe.Codes {
		if errors.Is(err, known) {
			return known.Error()
		}
	}
	return CodeApplyFailed
}

func (e *Executor) previewVpnEnsure(_ context.Context, r *run) (*agentv1.Preview, *agentv1.OperationResult) {
	if e.VpnProbe == nil {
		return nil, r.failed(CodeVpnProbeUnavailable, "точка замера на этом сервере недоступна")
	}
	p := r.body.GetParams().GetVpnProbeEnsure()
	plan, err := e.VpnProbe.EnsurePlan(p)
	if err != nil {
		return nil, r.failed(vpnCode(err), err.Error())
	}
	was := "ставится впервые"
	if plan.GetPreviousVersion() != "" {
		was = "сейчас " + plan.GetPreviousVersion()
	}
	return &agentv1.Preview{Summary: fmt.Sprintf("Движок замера %s %s в %s (%s); запуск — от trassa в песочнице",
		p.GetEngine(), p.GetVersion(), e.VpnProbe.Dir, was)}, nil
}

// applyVpnEnsure — установка с точкой отката: engines.json; прежняя версия остаётся на диске, лишние удаляются.
func (e *Executor) applyVpnEnsure(ctx context.Context, r *run) *agentv1.OperationResult {
	if e.VpnProbe == nil {
		return r.failed(CodeVpnProbeUnavailable, "точка замера на этом сервере недоступна")
	}
	p := r.body.GetParams().GetVpnProbeEnsure()
	var out *agentv1.VpnProbeEnsureResult
	res := e.runConfigChange(ctx, r, configChange{
		paths: []string{e.VpnProbe.StatePath()}, code: vpnCode,
		apply: func() error {
			var err error
			out, err = e.VpnProbe.Ensure(ctx, StageDir(e.Paths, r.body.GetOperationId()), p)
			return err
		},
		verify: func() error {
			_, _, err := e.VpnProbe.Installed(p.GetEngine())
			return err
		},
	})
	if out != nil && res.GetOutcome() == agentv1.OperationOutcome_OPERATION_OUTCOME_SUCCEEDED {
		if err := e.VpnProbe.Prune(p.GetEngine(), out.GetVersion(), out.GetPreviousVersion()); err != nil {
			r.system("Старые версии движка не удалены: %v", err)
		}
		res.Data = &agentv1.OperationResult_VpnProbeEnsure{VpnProbeEnsure: out}
	}
	return res
}

// applyVpnRun — замер: доступ расшифровывает помощник (ключ только у него), привязка к серверу, операции, типу,
// цепочке и полю; открытый текст живёт до конца замера и в журнал операции не попадает.
func (e *Executor) applyVpnRun(ctx context.Context, r *run) *agentv1.OperationResult {
	if e.VpnProbe == nil {
		return r.failed(CodeVpnProbeUnavailable, "точка замера на этом сервере недоступна")
	}
	if e.Secrets == nil {
		return r.failed(CodeVpnProbeUnavailable, "нет ключа секретов помощника")
	}
	p := r.body.GetParams().GetVpnProbeRun()
	s := p.GetConfig()
	info := secretkey.Info(r.body.GetServerId(), s.GetKid(), r.body.GetOperationId(), r.body.GetType(), p.GetRouteId(), FieldVpnProbeConfig)
	access, err := e.Secrets.Open(s, info)
	if err != nil {
		return r.failed(vpnprobe.ErrConfigInvalid.Error(), "тестовый доступ не расшифровался: "+err.Error())
	}
	defer clear(access)
	out, err := e.VpnProbe.Probe(ctx, p, access)
	if err != nil {
		return r.failed(vpnCode(err), err.Error())
	}
	res := r.succeeded("Замер: " + out.GetStatus().String())
	res.Data = &agentv1.OperationResult_VpnProbeRun{VpnProbeRun: out}
	return res
}
