// SPDX-License-Identifier: AGPL-3.0-only

package helper

import (
	"context"
	"errors"
	"path/filepath"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/deploy"
	"github.com/NogMeer/trassa-agent/internal/ops"
	"github.com/NogMeer/trassa-agent/internal/rollback"
)

// CodeDeployUnavailable — деплой на этой сборке или сервере не настроен.
const CodeDeployUnavailable = "DEPLOY_UNAVAILABLE"

func (e *Executor) deployHandlers() map[string]handler {
	return map[string]handler{
		ops.TypeDockerEnsure:    {apply: e.applyDockerEnsure},
		ops.TypeProxyEnsure:     {apply: e.applyProxyEnsure},
		ops.TypeProxyRouteApply: {apply: e.applyRouteApply},
		ops.TypeDeployInspect:   {apply: e.applyDeployInspect},
	}
}

func deployCode(err error) string {
	for _, known := range []error{
		deploy.ErrDockerTooOld, deploy.ErrDockerKey, deploy.ErrOSUnsupported, deploy.ErrDockerNotReady, deploy.ErrToolUnknown,
		deploy.ErrChecksum, deploy.ErrRoutesStale, deploy.ErrProxyMissing, deploy.ErrProxyPort, deploy.ErrImageNotPinned,
	} {
		if errors.Is(err, known) {
			return known.Error()
		}
	}
	return CodeApplyFailed
}

func (e *Executor) deployEnv(r *run) (*deploy.Env, *agentv1.OperationResult) {
	if e.Deploy == nil {
		return nil, r.failed(CodeDeployUnavailable, "деплой на этом сервере недоступен")
	}
	return e.Deploy, nil
}

func (e *Executor) applyDockerEnsure(ctx context.Context, r *run) *agentv1.OperationResult {
	env, fail := e.deployEnv(r)
	if fail != nil {
		return fail
	}
	var out *agentv1.DockerEnsureResult
	res := e.runConfigChange(ctx, r, configChange{
		paths: []string{filepath.Join(env.Root, "etc/apt/keyrings/docker.asc"), filepath.Join(env.Root, "etc/apt/sources.list.d/docker.sources"),
			filepath.Join(env.Root, "etc/docker/daemon.json")},
		code: deployCode,
		apply: func() error {
			var err error
			out, err = env.EnsureDocker(ctx, r.body.GetOperationId(), r.body.GetParams().GetDockerEnsure())
			return err
		},
		verify: func() error { return nil },
	})
	if out != nil && res.GetOutcome() == agentv1.OperationOutcome_OPERATION_OUTCOME_SUCCEEDED {
		res.Data = &agentv1.OperationResult_DockerEnsure{DockerEnsure: out}
	}
	return res
}

func (e *Executor) applyProxyEnsure(ctx context.Context, r *run) *agentv1.OperationResult {
	env, fail := e.deployEnv(r)
	if fail != nil {
		return fail
	}
	var out *agentv1.ProxyEnsureResult
	res := e.runConfigChange(ctx, r, configChange{
		paths: env.ProxyPaths(), code: deployCode,
		apply: func() error {
			var err error
			out, err = env.EnsureProxy(ctx, r.body.GetOperationId(), r.body.GetParams().GetProxyEnsure())
			return err
		},
		verify: func() error { return nil },
	})
	if out != nil && res.GetOutcome() == agentv1.OperationOutcome_OPERATION_OUTCOME_SUCCEEDED {
		res.Data = &agentv1.OperationResult_ProxyEnsure{ProxyEnsure: out}
	}
	return res
}

// applyRouteApply — маршруты прокси с точкой отката: откат возвращает состояние и загружает его в Caddy.
func (e *Executor) applyRouteApply(ctx context.Context, r *run) *agentv1.OperationResult {
	env, fail := e.deployEnv(r)
	if fail != nil {
		return fail
	}
	var out *agentv1.ProxyRouteApplyResult
	res := e.runConfigChange(ctx, r, configChange{
		paths: env.ProxyPaths(), code: deployCode,
		state: rollback.State{Commands: [][]string{{filepath.Join(e.Paths.BinDir, "trassa-helper"), "proxy-sync"}}},
		apply: func() error {
			var err error
			out, err = env.ApplyRoutes(ctx, r.body.GetParams().GetProxyRouteApply())
			return err
		},
		verify: func() error { return nil },
	})
	if out != nil && res.GetOutcome() == agentv1.OperationOutcome_OPERATION_OUTCOME_SUCCEEDED {
		res.Data = &agentv1.OperationResult_ProxyRouteApply{ProxyRouteApply: out}
	}
	return res
}

func (e *Executor) applyDeployInspect(ctx context.Context, r *run) *agentv1.OperationResult {
	env, fail := e.deployEnv(r)
	if fail != nil {
		return fail
	}
	out, err := env.Inspect(ctx, r.body.GetParams().GetDeployInspect().GetAppId())
	if err != nil {
		return r.failed(deployCode(err), err.Error())
	}
	res := r.succeeded("")
	res.Data = &agentv1.OperationResult_DeployInspect{DeployInspect: out}
	return res
}
