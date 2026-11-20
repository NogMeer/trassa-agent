// SPDX-License-Identifier: AGPL-3.0-only

package helper

import (
	"context"
	"errors"
	"path/filepath"
	"time"

	"google.golang.org/protobuf/proto"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/deploy"
	"github.com/NogMeer/trassa-agent/internal/helperrpc"
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
		ops.TypeDeployRelease:   {apply: e.applyDeployRelease},
		ops.TypeDeployRollback:  {apply: e.applyDeployRollback},
		ops.TypeDeployControl:   {apply: e.applyDeployControl},
		ops.TypeDeployRemove:    {apply: e.applyDeployRemove},
		ops.TypeDeployPrune:     {apply: e.applyDeployPrune},
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

// deployRunEnv — окружение долгой операции деплоя: маршруты пишутся под общей блокировкой помощника.
func (e *Executor) deployRunEnv(r *run) (*deploy.Env, *agentv1.OperationResult) {
	env, fail := e.deployEnv(r)
	if fail != nil {
		return nil, fail
	}
	cp := *env
	cp.RouteLock = e.Lock.Lock
	return &cp, nil
}

// deployProgress — кадр хода релиза (OperationProgress.deploy) на каждый шаг; попытки проверки — не чаще progressEvery.
func (r *run) deployProgress(release string) deploy.Step {
	var last time.Time
	var lastStep agentv1.DeployStep
	return func(step agentv1.DeployStep, attempt uint32) {
		now := time.Now()
		if step == lastStep && now.Sub(last) < progressEvery {
			return
		}
		last, lastStep = now, step
		r.seq++
		raw, _ := proto.Marshal(&agentv1.OperationProgress{
			OperationId: r.body.GetOperationId(), Seq: r.seq, Phase: r.phase,
			Deploy: &agentv1.DeployProgress{ReleaseId: release, Step: step, Attempt: attempt},
		})
		_ = r.send(helperrpc.Response{Kind: helperrpc.KindProgress, Progress: raw})
	}
}

func (e *Executor) runRelease(ctx context.Context, r *run, p *agentv1.DeployReleaseParams) *agentv1.OperationResult {
	env, fail := e.deployRunEnv(r)
	if fail != nil {
		return fail
	}
	if e.Secrets == nil && (len(p.GetEnv()) > 0 || p.GetPullFrom() != nil) {
		return r.failed(CodeDeployUnavailable, "нет ключа секретов помощника")
	}
	ctx, cancel := context.WithDeadline(ctx, time.UnixMilli(p.GetDeadlineMs()))
	defer cancel()
	job := deploy.ReleaseJob{
		Params: p, Open: &deploy.Opener{Key: e.Secrets, Body: r.body, App: p.GetAppId()},
		Step: r.deployProgress(p.GetReleaseId()),
		Log:  func(s string) { r.log(agentv1.LogStream_LOG_STREAM_STDERR, s) },
	}
	out, rolledBack, err := env.Release(ctx, job)
	var res *agentv1.OperationResult
	switch {
	case err == nil:
		res = r.succeeded("")
	case rolledBack:
		res = r.rolledBack(releaseCode(ctx, err), err.Error())
	default:
		res = r.failed(releaseCode(ctx, err), err.Error())
	}
	if out != nil {
		res.Data = &agentv1.OperationResult_DeployRelease{DeployRelease: out}
	}
	return res
}

// releaseCode — код итога релиза; срок операции — DEPLOY_TIMEOUT.
func releaseCode(ctx context.Context, err error) string {
	for _, known := range []error{
		deploy.ErrRegistry, deploy.ErrRegistryAuth, deploy.ErrImageGone, deploy.ErrPreDeploy, deploy.ErrHealthcheck,
		deploy.ErrNoFreePort, deploy.ErrReleaseTimeout, deploy.ErrComposeDenied, deploy.ErrAppMissing,
	} {
		if errors.Is(err, known) {
			return known.Error()
		}
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return deploy.ErrReleaseTimeout.Error()
	}
	return deployCode(err)
}

func (e *Executor) applyDeployRelease(ctx context.Context, r *run) *agentv1.OperationResult {
	return e.runRelease(ctx, r, r.body.GetParams().GetDeployRelease())
}

func (e *Executor) applyDeployRollback(ctx context.Context, r *run) *agentv1.OperationResult {
	return e.runRelease(ctx, r, r.body.GetParams().GetDeployRollback().GetRelease())
}

func (e *Executor) applyDeployControl(ctx context.Context, r *run) *agentv1.OperationResult {
	env, fail := e.deployRunEnv(r)
	if fail != nil {
		return fail
	}
	p := r.body.GetParams().GetDeployControl()
	ctx, cancel := context.WithDeadline(ctx, time.UnixMilli(p.GetDeadlineMs()))
	defer cancel()
	out, err := env.Control(ctx, p)
	if err != nil {
		return r.failed(releaseCode(ctx, err), err.Error())
	}
	res := r.succeeded("")
	res.Data = &agentv1.OperationResult_DeployInspect{DeployInspect: out}
	return res
}

func (e *Executor) applyDeployRemove(ctx context.Context, r *run) *agentv1.OperationResult {
	env, fail := e.deployRunEnv(r)
	if fail != nil {
		return fail
	}
	out, err := env.Remove(ctx, r.body.GetParams().GetDeployRemove())
	res := r.succeeded("")
	if err != nil {
		res = r.failed(releaseCode(ctx, err), err.Error())
	}
	if out != nil {
		res.Data = &agentv1.OperationResult_DeployRemove{DeployRemove: out}
	}
	return res
}

func (e *Executor) applyDeployPrune(ctx context.Context, r *run) *agentv1.OperationResult {
	env, fail := e.deployRunEnv(r)
	if fail != nil {
		return fail
	}
	out, err := env.PruneImages(ctx, r.body.GetParams().GetDeployImagesPrune())
	if err != nil {
		return r.failed(deployCode(err), err.Error())
	}
	res := r.succeeded("")
	res.Data = &agentv1.OperationResult_DeployImagesPrune{DeployImagesPrune: out}
	return res
}
