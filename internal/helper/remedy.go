// SPDX-License-Identifier: AGPL-3.0-only

package helper

import (
	"context"
	"errors"
	"fmt"
	"strings"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/ops"
	"github.com/NogMeer/trassa-agent/internal/remedy"
	"github.com/NogMeer/trassa-agent/internal/rollback"
)

// CodeRemedyUnavailable — исправления E18 на этой сборке не настроены.
const CodeRemedyUnavailable = "REMEDY_UNAVAILABLE"

func (e *Executor) remedyHandlers() map[string]handler {
	return map[string]handler{
		ops.TypeServiceRestart: {apply: e.applyService(false), dry: e.dryService(false)},
		ops.TypeServiceStart:   {apply: e.applyService(true), dry: e.dryService(true)},
		ops.TypeDiskCleanup:    {apply: e.applyCleanup(false), dry: e.applyCleanup(true)},
		ops.TypeCertRenew:      {apply: e.applyCertRenew, preview: e.previewCertRenew},
	}
}

func remedyCode(err error) string {
	for _, known := range remedy.Codes {
		if errors.Is(err, known) {
			return known.Error()
		}
	}
	return CodeApplyFailed
}

func (e *Executor) remedyEnv(r *run) (*remedy.Env, *agentv1.OperationResult) {
	if e.Remedy == nil {
		return nil, r.failed(CodeRemedyUnavailable, "исправления на этом сервере недоступны")
	}
	return e.Remedy, nil
}

func serviceParams(r *run, start bool) *agentv1.ServiceRestartParams {
	if start {
		return r.body.GetParams().GetServiceStart()
	}
	return r.body.GetParams().GetServiceRestart()
}

func target(p *agentv1.ServiceRestartParams) string {
	if p.GetKind() == agentv1.ServiceTargetKind_SERVICE_TARGET_KIND_CONTAINER {
		return "контейнер " + p.GetContainer()
	}
	return p.GetUnit()
}

// applyService — service.restart (E10) и service.start (E18): итог — работает 60 секунд подряд тем же процессом.
func (e *Executor) applyService(start bool) func(context.Context, *run) *agentv1.OperationResult {
	return func(ctx context.Context, r *run) *agentv1.OperationResult {
		env, fail := e.remedyEnv(r)
		if fail != nil {
			return fail
		}
		p := serviceParams(r, start)
		out, err := env.Service(ctx, p, start)
		res := r.succeeded(target(p) + " работает")
		if err != nil {
			res = r.failed(remedyCode(err), err.Error())
		}
		if out != nil {
			res.Data = &agentv1.OperationResult_ServiceRestart{ServiceRestart: out}
		}
		return res
	}
}

// dryService — предпросмотр: состояние цели сейчас, без действий.
func (e *Executor) dryService(start bool) func(context.Context, *run) *agentv1.OperationResult {
	return func(ctx context.Context, r *run) *agentv1.OperationResult {
		env, fail := e.remedyEnv(r)
		if fail != nil {
			return fail
		}
		p := serviceParams(r, start)
		out, err := env.ServiceState(ctx, p)
		if err != nil {
			return r.failed(remedyCode(err), err.Error())
		}
		verb := "Перезапуск"
		if start {
			verb = "Запуск"
		}
		res := r.succeeded("")
		res.Preview = &agentv1.Preview{Summary: fmt.Sprintf("%s: %s (сейчас %s, перезапусков %d)", verb, target(p), out.GetState(), out.GetRestarts()),
			Notes: []string{"Проверка: цель работает 60 секунд подряд"}}
		res.Data = &agentv1.OperationResult_ServiceRestart{ServiceRestart: out}
		return res
	}
}

func (e *Executor) applyCleanup(dry bool) func(context.Context, *run) *agentv1.OperationResult {
	return func(ctx context.Context, r *run) *agentv1.OperationResult {
		env, fail := e.remedyEnv(r)
		if fail != nil {
			return fail
		}
		out, err := env.Cleanup(ctx, r.body.GetParams().GetDiskCleanup(), dry)
		var total uint64
		var notes []string
		for _, f := range out.GetFreed() {
			total += f.GetBytes()
			if f.GetError() != "" {
				notes = append(notes, strings.TrimPrefix(f.GetCategory().String(), "DISK_CLEANUP_CATEGORY_")+": "+f.GetError())
			}
		}
		var res *agentv1.OperationResult
		switch {
		case err != nil:
			code := CodeApplyFailed
			for _, n := range notes {
				if strings.Contains(n, remedy.ErrPackageBusy.Error()) && len(out.GetFreed()) == 1 {
					code = remedy.ErrPackageBusy.Error()
				}
			}
			res = r.failed(code, err.Error()+": "+strings.Join(notes, "; "))
		case dry:
			res = r.succeeded("")
			res.Preview = &agentv1.Preview{Summary: fmt.Sprintf("Освободится до %d байт", total), Notes: append(notes,
				"Тома Docker, образы приложений Trassa и файлы пользователя не удаляются")}
		default:
			res = r.succeeded(fmt.Sprintf("Освобождено %d байт", total))
			for _, n := range notes {
				r.log(agentv1.LogStream_LOG_STREAM_STDERR, n)
			}
		}
		res.Data = &agentv1.OperationResult_DiskCleanup{DiskCleanup: out}
		return res
	}
}

func (e *Executor) previewCertRenew(_ context.Context, r *run) (*agentv1.Preview, *agentv1.OperationResult) {
	env, fail := e.remedyEnv(r)
	if fail != nil {
		return nil, fail
	}
	name := r.body.GetParams().GetCertRenew().GetDomain()
	conf, _, err := env.CertLineage(name)
	if err != nil {
		return nil, r.failed(remedyCode(err), err.Error())
	}
	return &agentv1.Preview{Summary: "Продление сертификата certbot " + name, Services: nil,
		Files: []*agentv1.FileChange{{Path: conf, Kind: agentv1.FileChangeKind_FILE_CHANGE_KIND_MODIFY}},
		Notes: []string{"certbot renew --cert-name " + name + " --non-interactive; хуки — из настроек certbot сервера"}}, nil
}

// applyCertRenew — cert.renew с точкой отката CONFIG: файл продления и прежние ссылки live/<имя>/*.
func (e *Executor) applyCertRenew(ctx context.Context, r *run) *agentv1.OperationResult {
	env, fail := e.remedyEnv(r)
	if fail != nil {
		return fail
	}
	name := r.body.GetParams().GetCertRenew().GetDomain()
	conf, relink, err := env.CertLineage(name)
	if err != nil {
		return r.failed(remedyCode(err), err.Error())
	}
	var out *agentv1.CertRenewResult
	res := e.runConfigChange(ctx, r, configChange{
		paths: []string{conf}, code: remedyCode, state: rollback.State{Commands: relink},
		apply: func() error {
			var err error
			out, err = env.RenewCert(ctx, name)
			return err
		},
		verify: func() error { return nil },
	})
	if out != nil {
		res.Data = &agentv1.OperationResult_CertRenew{CertRenew: out}
	}
	return res
}
