// SPDX-License-Identifier: AGPL-3.0-only

package helper

import (
	"context"
	"errors"
	"fmt"
	"strings"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/access"
	"github.com/NogMeer/trassa-agent/internal/ops"
	"github.com/NogMeer/trassa-agent/internal/rollback"
)

// CodeAccessUnavailable — доступ на этой сборке или сервере не настроен.
const CodeAccessUnavailable = "ACCESS_UNAVAILABLE"

func (e *Executor) accessHandlers() map[string]handler {
	return map[string]handler{
		ops.TypeSSHCATrust:              {preview: e.previewTrust, apply: e.applyTrust},
		ops.TypeSSHCAUntrust:            {preview: e.previewUntrust, apply: e.applyUntrust},
		ops.TypeAccessUserEnsure:        {preview: e.previewUserEnsure, apply: e.applyUserEnsure},
		ops.TypeAccessUserRemove:        {preview: e.previewUserRemove, apply: e.applyUserRemove},
		ops.TypeAccessSessionsTerminate: {apply: e.applyTerminate},
		ops.TypeAccessRescueGrant:       {preview: e.previewRescueGrant, apply: e.applyRescueGrant},
		ops.TypeAccessRescueRevoke:      {apply: e.applyRescueRevoke},
		ops.TypeAccessStateRead:         {apply: e.applyAccessState},
	}
}

// accessCode — код итога по ошибке пакета access (имена ошибок — коды панели).
func accessCode(err error) string {
	for _, known := range []error{
		access.ErrSSHDConflict, access.ErrSSHDInvalid, access.ErrIncludeMissing, access.ErrUserForeign,
		access.ErrNotManaged, access.ErrSudoMissing, access.ErrSudoInclude, access.ErrUserForbidden,
	} {
		if errors.Is(err, known) {
			return known.Error()
		}
	}
	return CodeApplyFailed
}

func (e *Executor) accessEnv(r *run) (*access.Env, *agentv1.OperationResult) {
	if e.Access == nil {
		return nil, r.failed(CodeAccessUnavailable, "доступ на этом сервере недоступен")
	}
	return e.Access, nil
}

// accessChange — изменение доступа с точкой отката CONFIG: файлы sshd, принципалы, sudo, учётные записи.
func (e *Executor) accessChange(ctx context.Context, r *run, users []string, apply func(env *access.Env) error) *agentv1.OperationResult {
	env, fail := e.accessEnv(r)
	if fail != nil {
		return fail
	}
	return e.runConfigChange(ctx, r, configChange{
		paths: env.Paths(users...), code: accessCode,
		// Откат файлов sshd без перечитывания оставил бы в силе новые настройки.
		state:  rollback.State{Commands: [][]string{{"/usr/bin/systemctl", "try-reload-or-restart", "ssh.service"}}},
		apply:  func() error { return apply(env) },
		verify: func() error { return nil }, // проверка sshd -T — внутри apply, до и после изменения
	})
}

func (e *Executor) previewTrust(_ context.Context, r *run) (*agentv1.Preview, *agentv1.OperationResult) {
	pv := &agentv1.Preview{Summary: "Доверие к CA пространства", Services: []string{"ssh.service"},
		Files: []*agentv1.FileChange{{Path: access.AccessConf}, {Path: access.CAFile}},
		Notes: []string{"Вход по сертификату — только пользователям с файлом принципалов; root по сертификату не войдёт"}}
	for _, k := range r.body.GetParams().GetSshcaTrust().GetCaPublicKeys() {
		if _, fp, err := access.ParseCA(k); err == nil {
			pv.Notes = append(pv.Notes, "CA "+fp)
		}
	}
	return pv, nil
}

func (e *Executor) applyTrust(ctx context.Context, r *run) *agentv1.OperationResult {
	var out *agentv1.SshCaTrustResult
	res := e.accessChange(ctx, r, nil, func(env *access.Env) error {
		var err error
		out, err = env.Trust(ctx, r.body.GetParams().GetSshcaTrust().GetCaPublicKeys())
		return err
	})
	if out != nil && res.GetOutcome() == agentv1.OperationOutcome_OPERATION_OUTCOME_SUCCEEDED {
		res.Data = &agentv1.OperationResult_SshcaTrust{SshcaTrust: out}
	}
	return res
}

func (e *Executor) previewUntrust(_ context.Context, r *run) (*agentv1.Preview, *agentv1.OperationResult) {
	return &agentv1.Preview{Summary: "Снять доверие к CA: " + strings.Join(r.body.GetParams().GetSshcaUntrust().GetCaFingerprints(), ", "),
		Services: []string{"ssh.service"}, Notes: []string{"Сертификаты этих CA перестанут пускать на сервер"}}, nil
}

func (e *Executor) applyUntrust(ctx context.Context, r *run) *agentv1.OperationResult {
	var out *agentv1.SshCaTrustResult
	res := e.accessChange(ctx, r, nil, func(env *access.Env) error {
		var err error
		out, err = env.Untrust(ctx, r.body.GetParams().GetSshcaUntrust().GetCaFingerprints())
		return err
	})
	if out != nil && res.GetOutcome() == agentv1.OperationOutcome_OPERATION_OUTCOME_SUCCEEDED {
		res.Data = &agentv1.OperationResult_SshcaUntrust{SshcaUntrust: out}
	}
	return res
}

func (e *Executor) previewUserEnsure(_ context.Context, r *run) (*agentv1.Preview, *agentv1.OperationResult) {
	p := r.body.GetParams().GetAccessUserEnsure()
	pv := &agentv1.Preview{Summary: fmt.Sprintf("Пользователь %s: принципалов %d", p.GetUnixUser(), len(p.GetPrincipals())),
		Files: []*agentv1.FileChange{{Path: access.PrincipalsDir + "/" + p.GetUnixUser()}}}
	if p.GetSudo() {
		pv.Notes = append(pv.Notes, "sudo без пароля (/etc/sudoers.d/trassa-"+p.GetUnixUser()+")")
	}
	return pv, nil
}

func (e *Executor) applyUserEnsure(ctx context.Context, r *run) *agentv1.OperationResult {
	p := r.body.GetParams().GetAccessUserEnsure()
	var out *agentv1.AccessUserEnsureResult
	res := e.accessChange(ctx, r, []string{p.GetUnixUser()}, func(env *access.Env) error {
		var err error
		out, err = env.UserEnsure(ctx, p)
		return err
	})
	if out != nil && res.GetOutcome() == agentv1.OperationOutcome_OPERATION_OUTCOME_SUCCEEDED {
		res.Data = &agentv1.OperationResult_AccessUserEnsure{AccessUserEnsure: out}
	}
	return res
}

func (e *Executor) previewUserRemove(_ context.Context, r *run) (*agentv1.Preview, *agentv1.OperationResult) {
	p := r.body.GetParams().GetAccessUserRemove()
	pv := &agentv1.Preview{Summary: "Удалить пользователя " + p.GetUnixUser(), Notes: []string{"Его сеансы и процессы будут завершены"}}
	if p.GetDeleteHome() {
		pv.Notes = append(pv.Notes, "Домашний каталог будет удалён без возврата")
	}
	return pv, nil
}

func (e *Executor) applyUserRemove(ctx context.Context, r *run) *agentv1.OperationResult {
	p := r.body.GetParams().GetAccessUserRemove()
	var out *agentv1.AccessUserRemoveResult
	res := e.accessChange(ctx, r, []string{p.GetUnixUser()}, func(env *access.Env) error {
		var err error
		out, err = env.UserRemove(ctx, p)
		return err
	})
	if out != nil && res.GetOutcome() == agentv1.OperationOutcome_OPERATION_OUTCOME_SUCCEEDED {
		res.Data = &agentv1.OperationResult_AccessUserRemove{AccessUserRemove: out}
	}
	return res
}

func (e *Executor) applyTerminate(ctx context.Context, r *run) *agentv1.OperationResult {
	env, fail := e.accessEnv(r)
	if fail != nil {
		return fail
	}
	p := r.body.GetParams().GetAccessSessionsTerminate()
	out := &agentv1.AccessSessionsTerminateResult{}
	if len(p.GetCertKeyIds()) > 0 {
		done, missing, err := env.TerminateCerts(ctx, p.GetCertKeyIds())
		if err != nil {
			return r.failed(CodeApplyFailed, err.Error())
		}
		out.Terminated, out.NotFound = done, missing
	}
	// Терминалов через помощник в этой версии нет: их идентификаторы не найдены.
	out.NotFound = append(out.NotFound, p.GetSessionIds()...)
	res := r.succeeded(fmt.Sprintf("Закрыто сеансов: %d", len(out.GetTerminated())))
	res.Data = &agentv1.OperationResult_AccessSessionsTerminate{AccessSessionsTerminate: out}
	return res
}

func (e *Executor) previewRescueGrant(_ context.Context, r *run) (*agentv1.Preview, *agentv1.OperationResult) {
	return &agentv1.Preview{Summary: "Аварийный вход trassa-rescue (sudo) по короткому сертификату",
		Notes: []string{"Ключи у trassa-rescue не действуют — только сертификат с выданным принципалом до срока"}}, nil
}

func (e *Executor) applyRescueGrant(ctx context.Context, r *run) *agentv1.OperationResult {
	var out *agentv1.AccessRescueGrantResult
	res := e.accessChange(ctx, r, []string{access.RescueUser}, func(env *access.Env) error {
		var err error
		out, err = env.RescueGrant(ctx, r.body.GetParams().GetAccessRescueGrant())
		return err
	})
	if out != nil && res.GetOutcome() == agentv1.OperationOutcome_OPERATION_OUTCOME_SUCCEEDED {
		res.Data = &agentv1.OperationResult_AccessRescueGrant{AccessRescueGrant: out}
	}
	return res
}

func (e *Executor) applyRescueRevoke(ctx context.Context, r *run) *agentv1.OperationResult {
	return e.accessChange(ctx, r, []string{access.RescueUser}, func(env *access.Env) error { return env.RescueRevoke(ctx) })
}

func (e *Executor) applyAccessState(ctx context.Context, r *run) *agentv1.OperationResult {
	env, fail := e.accessEnv(r)
	if fail != nil {
		return fail
	}
	out, err := env.StateRead(ctx)
	if err != nil {
		return r.failed(accessCode(err), err.Error())
	}
	res := r.succeeded("")
	res.Data = &agentv1.OperationResult_AccessState{AccessState: out}
	return res
}
