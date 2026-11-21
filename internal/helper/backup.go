// SPDX-License-Identifier: AGPL-3.0-only

package helper

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/backup"
	"github.com/NogMeer/trassa-agent/internal/backupstatus"
	"github.com/NogMeer/trassa-agent/internal/helperrpc"
	"github.com/NogMeer/trassa-agent/internal/ops"
)

// CodeBackupUnavailable — бэкапы на этой сборке или сервере не настроены (нет окружения или ключа секретов).
const CodeBackupUnavailable = "BACKUP_UNAVAILABLE"

// progressEvery — не чаще одного кадра хода бэкапа за столько.
const progressEvery = 5 * time.Second

func (e *Executor) backupHandlers() map[string]handler {
	return map[string]handler{
		ops.TypeBackupInit:         {preview: e.previewBackupInit, apply: e.applyBackupInit},
		ops.TypeBackupRun:          {preview: e.previewBackupRun, apply: e.applyBackupRun},
		ops.TypeBackupVerify:       {preview: e.previewBackupVerify, apply: e.applyBackupVerify},
		ops.TypeBackupRestore:      {preview: e.previewBackupRestore, apply: e.applyBackupRestore},
		ops.TypeBackupDiscover:     {apply: e.applyBackupDiscover},
		ops.TypeBackupSnapshots:    {apply: e.applyBackupSnapshots},
		ops.TypeBackupBrowse:       {apply: e.applyBackupBrowse},
		ops.TypeBackupPrune:        {preview: e.previewBackupPrune, apply: e.applyBackupPrune},
		ops.TypeBackupTargetEnsure: {preview: e.previewTargetEnsure, apply: e.applyTargetEnsure},
		ops.TypeBackupTargetRemove: {preview: e.previewTargetRemove, apply: e.applyTargetRemove},
		ops.TypeBackupUnconfigure:  {preview: e.previewBackupUnconfigure, apply: e.applyBackupUnconfigure},
		ops.TypeBackupRevokeReader: {apply: e.applyRevokeReader},
	}
}

// backupCode — код итога по ошибке пакета backup (имена ошибок — коды панели).
func backupCode(err error) string {
	for _, known := range []error{
		backup.ErrRepoExists, backup.ErrRepoPassword, backup.ErrRepoLocked, backup.ErrTargetDown,
		backup.ErrSnapshotMissing, backup.ErrNoSpace, backup.ErrRollbackUnavailable, backup.ErrRestoreVerify,
		backup.ErrResticChecksum, backup.ErrToolUnknown, backup.ErrPathForbidden, backup.ErrNoPlan, backup.ErrTargetPrecondition,
		backup.ErrDeadline,
	} {
		if errors.Is(err, known) {
			return known.Error()
		}
	}
	return CodeApplyFailed
}

func (e *Executor) backupEnv(r *run) (*backup.Env, *agentv1.OperationResult) {
	if e.Backup == nil {
		return nil, r.failed(CodeBackupUnavailable, "бэкапы на этом сервере недоступны")
	}
	return e.Backup, nil
}

// planRestic — restic сохранённого плана.
func (e *Executor) planRestic(r *run, planID string) (*backup.Env, *backup.Restic, *agentv1.OperationResult) {
	env, fail := e.backupEnv(r)
	if fail != nil {
		return nil, nil, fail
	}
	rs, err := env.Restic(planID)
	if err != nil {
		return nil, nil, r.failed(backupCode(err), err.Error())
	}
	return env, rs, nil
}

// backupProgress — кадр хода (OperationProgress.backup) не чаще progressEvery.
func (r *run) backupProgress() func(source string, st backup.Status) {
	var last time.Time
	return func(source string, st backup.Status) {
		now := time.Now()
		if now.Sub(last) < progressEvery {
			return
		}
		last = now
		done, files := st.BytesDone, st.FilesDone
		if st.BytesRestored > 0 || st.FilesRestored > 0 {
			done, files = st.BytesRestored, st.FilesRestored
		}
		r.seq++
		raw, _ := proto.Marshal(&agentv1.OperationProgress{
			OperationId: r.body.GetOperationId(), Seq: r.seq, Phase: r.phase,
			Backup: &agentv1.BackupProgress{BytesDone: done, BytesTotal: st.TotalBytes, FilesDone: files, CurrentSource: source},
		})
		_ = r.send(helperrpc.Response{Kind: helperrpc.KindProgress, Progress: raw})
	}
}

// ---------- backup.init ----------

func (e *Executor) previewBackupInit(_ context.Context, r *run) (*agentv1.Preview, *agentv1.OperationResult) {
	env, fail := e.backupEnv(r)
	if fail != nil {
		return nil, fail
	}
	p := r.body.GetParams().GetBackupInit()
	dir, _ := env.Store.PlanDir(p.GetPlanId())
	pv := &agentv1.Preview{
		Summary: fmt.Sprintf("restic %s и репозиторий %s", p.GetResticVersion(), p.GetRepo().GetUrl()),
		Notes: []string{
			"restic скачивает агент, помощник сверяет контрольную сумму из подписанной операции",
			"Настройки и секреты плана — " + dir + " (root, 0600)",
			"Существующий репозиторий не перезаписывается; чужой — отказ BACKUP_REPO_EXISTS",
		},
	}
	if p.GetSshKeypair() {
		pv.Notes = append(pv.Notes, "Будет создана пара ключей SSH для сервера-цели; закрытый ключ не покидает сервер")
	}
	return pv, nil
}

func (e *Executor) applyBackupInit(ctx context.Context, r *run) *agentv1.OperationResult {
	env, fail := e.backupEnv(r)
	if fail != nil {
		return fail
	}
	if e.Secrets == nil {
		return r.failed(CodeBackupUnavailable, "нет ключа секретов помощника")
	}
	p := r.body.GetParams().GetBackupInit()
	plan := p.GetPlanId()
	paths, err := env.Store.Paths(plan)
	if err != nil {
		return r.failed(ops.CodeParamsInvalid, err.Error())
	}
	keys, _ := env.SSHKeyPaths(plan)
	paths = append(paths, keys...)
	repo, err := backup.OpenRepo(e.Secrets, r.body, plan, p.GetRepo(), "")
	if err != nil {
		return r.failed("SECRET_INVALID", err.Error())
	}
	repo.ResticVersion = p.GetResticVersion()
	data := &agentv1.BackupInitResult{}
	res := e.runConfigChange(ctx, r, configChange{
		paths: paths,
		code:  backupCode,
		apply: func() error {
			if _, err := backup.InstallRestic(ctx, StageDir(e.Paths, r.body.GetOperationId()), p.GetResticSha256(), p.GetResticVersion(), env.BinDir); err != nil {
				return err
			}
			r.system("restic %s установлен", p.GetResticVersion())
			if err := env.Store.Save(plan, repo); err != nil {
				return err
			}
			if k := p.GetSshHostKey(); k != "" {
				if err := env.PinHostKey(plan, repo.URL, k); err != nil {
					return err
				}
			}
			if p.GetSshKeypair() {
				// Цель SERVER: сначала ключ (панель ставит его на цель backup.target.ensure), репозиторий —
				// следующим backup.init, когда цель готова.
				pub, err := env.EnsureSSHKey(plan)
				if err != nil {
					return err
				}
				data.SshPublicKey = pub
				return nil
			}
			rs, err := env.Restic(plan)
			if err != nil {
				return err
			}
			existed, err := backup.InitRepo(ctx, rs)
			if err != nil {
				return err
			}
			data.RepoExisted = existed
			return nil
		},
		verify: func() error {
			_, err := env.Restic(plan)
			return err
		},
	})
	if res.GetOutcome() == agentv1.OperationOutcome_OPERATION_OUTCOME_SUCCEEDED {
		res.Data = &agentv1.OperationResult_BackupInit{BackupInit: data}
		now := e.now().UnixMilli()
		e.markStatus(env, plan, func(s *backupstatus.Plan) bool {
			if s.ConfiguredMs == 0 {
				s.ConfiguredMs = now
			}
			return true
		})
	}
	return res
}

// markStatus — учёт для метрики backup_last_success_age_seconds; сбой записи не меняет итог операции.
func (e *Executor) markStatus(env *backup.Env, plan string, fn func(*backupstatus.Plan) bool) {
	if err := env.MarkStatus(plan, fn); err != nil {
		e.log().Warn("helper: состояние бэкапов не записано", "plan", plan, "err", err)
	}
}

// ---------- backup.unconfigure ----------

func (e *Executor) previewBackupUnconfigure(_ context.Context, r *run) (*agentv1.Preview, *agentv1.OperationResult) {
	env, fail := e.backupEnv(r)
	if fail != nil {
		return nil, fail
	}
	dir, _ := env.Store.PlanDir(r.body.GetParams().GetBackupUnconfigure().GetPlanId())
	return &agentv1.Preview{Summary: "Удалить настройки плана " + dir, Notes: []string{"Репозиторий и копии в хранилище не удаляются"}}, nil
}

func (e *Executor) applyBackupUnconfigure(_ context.Context, r *run) *agentv1.OperationResult {
	env, fail := e.backupEnv(r)
	if fail != nil {
		return fail
	}
	plan := r.body.GetParams().GetBackupUnconfigure().GetPlanId()
	if err := env.Store.Remove(plan); err != nil {
		return r.failed(CodeApplyFailed, err.Error())
	}
	e.markStatus(env, plan, func(*backupstatus.Plan) bool { return false })
	if err := os.RemoveAll(filepath.Join(env.CacheDir, strings.ToLower(plan))); err != nil {
		r.system("Кэш restic не удалён: %v", err)
	}
	return r.succeeded("Настройки плана удалены")
}

// ---------- чтение: snapshots, browse, discover ----------

func (e *Executor) applyBackupSnapshots(ctx context.Context, r *run) *agentv1.OperationResult {
	_, rs, fail := e.planRestic(r, r.body.GetParams().GetBackupSnapshots().GetPlanId())
	if fail != nil {
		return fail
	}
	snaps, err := backup.Snapshots(ctx, rs)
	if err != nil {
		return r.failed(backupCode(err), err.Error())
	}
	out := &agentv1.BackupSnapshotsResult{}
	for _, s := range snaps {
		out.Snapshots = append(out.Snapshots, &agentv1.BackupSnapshot{Id: s.ID, TimeMs: s.Time.UnixMilli(), Paths: s.Paths, Tags: s.Tags})
	}
	res := r.succeeded("")
	res.Data = &agentv1.OperationResult_BackupSnapshots{BackupSnapshots: out}
	return res
}

func (e *Executor) applyBackupBrowse(ctx context.Context, r *run) *agentv1.OperationResult {
	p := r.body.GetParams().GetBackupBrowse()
	_, rs, fail := e.planRestic(r, p.GetPlanId())
	if fail != nil {
		return fail
	}
	entries, truncated, err := backup.Browse(ctx, rs, p.GetSnapshotId(), p.GetPath(), int(p.GetLimit()))
	if err != nil {
		return r.failed(backupCode(err), err.Error())
	}
	res := r.succeeded("")
	res.Data = &agentv1.OperationResult_BackupBrowse{BackupBrowse: &agentv1.BackupBrowseResult{Entries: entries, Truncated: truncated}}
	return res
}

func (e *Executor) applyBackupDiscover(ctx context.Context, r *run) *agentv1.OperationResult {
	env, fail := e.backupEnv(r)
	if fail != nil {
		return fail
	}
	found, notes := env.Discover(ctx)
	res := r.succeeded(strings.Join(notes, "; "))
	res.Data = &agentv1.OperationResult_BackupDiscover{BackupDiscover: found}
	return res
}

// ---------- backup.run ----------

func (e *Executor) previewBackupRun(_ context.Context, r *run) (*agentv1.Preview, *agentv1.OperationResult) {
	p := r.body.GetParams().GetBackupRun()
	pv := &agentv1.Preview{Summary: fmt.Sprintf("Бэкап: источников %d", len(p.GetSources()))}
	for _, s := range p.GetSources() {
		pv.Notes = append(pv.Notes, "Источник "+s.GetName())
	}
	pv.Notes = append(pv.Notes, "Незавершённая копия в список не попадает; следующий запуск дозагрузит недостающее")
	return pv, nil
}

func (e *Executor) applyBackupRun(ctx context.Context, r *run) *agentv1.OperationResult {
	p := r.body.GetParams().GetBackupRun()
	env, rs, fail := e.planRestic(r, p.GetPlanId())
	if fail != nil {
		return fail
	}
	out, code, err := env.RunPlan(ctx, rs, backup.RunJob{Params: p, Deadline: env.Deadline(p.GetDeadlineMs()), Progress: r.backupProgress(),
		Event: e.PushEvent})
	var res *agentv1.OperationResult
	switch {
	case err != nil:
		res = r.failed(backupCode(err), err.Error())
	case code != "":
		res = r.failed(code, "Не все источники скопированы")
	default:
		res = r.succeeded(fmt.Sprintf("Источников скопировано: %d", len(out.GetSources())))
		now := e.now().UnixMilli()
		e.markStatus(env, p.GetPlanId(), func(s *backupstatus.Plan) bool {
			if s.ConfiguredMs == 0 {
				s.ConfiguredMs = now
			}
			s.LastSuccessMs = now
			return true
		})
	}
	res.Data = &agentv1.OperationResult_BackupRun{BackupRun: out}
	return res
}

// ---------- backup.verify ----------

func (e *Executor) previewBackupVerify(_ context.Context, r *run) (*agentv1.Preview, *agentv1.OperationResult) {
	p := r.body.GetParams().GetBackupVerify()
	return &agentv1.Preview{
		Summary: fmt.Sprintf("Проверка: целостность (%s данных), выборка до %d файлов, дампы баз", p.GetReadDataSubset(), p.GetSampleFiles()),
		Notes:   []string{fmt.Sprintf("Во временном каталоге понадобится до %d байт; он удаляется всегда", p.GetMaxBytes())},
	}, nil
}

func (e *Executor) applyBackupVerify(ctx context.Context, r *run) *agentv1.OperationResult {
	p := r.body.GetParams().GetBackupVerify()
	env, rs, fail := e.planRestic(r, p.GetPlanId())
	if fail != nil {
		return fail
	}
	out, err := env.Verify(ctx, rs, backup.VerifySpec{OpID: r.body.GetOperationId(), Params: p, Deadline: env.Deadline(p.GetDeadlineMs())})
	if err != nil {
		return r.failed(backupCode(err), err.Error())
	}
	var res *agentv1.OperationResult
	if out.GetRepoCheckOk() && out.GetFilesOk() && out.GetDumpsOk() {
		res = r.succeeded("Копия проверена")
	} else {
		res = r.failed("BACKUP_VERIFY_FAILED", "Проверка копии не прошла")
	}
	res.Data = &agentv1.OperationResult_BackupVerify{BackupVerify: out}
	return res
}

// ---------- backup.prune ----------

func (e *Executor) previewBackupPrune(_ context.Context, r *run) (*agentv1.Preview, *agentv1.OperationResult) {
	ret := r.body.GetParams().GetBackupPrune().GetRetention()
	return &agentv1.Preview{
		Summary: fmt.Sprintf("Чистка по политике: последних %d, сроки %s/%s/%s", ret.GetKeepLast(), ret.GetKeepWithinDaily(), ret.GetKeepWithinWeekly(), ret.GetKeepWithinMonthly()),
		Notes:   []string{"Удалённые копии вернуть нельзя", "Ключи обслуживания используются только на время операции и не сохраняются"},
	}, nil
}

func (e *Executor) applyBackupPrune(ctx context.Context, r *run) *agentv1.OperationResult {
	env, fail := e.backupEnv(r)
	if fail != nil {
		return fail
	}
	if e.Secrets == nil {
		return r.failed(CodeBackupUnavailable, "нет ключа секретов помощника")
	}
	p := r.body.GetParams().GetBackupPrune()
	if u := p.GetTargetUnixUser(); u != "" {
		return e.pruneOnTarget(ctx, r, env, p)
	}
	saved, err := env.Store.Load(p.GetPlanId())
	if err != nil {
		return r.failed(backupCode(err), err.Error())
	}
	maint, err := backup.OpenRepo(e.Secrets, r.body, p.GetPlanId(), p.GetMaintenanceRepo(), backup.FieldMaintPrefix)
	if err != nil {
		return r.failed("SECRET_INVALID", err.Error())
	}
	if maint.URL != saved.URL {
		return r.failed(ops.CodeParamsInvalid, "ключи обслуживания для другого репозитория")
	}
	maint.ResticVersion = saved.ResticVersion
	out, err := env.Prune(ctx, p.GetPlanId(), maint, p.GetRetention(), env.Deadline(0))
	if err != nil {
		return r.failed(backupCode(err), err.Error())
	}
	res := r.succeeded(fmt.Sprintf("Удалено копий: %d", out.GetRemovedSnapshots()))
	res.Data = &agentv1.OperationResult_BackupPrune{BackupPrune: out}
	return res
}

// pruneOnTarget — чистка репозитория цели SERVER на самой цели: пароль — секретом в операции, только на время.
func (e *Executor) pruneOnTarget(ctx context.Context, r *run, env *backup.Env, p *agentv1.BackupPruneParams) *agentv1.OperationResult {
	t, fail := e.backupTarget(r)
	if fail != nil {
		return fail
	}
	maint, err := backup.OpenRepo(e.Secrets, r.body, p.GetPlanId(), p.GetMaintenanceRepo(), backup.FieldMaintPrefix)
	if err != nil {
		return r.failed("SECRET_INVALID", err.Error())
	}
	out, err := env.PruneTarget(ctx, t, p.GetTargetUnixUser(), maint.Password, p.GetRetention(), env.Deadline(0))
	if err != nil {
		return r.failed(backupCode(err), err.Error())
	}
	res := r.succeeded(fmt.Sprintf("Удалено копий: %d", out.GetRemovedSnapshots()))
	res.Data = &agentv1.OperationResult_BackupPrune{BackupPrune: out}
	return res
}

// ---------- backup.restore ----------

func (e *Executor) previewBackupRestore(_ context.Context, r *run) (*agentv1.Preview, *agentv1.OperationResult) {
	p := r.body.GetParams().GetBackupRestore()
	if p.GetSshKeypair() {
		return &agentv1.Preview{Summary: "Подготовить ключ получателя для восстановления на этот сервер",
			Notes: []string{"Будет создана пара ключей SSH; закрытый ключ не покидает сервер и удаляется после восстановления"}}, nil
	}
	pv := &agentv1.Preview{Summary: fmt.Sprintf("Восстановление снимка %s (%s)", p.GetSnapshotId(), p.GetMode())}
	if p.GetRepo() != nil {
		pv.Notes = append(pv.Notes, "Репозиторий другого сервера — только чтение; пароль и ключи хранилища используются на время операции и удаляются")
	}
	sel := p.GetSelection()
	if sel.GetAll() {
		pv.Notes = append(pv.Notes, "Восстанавливается весь снимок")
	}
	for _, x := range sel.GetPaths() {
		pv.Files = append(pv.Files, &agentv1.FileChange{Path: x, Kind: agentv1.FileChangeKind_FILE_CHANGE_KIND_MODIFY})
	}
	for _, d := range sel.GetDatabases() {
		pv.Notes = append(pv.Notes, "База "+d+" будет заменена данными копии")
	}
	switch r.body.GetRollback() {
	case agentv1.RollbackKind_ROLLBACK_KIND_LOCAL_COPY:
		pv.Notes = append(pv.Notes, "Перед заменой — локальная копия заменяемых путей и свежий дамп базы (хранится 72 часа); при провале проверки вернётся сама")
	case agentv1.RollbackKind_ROLLBACK_KIND_SNAPSHOT:
		pv.Notes = append(pv.Notes, "Откат — снапшотом сервера у хостера")
	}
	return pv, nil
}

func (e *Executor) applyBackupRestore(ctx context.Context, r *run) *agentv1.OperationResult {
	p := r.body.GetParams().GetBackupRestore()
	env, fail := e.backupEnv(r)
	if fail != nil {
		return fail
	}
	// Подготовка получателя: только пара ключей, ничего не восстанавливается.
	if p.GetSshKeypair() {
		pub, err := env.EnsureRestoreKey(p.GetPlanId())
		if err != nil {
			return r.failed(CodeApplyFailed, err.Error())
		}
		res := r.succeeded("Ключ получателя готов")
		res.Data = &agentv1.OperationResult_BackupRestore{BackupRestore: &agentv1.BackupRestoreResult{SshPublicKey: pub}}
		return res
	}
	var rs *backup.Restic
	remote := p.GetRepo() != nil
	if remote {
		var cleanup func(bool)
		var res *agentv1.OperationResult
		rs, cleanup, res = e.remoteRestic(ctx, r, env, p)
		if res != nil {
			return res
		}
		ok := false
		// Секреты репозитория — только на время операции; пара ключей — до успешного восстановления.
		defer func() { cleanup(ok) }()
		out := e.restoreWith(ctx, r, env, rs, p)
		ok = out.GetOutcome() == agentv1.OperationOutcome_OPERATION_OUTCOME_SUCCEEDED
		return out
	}
	_, rs, fail = e.planRestic(r, p.GetPlanId())
	if fail != nil {
		return fail
	}
	return e.restoreWith(ctx, r, env, rs, p)
}

// remoteRestic — получатель без плана: restic из таблицы помощника (архив скачал агент), секреты из операции
// открываются ключом получателя и живут только в памяти и во временном файле пароля.
func (e *Executor) remoteRestic(ctx context.Context, r *run, env *backup.Env, p *agentv1.BackupRestoreParams) (*backup.Restic, func(bool), *agentv1.OperationResult) {
	if e.Secrets == nil {
		return nil, nil, r.failed(CodeBackupUnavailable, "нет ключа секретов помощника")
	}
	repo, err := backup.OpenRepo(e.Secrets, r.body, p.GetPlanId(), p.GetRepo(), "")
	if err != nil {
		return nil, nil, r.failed("SECRET_INVALID", err.Error())
	}
	tool := p.GetRestic()
	if _, err := backup.InstallRestic(ctx, StageDir(e.Paths, r.body.GetOperationId()), tool.GetSha256(), tool.GetVersion(), env.BinDir); err != nil {
		return nil, nil, r.failed(backupCode(err), err.Error())
	}
	repo.ResticVersion = tool.GetVersion()
	rs, cleanup, err := env.RemoteRestic(p.GetPlanId(), repo, p.GetSshHostKey())
	if err != nil {
		return nil, nil, r.failed(backupCode(err), err.Error())
	}
	return rs, cleanup, nil
}

func (e *Executor) restoreWith(ctx context.Context, r *run, env *backup.Env, rs *backup.Restic, p *agentv1.BackupRestoreParams) *agentv1.OperationResult {
	prog := r.backupProgress()
	out, err := env.Restore(ctx, rs, backup.RestoreJob{
		OpID: r.body.GetOperationId(), Params: p, Rollback: r.body.GetRollback(), Deadline: env.Deadline(p.GetDeadlineMs()),
		Progress: func(st backup.Status) { prog("", st) },
		Log:      func(s string) { r.system("%s", s) },
	})
	var res *agentv1.OperationResult
	switch {
	case out != nil && out.RolledBack:
		res = r.rolledBack(backupCode(err), err.Error())
	case err != nil:
		res = r.failed(backupCode(err), err.Error())
	default:
		res = r.succeeded("Восстановлено")
		res.Data = &agentv1.OperationResult_BackupRestore{BackupRestore: out.Result}
	}
	if r.body.GetRollback() == agentv1.RollbackKind_ROLLBACK_KIND_LOCAL_COPY {
		res.RollbackPoint = &agentv1.RollbackPoint{Kind: agentv1.RollbackKind_ROLLBACK_KIND_LOCAL_COPY, Ref: env.LocalCopyDir(r.body.GetOperationId())}
	}
	return res
}

// ---------- backup.target.ensure / remove ----------

func (e *Executor) backupTarget(r *run) (*backup.Target, *agentv1.OperationResult) {
	if e.BackupTarget == nil {
		return nil, r.failed(CodeBackupUnavailable, "цель бэкапов на этом сервере недоступна")
	}
	return e.BackupTarget, nil
}

func (e *Executor) previewTargetEnsure(_ context.Context, r *run) (*agentv1.Preview, *agentv1.OperationResult) {
	p := r.body.GetParams().GetBackupTargetEnsure()
	return &agentv1.Preview{
		Summary: fmt.Sprintf("Цель бэкапов: пользователь %s, каталог %s", p.GetUnixUser(), p.GetPath()),
		Files: []*agentv1.FileChange{
			{Path: backup.SSHDropInDir + "/" + p.GetUnixUser() + ".conf", Kind: agentv1.FileChangeKind_FILE_CHANGE_KIND_CREATE},
			{Path: backup.TargetKeyDir + "/" + p.GetUnixUser() + ".keys", Kind: agentv1.FileChangeKind_FILE_CHANGE_KIND_CREATE},
		},
		Services: []string{"ssh.service"},
		Notes: []string{
			"Ключ источника только добавляет копии (rclone serve restic --append-only): взломанный источник не удалит старые копии",
			"Вход по ключу только с адреса " + p.GetSourceAddress() + ", без оболочки, переадресаций и пароля",
			"Удаление копий (backup.prune) — только на этом сервере",
		},
	}, nil
}

func (e *Executor) applyTargetEnsure(ctx context.Context, r *run) *agentv1.OperationResult {
	t, fail := e.backupTarget(r)
	if fail != nil {
		return fail
	}
	p := r.body.GetParams().GetBackupTargetEnsure()
	var data *agentv1.BackupTargetEnsureResult
	res := e.runConfigChange(ctx, r, configChange{
		paths: t.Paths(p.GetUnixUser()),
		code:  backupCode,
		apply: func() error {
			var err error
			data, err = t.Ensure(ctx, r.body.GetOperationId(), p)
			return err
		},
		verify: func() error { return t.Check(ctx, p) },
	})
	if res.GetOutcome() == agentv1.OperationOutcome_OPERATION_OUTCOME_SUCCEEDED && data != nil {
		res.Data = &agentv1.OperationResult_BackupTargetEnsure{BackupTargetEnsure: data}
	}
	return res
}

func (e *Executor) previewTargetRemove(_ context.Context, r *run) (*agentv1.Preview, *agentv1.OperationResult) {
	p := r.body.GetParams().GetBackupTargetRemove()
	pv := &agentv1.Preview{Summary: "Снять цель бэкапов " + p.GetUnixUser(), Services: []string{"ssh.service"}}
	if p.GetDeleteData() {
		pv.Notes = append(pv.Notes, "Каталог "+p.GetPath()+" с копиями будет удалён без возврата")
	}
	return pv, nil
}

func (e *Executor) applyTargetRemove(ctx context.Context, r *run) *agentv1.OperationResult {
	t, fail := e.backupTarget(r)
	if fail != nil {
		return fail
	}
	p := r.body.GetParams().GetBackupTargetRemove()
	return e.runConfigChange(ctx, r, configChange{
		paths: t.Paths(p.GetUnixUser()),
		code:  backupCode,
		apply: func() error { return t.Remove(ctx, p) },
		verify: func() error {
			if _, err := user.Lookup(p.GetUnixUser()); err == nil {
				return fmt.Errorf("пользователь %s остался", p.GetUnixUser())
			}
			return nil
		},
	})
}

// applyRevokeReader — backup.target.revoke_reader: читатель цели снимается до срока.
func (e *Executor) applyRevokeReader(ctx context.Context, r *run) *agentv1.OperationResult {
	t, fail := e.backupTarget(r)
	if fail != nil {
		return fail
	}
	u := r.body.GetParams().GetBackupTargetRevokeReader().GetUnixUser()
	return e.runConfigChange(ctx, r, configChange{
		paths: t.Paths(u),
		code:  backupCode,
		apply: func() error { return t.RevokeReader(ctx, u) },
		verify: func() error {
			if _, err := user.Lookup(backup.ReaderUser(u)); err == nil {
				return fmt.Errorf("читатель %s остался", backup.ReaderUser(u))
			}
			return nil
		},
	})
}
