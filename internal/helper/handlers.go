// SPDX-License-Identifier: AGPL-3.0-only

package helper

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/autorollback"
	"github.com/NogMeer/trassa-agent/internal/ops"
	"github.com/NogMeer/trassa-agent/internal/redact"
	"github.com/NogMeer/trassa-agent/internal/rollback"
	"github.com/NogMeer/trassa-agent/internal/uninstall"
	"github.com/NogMeer/trassa-agent/internal/update"
)

// Updater — зависимости agent.update.
type Updater struct {
	// Verifier — ключи выпуска; nil — обновления не ставятся (UPDATE_SIGNATURE_INVALID).
	Verifier *update.Verifier
	Client   *http.Client
}

// Бинарники, которые меняет обновление.
var binaries = []string{"trassa-agent", "trassa-helper"}

// Предельные размеры загрузок.
const (
	maxSignature = 4 << 10
	maxSums      = 64 << 10
	maxBinary    = 128 << 20
)

func (e *Executor) builtinHandlers() map[string]handler {
	h := map[string]handler{
		ops.TypeSystemInfo:      {apply: e.applySystemInfo},
		ops.TypeSystemInventory: {apply: e.applyInventory},
		ops.TypeAgentUpdate:     {preview: e.previewUpdate, apply: e.applyUpdate},
		ops.TypeAgentUninstall:  {preview: e.previewUninstall, apply: e.applyUninstall},
		ops.TypeRollbackRestore: {preview: e.previewRestore, apply: e.applyRestore},
	}
	for t, x := range e.extraHandlers() {
		h[t] = x
	}
	return h
}

// ---------- system.info, system.inventory ----------

func (e *Executor) applySystemInfo(ctx context.Context, r *run) *agentv1.OperationResult {
	info, notes := e.System.Info(ctx)
	res := r.succeeded(strings.Join(notes, "; "))
	res.Data = &agentv1.OperationResult_SystemInfo{SystemInfo: info}
	return res
}

func (e *Executor) applyInventory(ctx context.Context, r *run) *agentv1.OperationResult {
	inv, notes := e.System.Inventory(ctx, r.body.GetParams().GetSystemInventory().GetInclude())
	res := r.succeeded(strings.Join(notes, "; "))
	res.Data = &agentv1.OperationResult_SystemInventory{SystemInventory: inv}
	return res
}

// ---------- Изменение с точкой отката CONFIG ----------

// configChange — изменение файлов: точка отката, (автооткат), применение, проверка.
type configChange struct {
	paths    []string
	services []string
	apply    func() error
	verify   func() error
}

func (e *Executor) runConfigChange(ctx context.Context, r *run, c configChange) *agentv1.OperationResult {
	op := strings.ToLower(r.body.GetOperationId())
	r.phase = agentv1.OperationPhase_OPERATION_PHASE_ROLLBACK_POINT
	m, err := e.Rollback.Create(op, c.paths, c.services)
	if err != nil {
		r.system("Точка отката не создана: %v", err)
		return r.failed(CodeRollbackUnavailable, err.Error())
	}
	point := &agentv1.RollbackPoint{
		Kind: agentv1.RollbackKind_ROLLBACK_KIND_CONFIG, Ref: filepath.Join(e.Rollback.Dir, op),
		Files: uint32(len(m.Files)), Bytes: uint64(m.TotalBytes),
	}
	r.system("Сохранена копия: файлов %d", len(m.Files))
	cw := time.Duration(r.body.GetConfirmWithinSec()) * time.Second
	if cw > 0 {
		if err := e.armAuto(ctx, op, autorollback.KindConfig, cw); err != nil {
			r.system("Таймер автооткатa не заведён: %v", err)
			res := r.failed(CodeRollbackUnavailable, "таймер автооткатa: "+err.Error())
			res.RollbackPoint = point
			return res
		}
	}
	undo := func(code, why string) *agentv1.OperationResult {
		r.phase = agentv1.OperationPhase_OPERATION_PHASE_ROLLBACK
		r.system("%s; возвращаю прежнее состояние", why)
		if cw > 0 {
			e.disarmAuto(ctx, op)
		}
		var res *agentv1.OperationResult
		if _, rerr := e.Rollback.Restore(op); rerr != nil {
			res = r.failed(CodeRollbackFailed, why+"; возврат: "+rerr.Error())
		} else {
			if len(c.services) > 0 {
				if err := e.Services.Restart(ctx, c.services...); err != nil {
					r.system("Перезапуск служб после возврата: %v", err)
				}
			}
			res = r.rolledBack(code, why)
		}
		res.RollbackPoint = point
		return res
	}
	r.phase = agentv1.OperationPhase_OPERATION_PHASE_APPLY
	if err := c.apply(); err != nil {
		return undo(CodeApplyFailed, "Не удалось применить: "+err.Error())
	}
	if len(c.services) > 0 {
		if err := e.Services.Restart(ctx, c.services...); err != nil {
			return undo(CodeVerifyFailed, "Службы не перезапустились: "+err.Error())
		}
	}
	r.phase = agentv1.OperationPhase_OPERATION_PHASE_VERIFY
	if err := c.verify(); err != nil {
		return undo(CodeVerifyFailed, "Проверка не прошла: "+err.Error())
	}
	var res *agentv1.OperationResult
	if cw > 0 {
		r.phase = agentv1.OperationPhase_OPERATION_PHASE_AWAIT_CONFIRM
		r.system("Применено; жду подтверждения связи %d с", r.body.GetConfirmWithinSec())
		res = r.result(agentv1.OperationOutcome_OPERATION_OUTCOME_AWAITING_CONFIRM, "", "Применено, ждёт подтверждения")
	} else {
		res = r.succeeded("Применено и проверено")
	}
	res.RollbackPoint = point
	return res
}

// ---------- rollback.restore ----------

func (e *Executor) restoreTarget(r *run) (*rollback.Manifest, *agentv1.OperationResult) {
	target := strings.ToLower(r.body.GetParams().GetRollbackRestore().GetTargetOperationId())
	if rec, err := e.Auto.Get(target); err != nil || rec != nil {
		return nil, r.failed(CodeRollbackNotAvailable, "исходная операция ещё ждёт подтверждения")
	}
	m, err := e.Rollback.Load(target)
	if errors.Is(err, rollback.ErrNotFound) {
		return nil, r.failed(CodeRollbackNotAvailable, "точки отката нет или срок хранения вышел")
	}
	if err != nil {
		return nil, r.failed(CodeRollbackNotAvailable, err.Error())
	}
	return m, nil
}

func (e *Executor) previewRestore(_ context.Context, r *run) (*agentv1.Preview, *agentv1.OperationResult) {
	m, fail := e.restoreTarget(r)
	if fail != nil {
		return nil, fail
	}
	p := &agentv1.Preview{Summary: fmt.Sprintf("Вернутся файлов: %d", len(m.Files)), Services: m.Services}
	for _, f := range m.Files {
		kind := agentv1.FileChangeKind_FILE_CHANGE_KIND_MODIFY
		if !f.Existed {
			kind = agentv1.FileChangeKind_FILE_CHANGE_KIND_DELETE
		}
		p.Files = append(p.Files, &agentv1.FileChange{Path: f.Path, Kind: kind})
	}
	return p, nil
}

func (e *Executor) applyRestore(ctx context.Context, r *run) *agentv1.OperationResult {
	m, fail := e.restoreTarget(r)
	if fail != nil {
		return fail
	}
	paths := make([]string, 0, len(m.Files))
	for _, f := range m.Files {
		paths = append(paths, f.Path)
	}
	return e.runConfigChange(ctx, r, configChange{
		paths: paths, services: m.Services,
		apply: func() error {
			_, err := e.Rollback.Restore(m.OperationID)
			return err
		},
		// Хэши, права и владельцы равны сохранённым.
		verify: func() error {
			for _, f := range m.Files {
				if err := rollback.Matches(f); err != nil {
					return fmt.Errorf("%s: %w", f.Path, err)
				}
			}
			return nil
		},
	})
}

// ---------- agent.update ----------

func (e *Executor) previewUpdate(_ context.Context, r *run) (*agentv1.Preview, *agentv1.OperationResult) {
	v := r.body.GetParams().GetAgentUpdate().GetVersion()
	return &agentv1.Preview{
		Summary:  fmt.Sprintf("Агент %s → %s", e.Version, v),
		Services: []string{"trassa-agent.service", "trassa-helper.service"},
		Notes: []string{
			"Подпись выпуска и контрольные суммы проверяются до замены",
			"Если новая версия не выйдет на связь за 120 секунд, вернётся прежняя",
		},
	}, nil
}

func (e *Executor) applyUpdate(ctx context.Context, r *run) *agentv1.OperationResult {
	p := r.body.GetParams().GetAgentUpdate()
	op := strings.ToLower(r.body.GetOperationId())
	cmp, err := update.Compare(p.GetVersion(), e.Version)
	if err != nil || cmp <= 0 {
		return r.failed(update.CodeDowngrade, fmt.Sprintf("Версия %s не новее текущей %s", p.GetVersion(), e.Version))
	}
	arts := map[string]*agentv1.ReleaseArtifact{}
	for _, a := range p.GetArtifacts() {
		if bin, ok := ops.ArtifactBinary(a); ok && a.GetArch() == runtime.GOARCH {
			arts[bin] = a
		}
	}
	for _, b := range binaries {
		if arts[b] == nil {
			return r.failed(update.CodeArtifactMissing, "В выпуске нет "+b+" для "+runtime.GOARCH)
		}
	}
	if e.Updater == nil || e.Updater.Verifier == nil {
		return r.failed(update.CodeSignatureInvalid, "В сборке нет ключей выпуска: обновление не ставится")
	}
	client := e.Updater.Client
	r.system("Скачиваю подпись и контрольные суммы")
	sig, err := update.Fetch(ctx, client, p.GetSignatureUrl(), maxSignature)
	if err != nil {
		return r.failed(update.CodeDownloadFailed, err.Error())
	}
	sumsURL := strings.TrimSuffix(p.GetSignatureUrl(), ".minisig")
	sums, err := update.Fetch(ctx, client, sumsURL, maxSums)
	if err != nil {
		return r.failed(update.CodeDownloadFailed, err.Error())
	}
	if err := e.Updater.Verifier.VerifySums(sums, sig, p.GetVersion()); err != nil {
		return r.failed(update.CodeSignatureInvalid, "Подпись выпуска не сошлась")
	}
	table, err := update.ParseSums(sums)
	if err != nil {
		return r.failed(update.CodeSignatureInvalid, err.Error())
	}
	files := map[string][]byte{}
	for _, b := range binaries {
		a := arts[b]
		u, _ := url.Parse(a.GetUrl())
		if table[path.Base(u.Path)] != a.GetSha256() {
			return r.failed(update.CodeSignatureInvalid, b+": сумма не совпала с подписанным SHA256SUMS")
		}
		r.system("Скачиваю %s", b)
		data, err := update.Fetch(ctx, client, a.GetUrl(), maxBinary)
		if err != nil {
			return r.failed(update.CodeDownloadFailed, err.Error())
		}
		if update.SHA256Hex(data) != a.GetSha256() {
			return r.failed(update.CodeSignatureInvalid, b+": контрольная сумма не совпала")
		}
		files[b] = data
	}
	// Сторож заводится до замены: даже если помощник упадёт сразу после rename, прежняя версия вернётся.
	if err := e.armAuto(ctx, op, autorollback.KindUpdate, UpdateWatchdog); err != nil {
		return r.failed(CodeRollbackUnavailable, "сторож обновления: "+err.Error())
	}
	fail := func(code, msg string) *agentv1.OperationResult {
		if rerr := e.restorePrevBinaries(ctx); rerr != nil {
			msg += "; возврат: " + rerr.Error()
			code = CodeRollbackFailed
		}
		e.disarmAuto(ctx, op)
		return r.failed(code, msg)
	}
	if err := update.Install(e.Paths.BinDir, e.Paths.BinPrevDir, files); err != nil {
		return fail("UPDATE_INSTALL_FAILED", err.Error())
	}
	// Перезапуск — во временном юните через 3 с: итог успевает уйти, а остановка помощника не обрывает команду.
	if err := e.Services.Schedule(ctx, "trassa-update-restart-"+op, 3*time.Second,
		"/usr/bin/systemctl", "restart", "trassa-helper.service", "trassa-agent.service"); err != nil {
		return fail("UPDATE_INSTALL_FAILED", "перезапуск: "+err.Error())
	}
	r.phase = agentv1.OperationPhase_OPERATION_PHASE_AWAIT_CONFIRM
	r.system("Версия %s установлена; жду её выхода на связь", p.GetVersion())
	return r.result(agentv1.OperationOutcome_OPERATION_OUTCOME_AWAITING_CONFIRM, "", "Новая версия запускается")
}

func (e *Executor) restorePrevBinaries(ctx context.Context) error {
	if err := update.RestorePrev(e.Paths.BinDir, e.Paths.BinPrevDir, binaries); err != nil {
		return err
	}
	return e.Services.Schedule(ctx, "trassa-update-revert-"+fmt.Sprint(e.now().Unix()), 2*time.Second,
		"/usr/bin/systemctl", "restart", "trassa-helper.service", "trassa-agent.service")
}

// ---------- agent.uninstall ----------

func (e *Executor) previewUninstall(_ context.Context, r *run) (*agentv1.Preview, *agentv1.OperationResult) {
	plan := uninstall.Plan(e.Paths, r.body.GetParams().GetAgentUninstall().GetPurgeRollback())
	p := &agentv1.Preview{Summary: "Агент Trassa будет удалён с сервера", Services: plan.Units, Notes: []string{"Пользователь " + plan.User + " будет удалён", "Отменить удаление нельзя"}}
	for _, f := range plan.Paths {
		p.Files = append(p.Files, &agentv1.FileChange{Path: f, Kind: agentv1.FileChangeKind_FILE_CHANGE_KIND_DELETE})
	}
	if !plan.PurgeRollback {
		p.Notes = append(p.Notes, "Точки отката останутся в "+e.Paths.RollbackDir)
	}
	return p, nil
}

func (e *Executor) applyUninstall(ctx context.Context, r *run) *agentv1.OperationResult {
	argv := []string{filepath.Join(e.Paths.BinDir, "trassa-helper"), "uninstall"}
	if r.body.GetParams().GetAgentUninstall().GetPurgeRollback() {
		argv = append(argv, "--purge-rollback")
	}
	// Удаление — во временном юните через 5 с: итог успевает уйти до разрыва связи (раздел 6).
	if err := e.Services.Schedule(ctx, "trassa-uninstall", 5*time.Second, argv...); err != nil {
		return r.failed(CodeApplyFailed, redact.Text(err.Error()))
	}
	r.system("Удаление начнётся через 5 секунд")
	return r.succeeded("Агент удаляется")
}
