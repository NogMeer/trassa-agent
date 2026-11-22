// SPDX-License-Identifier: AGPL-3.0-only

package helper

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/config"
	"github.com/NogMeer/trassa-agent/internal/fsutil"
	"github.com/NogMeer/trassa-agent/internal/helperrpc"
	"github.com/NogMeer/trassa-agent/internal/ops"
	"github.com/NogMeer/trassa-agent/internal/redact"
	"github.com/NogMeer/trassa-agent/internal/verify"
)

// Коды перевода в другую панель (E24-T20).
const (
	CodeRebindRolledBack = "REBIND_ROLLED_BACK"
	CodeRebindInProgress = "REBIND_IN_PROGRESS"
	maxRebindDetail      = 300
)

// RebindState — перевод ждёт подтверждения новой панелью (helper/rebind.json, root 0600). Агент читает его через
// helperrpc rebind.state: id операции для Hello и адрес, на котором ждать подтверждения. Failure — что агент
// успел увидеть (для итога возврата); без него возврат по сроку — NO_CONFIRM.
type RebindState struct {
	OperationID    string `json:"operation_id"`
	GatewayURL     string `json:"gateway_url"`
	PrevGatewayURL string `json:"prev_gateway_url"`
	AppliedAtMs    int64  `json:"applied_at_ms"`
	DeadlineMs     int64  `json:"deadline_ms"`
	Failure        int32  `json:"failure,omitempty"`
	Detail         string `json:"detail,omitempty"`
}

func (e *Executor) rebindPath() string { return filepath.Join(e.Paths.HelperDir, "rebind.json") }

// LoadRebind — действующий перевод или nil.
func (e *Executor) LoadRebind() (*RebindState, error) {
	raw, err := fsutil.ReadLimited(e.rebindPath(), 16<<10)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var s RebindState
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

func (e *Executor) saveRebind(s *RebindState) error {
	raw, _ := json.Marshal(s)
	return fsutil.WriteFileAtomic(e.rebindPath(), raw, 0o600, fsutil.Keep)
}

func (e *Executor) dropRebind() {
	if err := os.Remove(e.rebindPath()); err != nil && !errors.Is(err, fs.ErrNotExist) {
		e.log().Warn("helper: rebind.json не удалён", "err", err)
	}
}

// reloadPanelKeys — ключи проверки подписи из записи о регистрации: после перевода — новой панели, после возврата —
// прежней. Запись не читается — ключи не меняются (и это видно в журнале).
func (e *Executor) reloadPanelKeys() {
	_, keys, err := config.LoadEnrollment(e.Paths.Enrollment)
	if err != nil {
		e.log().Error("helper: запись о регистрации не прочитана, ключи панели прежние", "err", err)
		return
	}
	e.Checker.SetPanelKeys(keys)
}

func (e *Executor) rebindHandlers() map[string]handler {
	return map[string]handler{ops.TypeAgentRebind: {preview: e.previewRebind, apply: e.applyRebind}}
}

func keyPrints(keys []verify.PanelKey) string {
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		sum := sha256.Sum256(k.PublicKey)
		out = append(out, k.ID+" "+hex.EncodeToString(sum[:8]))
	}
	return strings.Join(out, ", ")
}

func (e *Executor) previewRebind(_ context.Context, r *run) (*agentv1.Preview, *agentv1.OperationResult) {
	p := r.body.GetParams().GetAgentRebind()
	en, _, err := config.LoadEnrollment(e.Paths.Enrollment)
	if err != nil {
		return nil, r.failed(CodeApplyFailed, "запись о регистрации не прочитана")
	}
	keys, _ := ops.RebindKeys(p)
	return &agentv1.Preview{
		Summary: "Перевод агента в другую панель: " + en.GatewayURL + " → " + p.GetGatewayUrl(),
		Files:   []*agentv1.FileChange{{Path: e.Paths.Enrollment, Kind: agentv1.FileChangeKind_FILE_CHANGE_KIND_MODIFY}},
		Notes: []string{
			"Ключи новой панели (sha256, первые 8 байт): " + keyPrints(keys),
			fmt.Sprintf("Без подтверждения новой панелью за %d с агент вернётся к прежней", r.body.GetConfirmWithinSec()),
		},
	}, nil
}

// applyRebind — новая запись о регистрации с точкой отката CONFIG и автооткатом: итог AWAITING_CONFIRM уходит в
// прежнюю панель, агент переподключается к новой, подтверждение (SignedConfirm этой операции) принимается только
// ключом новой панели.
func (e *Executor) applyRebind(ctx context.Context, r *run) *agentv1.OperationResult {
	p := r.body.GetParams().GetAgentRebind()
	if cur, err := e.LoadRebind(); err != nil || cur != nil {
		return r.failed(CodeRebindInProgress, "предыдущий перевод ещё не завершён")
	}
	keys, err := ops.RebindKeys(p)
	if err != nil {
		return r.failed(ops.CodeParamsInvalid, err.Error())
	}
	path := e.Paths.Enrollment
	en, _, err := config.LoadEnrollment(path)
	if err != nil {
		return r.failed(CodeApplyFailed, "запись о регистрации не прочитана")
	}
	next, err := en.Rebound(p.GetGatewayUrl(), keys)
	if err != nil {
		return r.failed(ops.CodeParamsInvalid, err.Error())
	}
	owner := fsutil.Owner{UID: 0, GID: 0}
	if fi, err := os.Stat(path); err == nil {
		if st, ok := fi.Sys().(*syscall.Stat_t); ok {
			owner = fsutil.Owner{UID: int(st.Uid), GID: int(st.Gid)}
		}
	}
	res := e.runConfigChange(ctx, r, configChange{
		paths: []string{path},
		apply: func() error { return config.SaveEnrollment(path, next, owner) },
		verify: func() error {
			got, _, err := config.LoadEnrollment(path)
			if err != nil {
				return err
			}
			if got.GatewayURL != next.GatewayURL || got.ServerID != en.ServerID {
				return errors.New("запись о регистрации не совпала с записанной")
			}
			return nil
		},
	})
	if res.GetOutcome() != agentv1.OperationOutcome_OPERATION_OUTCOME_AWAITING_CONFIRM {
		return res
	}
	now := e.now()
	st := &RebindState{OperationID: strings.ToLower(r.body.GetOperationId()), GatewayURL: next.GatewayURL,
		PrevGatewayURL: en.GatewayURL, AppliedAtMs: now.UnixMilli(),
		DeadlineMs: now.Add(time.Duration(r.body.GetConfirmWithinSec()) * time.Second).UnixMilli()}
	if err := e.saveRebind(st); err != nil {
		// Без файла агент не узнает о переводе (Hello без id, отказ новой панели принял бы за отзыв): прежняя запись
		// возвращается сразу, перевод не начинается.
		e.log().Error("helper: rebind.json не записан", "err", err)
		op := st.OperationID
		if derr := e.Timer.Disarm(ctx, op); derr != nil {
			e.log().Warn("helper: таймер не снят", "op", op, "err", derr)
		}
		_ = e.Auto.Delete(op)
		if _, rerr := e.Rollback.Restore(op); rerr != nil {
			return r.failed(CodeRollbackFailed, "состояние перевода не записано; возврат записи: "+rerr.Error())
		}
		return r.rolledBack(CodeApplyFailed, "состояние перевода не записано: прежняя запись возвращена")
	}
	e.Checker.SetPanelKeys(keys)
	r.system("Новый адрес панели записан; жду подтверждения новой панелью %d с", r.body.GetConfirmWithinSec())
	return res
}

// rebindConfirmed — новая панель подтвердила: копия прежней записи удаляется (rollback.restore к ней невозможен).
func (e *Executor) rebindConfirmed(op string) {
	e.dropRebind()
	// Неотданные итоги прежней панели новой не достаются: они отмечаются как доставленные (вызывается под e.Lock).
	if states, err := e.States.List(); err == nil {
		for _, st := range states {
			if st.OperationID == op || st.Reported || st.Status != StatusDone {
				continue
			}
			st.Reported = true
			if err := e.States.Put(st); err != nil {
				e.log().Warn("helper: итог прежней панели не отмечен", "op", st.OperationID, "err", err)
			}
		}
	}
	if err := e.Rollback.Delete(op); err != nil {
		e.log().Warn("helper: точка отката перевода не удалена", "op", op, "err", err)
	}
}

// rebindRolledBack — итог возврата: REBIND_ROLLED_BACK с причиной (то, что видел агент, иначе NO_CONFIRM); ключи
// панели — снова из прежней записи. Отмена человеком (cancelled) сохраняет свой код CANCELLED.
func (e *Executor) rebindRolledBack(res *agentv1.OperationResult, cancelled bool) {
	failure, detail := agentv1.RebindFailure_REBIND_FAILURE_NO_CONFIRM, "новая панель не подтвердила перевод в срок"
	if st, _ := e.LoadRebind(); st != nil && st.Failure != 0 {
		failure, detail = agentv1.RebindFailure(st.Failure), st.Detail
	}
	if res.GetOutcome() == agentv1.OperationOutcome_OPERATION_OUTCOME_ROLLED_BACK && !cancelled {
		res.ErrorCode, res.Message = CodeRebindRolledBack, "Перевод не состоялся: агент вернулся к прежней панели"
	}
	res.Data = &agentv1.OperationResult_AgentRebind{AgentRebind: &agentv1.AgentRebindResult{Failure: failure, Detail: detail}}
	e.dropRebind()
	e.reloadPanelKeys()
}

// cleanDetail — описание сбоя от агента: без секретов, печатное, до 300 знаков.
func cleanDetail(s string) string {
	s = redact.Text(strings.ToValidUTF8(s, "?"))
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	if utf8.RuneCountInString(s) > maxRebindDetail {
		s = string([]rune(s)[:maxRebindDetail])
	}
	return s
}

// rebindFail — helperrpc rebind.fail: агент сообщает, что новая панель недоступна, сертификат не проверен или
// рукопожатие отклонено. now — вернуться сразу, не дожидаясь срока. Подписи не нужно: агент может только ускорить
// возврат к прежней панели, который и так наступит по таймеру помощника (сужение, не расширение).
func (e *Executor) rebindFail(ctx context.Context, req helperrpc.Request) string {
	failure := agentv1.RebindFailure(req.Reason)
	switch failure {
	case agentv1.RebindFailure_REBIND_FAILURE_UNREACHABLE, agentv1.RebindFailure_REBIND_FAILURE_TLS_UNTRUSTED,
		agentv1.RebindFailure_REBIND_FAILURE_HANDSHAKE_REJECTED:
	default:
		return ops.CodeParamsInvalid
	}
	unlock, err := e.Lock.Lock(ctx)
	if err != nil {
		return CodeInternal
	}
	defer unlock()
	st, err := e.LoadRebind()
	if err != nil {
		return CodeInternal
	}
	if st == nil || st.OperationID != strings.ToLower(req.OperationID) {
		return CodeConfirmUnknown
	}
	st.Failure, st.Detail = int32(failure), cleanDetail(req.Detail)
	if err := e.saveRebind(st); err != nil {
		return CodeInternal
	}
	if !req.Now {
		return ""
	}
	if err := e.rollbackAwaitingLocked(ctx, st.OperationID, false); err != nil {
		e.log().Error("helper: возврат перевода", "op", st.OperationID, "err", err)
		return CodeInternal
	}
	return ""
}
