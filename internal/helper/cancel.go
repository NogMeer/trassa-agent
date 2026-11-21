// SPDX-License-Identifier: AGPL-3.0-only

package helper

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/autorollback"
	"github.com/NogMeer/trassa-agent/internal/deploy"
	"github.com/NogMeer/trassa-agent/internal/nonce"
	"github.com/NogMeer/trassa-agent/internal/opcheck"
	"github.com/NogMeer/trassa-agent/internal/verify"
)

// Коды отмены (E17).
const (
	CodeCancelled     = "CANCELLED"
	CodeCancelTooLate = "CANCEL_TOO_LATE"
	CodeCancelInvalid = "CANCEL_INVALID"
	CodeCancelUnknown = "CANCEL_NOT_RUNNING"
	// CodeCancelUnsupported — отмена ожидающей операции этого вида не делается (agent.update).
	CodeCancelUnsupported = "CANCEL_UNSUPPORTED"
)

// errCancelled — причина отмены контекста операции.
var errCancelled = errors.New(CodeCancelled)

// cancelable — идущий релиз или сборка: отмена возможна до шага SWITCH.
type cancelable struct {
	mu       sync.Mutex
	cancel   context.CancelCauseFunc
	switched bool
}

// trackCancel — контекст операции op, который отменяет подписанная отмена; step отмечает SWITCH под тем же
// замком, что и проверка отмены: отмена и переключение не пересекаются.
func (e *Executor) trackCancel(ctx context.Context, op string, step deploy.Step) (context.Context, deploy.Step, func()) {
	ctx, cancel := context.WithCancelCause(ctx)
	c := &cancelable{cancel: cancel}
	op = strings.ToLower(op)
	e.mu.Lock()
	if e.cancels == nil {
		e.cancels = map[string]*cancelable{}
	}
	e.cancels[op] = c
	e.mu.Unlock()
	wrapped := func(s agentv1.DeployStep, attempt uint32) {
		if s == agentv1.DeployStep_DEPLOY_STEP_SWITCH {
			c.mu.Lock()
			if ctx.Err() == nil {
				c.switched = true
			}
			c.mu.Unlock()
		}
		step(s, attempt)
	}
	return ctx, wrapped, func() {
		e.mu.Lock()
		delete(e.cancels, op)
		e.mu.Unlock()
		cancel(nil)
	}
}

// cancelled — операция прервана подписанной отменой.
func cancelled(ctx context.Context) bool { return errors.Is(context.Cause(ctx), errCancelled) }

// Cancel — SignedCancel: подпись панели, этот сервер, срок, одноразовый nonce. Цель:
//   - идущий релиз или сборка E17 — отмена до шага SWITCH (итог придёт с операцией, ответ пустой);
//   - операция в ожидании подтверждения с автооткатом конфигурации (E10-T14, «Вернуть как было») — немедленный
//     откат тем же путём, что у таймера, под e.Lock; ответ — итог ROLLED_BACK с CANCELLED.
//
// Пустой код — отмена принята.
func (e *Executor) Cancel(ctx context.Context, raw []byte) ([]byte, string) {
	e.init()
	if e.Checker == nil {
		return nil, CodeCancelInvalid
	}
	var sc agentv1.SignedCancel
	if proto.Unmarshal(raw, &sc) != nil {
		return nil, CodeCancelInvalid
	}
	if verify.Signature(e.Checker.Keys, sc.GetKeyId(), verify.ContextCancel, sc.GetBody(), sc.GetSignature()) != nil {
		return nil, CodeCancelInvalid
	}
	var b agentv1.CancelBody
	if proto.Unmarshal(sc.GetBody(), &b) != nil {
		return nil, CodeCancelInvalid
	}
	now := e.now()
	notAfter := time.UnixMilli(b.GetNotAfterMs())
	if b.GetServerId() != e.Checker.ServerID || !notAfter.After(now) || notAfter.Sub(now) > opcheck.MaxNotAfter+opcheck.ClockTolerance ||
		len(b.GetNonce()) != opcheck.NonceSize {
		return nil, CodeCancelInvalid
	}
	op := strings.ToLower(b.GetOperationId())
	key := "cancel:" + op
	if e.Checker.Nonces.Check(b.GetNonce(), key) != nonce.Fresh || e.Checker.Nonces.Record(b.GetNonce(), key, notAfter) != nil {
		return nil, CodeCancelInvalid
	}
	e.mu.Lock()
	c := e.cancels[op]
	e.mu.Unlock()
	if c != nil {
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.switched {
			return nil, CodeCancelTooLate
		}
		c.cancel(errCancelled)
		return nil, ""
	}
	return e.cancelAwaiting(ctx, op)
}

// cancelAwaiting — «Вернуть как было» (E10-T14). Под той же блокировкой, что Confirm и таймер: подтверждение и
// отмена не пересекаются. Подтверждена — CANCEL_TOO_LATE; уже откачена таймером — её итог как есть.
func (e *Executor) cancelAwaiting(ctx context.Context, op string) ([]byte, string) {
	unlock, err := e.Lock.Lock(ctx)
	if err != nil {
		return nil, CodeInternal
	}
	defer unlock()
	st, err := e.States.Get(op)
	if err != nil {
		return nil, CodeInternal
	}
	rec, err := e.Auto.Get(op)
	if err != nil {
		return nil, CodeInternal
	}
	if st == nil {
		return nil, CodeCancelUnknown
	}
	if rec == nil {
		if st.Status == StatusDone && st.Outcome == int32(agentv1.OperationOutcome_OPERATION_OUTCOME_ROLLED_BACK) && len(st.Result) > 0 {
			return st.Result, ""
		}
		if st.Status == StatusDone {
			return nil, CodeCancelTooLate
		}
		return nil, CodeCancelUnknown
	}
	if st.Status != StatusAwaitingConfirm {
		return nil, CodeCancelUnknown
	}
	// Откат обновления агента по отмене не делается: его подтверждает сам агент, выйдя на связь.
	if rec.Kind != autorollback.KindConfig {
		return nil, CodeCancelUnsupported
	}
	if err := e.rollbackAwaitingLocked(ctx, op, true); err != nil {
		e.log().Error("helper: откат по отмене", "op", op, "err", err)
		return nil, CodeInternal
	}
	st, err = e.States.Get(op)
	if err != nil || st == nil {
		return nil, CodeInternal
	}
	return st.Result, ""
}
