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

// Cancel — SignedCancel: подпись панели, этот сервер, срок, одноразовый nonce, операция идёт и ещё не
// переключила трафик. Пустой код — отмена принята.
func (e *Executor) Cancel(raw []byte) string {
	if e.Checker == nil {
		return CodeCancelInvalid
	}
	var sc agentv1.SignedCancel
	if proto.Unmarshal(raw, &sc) != nil {
		return CodeCancelInvalid
	}
	if verify.Signature(e.Checker.Keys, sc.GetKeyId(), verify.ContextCancel, sc.GetBody(), sc.GetSignature()) != nil {
		return CodeCancelInvalid
	}
	var b agentv1.CancelBody
	if proto.Unmarshal(sc.GetBody(), &b) != nil {
		return CodeCancelInvalid
	}
	now := e.now()
	notAfter := time.UnixMilli(b.GetNotAfterMs())
	if b.GetServerId() != e.Checker.ServerID || !notAfter.After(now) || notAfter.Sub(now) > opcheck.MaxNotAfter+opcheck.ClockTolerance ||
		len(b.GetNonce()) != opcheck.NonceSize {
		return CodeCancelInvalid
	}
	op := strings.ToLower(b.GetOperationId())
	key := "cancel:" + op
	if e.Checker.Nonces.Check(b.GetNonce(), key) != nonce.Fresh || e.Checker.Nonces.Record(b.GetNonce(), key, notAfter) != nil {
		return CodeCancelInvalid
	}
	e.mu.Lock()
	c := e.cancels[op]
	e.mu.Unlock()
	if c == nil {
		return CodeCancelUnknown
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.switched {
		return CodeCancelTooLate
	}
	c.cancel(errCancelled)
	return ""
}
