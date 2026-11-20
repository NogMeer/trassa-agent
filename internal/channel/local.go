// SPDX-License-Identifier: AGPL-3.0-only

package channel

import (
	"context"
	"errors"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/netcheck"
	"github.com/NogMeer/trassa-agent/internal/nonce"
	"github.com/NogMeer/trassa-agent/internal/opcheck"
	"github.com/NogMeer/trassa-agent/internal/ops"
)

// Local — операции, которые исполняет сам агент (ops.Agent): те же проверки 1–6 (opcheck) и своё окно nonce в
// каталоге агента. Итог хранится в памяти до квитанции; после перезапуска агента повтор той же операции
// выполняется снова (операции только читают).
type Local struct {
	Checker *opcheck.Checker
	Nonces  *nonce.Store
}

func (l *Local) handles(t string) bool {
	if l == nil || l.Checker == nil {
		return false
	}
	_, ok := l.Checker.Catalog.Lookup(t)
	return ok
}

// localOperation — проверка, запись nonce до выполнения, выполнение, итог через outbox.
func (a *Agent) localOperation(sctx context.Context, c *conn, raw []byte, opID string, ack func(bool, string)) {
	l := a.cfg.Local
	checked, rej := l.Checker.Operation(raw)
	if rej != nil {
		a.cfg.Log.Warn("операция отклонена", "op", opID, "code", rej.Code, "detail", rej.Detail)
		ack(false, rej.Code)
		return
	}
	b := checked.Body
	op := strings.ToLower(b.GetOperationId())
	if err := l.Nonces.Record(b.GetNonce(), op, time.UnixMilli(b.GetNotAfterMs())); err != nil {
		if errors.Is(err, nonce.ErrReplay) {
			ack(false, ops.CodeReplay)
			return
		}
		a.cfg.Log.Error("окно nonce агента", "err", err)
		ack(false, ops.CodeParamsInvalid)
		return
	}
	ack(true, "")
	started := a.cfg.Now()
	res := &agentv1.OperationResult{OperationId: b.GetOperationId(), StartedAtMs: started.UnixMilli()}
	switch b.GetType() {
	case ops.TypeNetCheck:
		res.Data = &agentv1.OperationResult_NetCheck{NetCheck: netcheck.Run(context.WithoutCancel(sctx), b.GetParams().GetNetCheck())}
		res.Outcome = agentv1.OperationOutcome_OPERATION_OUTCOME_SUCCEEDED
	default:
		res.Outcome = agentv1.OperationOutcome_OPERATION_OUTCOME_FAILED
		res.ErrorCode = ops.CodeTypeUnknown
	}
	res.FinishedAtMs = a.cfg.Now().UnixMilli()
	out, err := proto.Marshal(res)
	if err != nil {
		return
	}
	a.ob.markLocal(res.GetOperationId())
	a.deliver(sctx, c, out)
}
