// SPDX-License-Identifier: AGPL-3.0-only

package channel

import (
	"context"

	"google.golang.org/protobuf/proto"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
)

// Canceler — помощник принимает подписанную отмену (E17, E10-T14). Итог отката ожидающей операции
// возвращается сразу; для релиза и сборки — пусто (итог придёт с операцией).
type Canceler interface {
	Cancel(ctx context.Context, signed []byte) ([]byte, error)
}

// cancelOperation — SignedCancel уходит помощнику как есть: агент без прав не решает, отменять ли.
// Итог отката ожидающей операции (ROLLED_BACK с CANCELLED) уходит панели сразу, как итог подтверждения; отказ
// (CANCEL_TOO_LATE) — только в журнале агента: кадра ответа на отмену в протоколе нет.
func (a *Agent) cancelOperation(sctx context.Context, c *conn, r *agentv1.SignedCancel) {
	h, ok := a.cfg.Helper.(Canceler)
	if !ok {
		a.cfg.Log.Warn("отмена: помощник не поддерживает")
		return
	}
	raw, err := proto.Marshal(r)
	if err != nil {
		return
	}
	res, err := h.Cancel(context.WithoutCancel(sctx), raw)
	if err != nil {
		a.cfg.Log.Warn("отмена отклонена помощником", "err", err)
		return
	}
	if len(res) > 0 {
		a.deliver(sctx, c, res)
	}
}
