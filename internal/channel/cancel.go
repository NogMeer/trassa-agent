// SPDX-License-Identifier: AGPL-3.0-only

package channel

import (
	"context"

	"google.golang.org/protobuf/proto"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
)

// Canceler — помощник принимает подписанную отмену (E17).
type Canceler interface {
	Cancel(ctx context.Context, signed []byte) error
}

// cancelOperation — SignedCancel уходит помощнику как есть: агент без прав не решает, отменять ли.
// Итог виден панели в итоге операции (ROLLED_BACK с CANCELLED); отказ (CANCEL_TOO_LATE) — только в журнале
// агента: кадра ответа на отмену в протоколе нет.
func (a *Agent) cancelOperation(ctx context.Context, r *agentv1.SignedCancel) {
	h, ok := a.cfg.Helper.(Canceler)
	if !ok {
		a.cfg.Log.Warn("отмена: помощник не поддерживает")
		return
	}
	raw, err := proto.Marshal(r)
	if err != nil {
		return
	}
	if err := h.Cancel(ctx, raw); err != nil {
		a.cfg.Log.Warn("отмена отклонена помощником", "err", err)
	}
}
