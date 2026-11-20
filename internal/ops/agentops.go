// SPDX-License-Identifier: AGPL-3.0-only

package ops

import (
	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/netcheck"
)

// TypeNetCheck — проверка связи (E07, раздел 6). Исполняет агент без прав: помощник в сеть не выходит.
const TypeNetCheck = "net.check"

// Agent — зашитый список типов, которые исполняет сам агент. Помощник их не знает; проверки 1–6 агент делает
// тем же кодом (opcheck), nonce пишет в своё окно.
func Agent() *Catalog {
	c, err := NewCatalog(Spec{
		Type: TypeNetCheck, Class: Read, Rollback: agentv1.RollbackKind_ROLLBACK_KIND_NONE,
		match:    func(p *agentv1.OperationParams) bool { return p.GetNetCheck() != nil },
		Validate: func(b *agentv1.OperationBody) error { return netcheck.Validate(b.GetParams().GetNetCheck()) },
	})
	if err != nil {
		panic(err)
	}
	return c
}
