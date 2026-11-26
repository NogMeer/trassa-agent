// SPDX-License-Identifier: AGPL-3.0-only

package ops

import (
	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/imageupdate"
)

// TypeContainerUpdate — смена тега образа сервиса docker compose (E10, рекомендации обновлений).
const TypeContainerUpdate = "container.update"

// containerSpecs — E10: откат RELEASE — прежний файл и прежний образ возвращаются внутри операции.
func containerSpecs() []Spec {
	return []Spec{{
		Type: TypeContainerUpdate, Class: Change, Rollback: agentv1.RollbackKind_ROLLBACK_KIND_RELEASE,
		match: func(p *agentv1.OperationParams) bool { return p.GetContainerUpdate() != nil },
		Validate: func(b *agentv1.OperationBody) error {
			return imageupdate.Validate(b.GetParams().GetContainerUpdate())
		},
	}}
}
