// SPDX-License-Identifier: AGPL-3.0-only

package ops

import (
	"errors"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/wireguard"
)

// Типы приватной сети (E14, раздел 6). wireguard.rollout — операция панели, в списке помощника её нет.
const (
	TypeWireguardInspect = "wireguard.inspect"
	TypeWireguardKeygen  = "wireguard.keygen"
	TypeWireguardApply   = "wireguard.apply"
	TypeWireguardRemove  = "wireguard.remove"
)

func wireguardSpecs() []Spec {
	needConfirm := func(b *agentv1.OperationBody) error {
		// Без автоотката менять сеть нельзя (R14): потеря доступа должна возвращаться сама.
		if b.GetConfirmWithinSec() == 0 {
			return errors.New("confirm_within_sec обязателен")
		}
		return nil
	}
	return []Spec{
		{
			Type: TypeWireguardInspect, Class: Read, Rollback: agentv1.RollbackKind_ROLLBACK_KIND_NONE,
			match: func(p *agentv1.OperationParams) bool { return p.GetWireguardInspect() != nil },
			Validate: func(b *agentv1.OperationBody) error {
				return wireguard.ValidateInspect(b.GetParams().GetWireguardInspect())
			},
		},
		{
			Type: TypeWireguardKeygen, Class: Change, Rollback: agentv1.RollbackKind_ROLLBACK_KIND_NONE,
			match: func(p *agentv1.OperationParams) bool { return p.GetWireguardKeygen() != nil },
			Validate: func(b *agentv1.OperationBody) error {
				return wireguard.ValidateKeygen(b.GetParams().GetWireguardKeygen())
			},
		},
		{
			Type: TypeWireguardApply, Class: Destructive, Rollback: agentv1.RollbackKind_ROLLBACK_KIND_CONFIG, AutoRollback: true,
			match: func(p *agentv1.OperationParams) bool { return p.GetWireguardApply() != nil },
			Validate: func(b *agentv1.OperationBody) error {
				if err := needConfirm(b); err != nil {
					return err
				}
				return wireguard.ValidateApply(b.GetParams().GetWireguardApply())
			},
		},
		{
			Type: TypeWireguardRemove, Class: Destructive, Rollback: agentv1.RollbackKind_ROLLBACK_KIND_CONFIG, AutoRollback: true,
			match: func(p *agentv1.OperationParams) bool { return p.GetWireguardRemove() != nil },
			Validate: func(b *agentv1.OperationBody) error {
				if err := needConfirm(b); err != nil {
					return err
				}
				return wireguard.ValidateRemove(b.GetParams().GetWireguardRemove())
			},
		},
	}
}
