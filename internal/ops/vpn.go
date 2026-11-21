// SPDX-License-Identifier: AGPL-3.0-only

package ops

import (
	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/vpnprobe"
)

// Типы точки замера VPN-пакета (E25, раздел 6).
const (
	TypeVpnProbeEnsure = "vpn.probe.ensure"
	TypeVpnProbeRun    = "vpn.probe.run"
)

func vpnSpecs() []Spec {
	return []Spec{
		{
			// CONFIG — файл действующих версий движка: откат возвращает прежнюю (её каталог остаётся на диске).
			Type: TypeVpnProbeEnsure, Class: Change, Rollback: agentv1.RollbackKind_ROLLBACK_KIND_CONFIG,
			match: func(p *agentv1.OperationParams) bool { return p.GetVpnProbeEnsure() != nil },
			Validate: func(b *agentv1.OperationBody) error {
				return vpnprobe.ValidateEnsure(b.GetParams().GetVpnProbeEnsure())
			},
		},
		{
			// Замер — до 10 минут: сеанс без общей очереди READ, предел одновременных — у обработчика (4).
			Type: TypeVpnProbeRun, Class: Read, Rollback: agentv1.RollbackKind_ROLLBACK_KIND_NONE, Session: true,
			match:    func(p *agentv1.OperationParams) bool { return p.GetVpnProbeRun() != nil },
			Validate: vpnprobe.ValidateRun,
		},
	}
}
