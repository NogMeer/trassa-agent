// SPDX-License-Identifier: AGPL-3.0-only

package ops

import (
	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/security"
)

// Типы центра безопасности (E10, раздел 6), блок только чтения.
const (
	TypeSecurityScan        = "security.scan"
	TypePackagesListUpdates = "packages.list_updates"
)

func securitySpecs() []Spec {
	return []Spec{
		{
			Type: TypeSecurityScan, Class: Read, Rollback: agentv1.RollbackKind_ROLLBACK_KIND_NONE,
			match:    func(p *agentv1.OperationParams) bool { return p.GetSecurityScan() != nil },
			Validate: func(b *agentv1.OperationBody) error { return security.ValidateParams(b.GetParams().GetSecurityScan()) },
		},
		{
			Type: TypePackagesListUpdates, Class: Read, Rollback: agentv1.RollbackKind_ROLLBACK_KIND_NONE,
			match:    func(p *agentv1.OperationParams) bool { return p.GetPackagesListUpdates() != nil },
			Validate: func(*agentv1.OperationBody) error { return nil },
		},
	}
}
