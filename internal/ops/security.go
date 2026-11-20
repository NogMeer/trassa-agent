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

// FixPrefix — тип исправления: security.fix.<код проверки>.
const FixPrefix = "security.fix."

// destructiveFixes — исправления класса DESTRUCTIVE по каталогу E10 (остальные — CHANGE).
var destructiveFixes = map[string]bool{"USER_EMPTY_PASSWORD": true, "USER_SERVICE_SHELL": true}

func securitySpecs() []Spec {
	var fixes []Spec
	for _, code := range security.FixCodes() {
		class := Change
		if destructiveFixes[code] {
			class = Destructive
		}
		fixes = append(fixes, Spec{
			Type: FixPrefix + code, Class: class, Rollback: agentv1.RollbackKind_ROLLBACK_KIND_CONFIG,
			match: func(p *agentv1.OperationParams) bool { return p.GetSecurityFix() != nil },
			Validate: func(b *agentv1.OperationBody) error {
				return security.ValidateFix(code, b.GetParams().GetSecurityFix())
			},
		})
	}
	return append(fixes, []Spec{
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
	}...)
}
