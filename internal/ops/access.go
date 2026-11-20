// SPDX-License-Identifier: AGPL-3.0-only

package ops

import (
	"errors"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/access"
)

// Типы доступа (E16, раздел 6; decisions/E16-access.md). terminal.open — отдельным шагом.
const (
	TypeSSHCATrust              = "sshca.trust"
	TypeSSHCAUntrust            = "sshca.untrust"
	TypeAccessUserEnsure        = "access.user.ensure"
	TypeAccessUserRemove        = "access.user.remove"
	TypeAccessSessionsTerminate = "access.sessions.terminate"
	TypeAccessRescueGrant       = "access.rescue.grant"
	TypeAccessRescueRevoke      = "access.rescue.revoke"
	TypeAccessStateRead         = "access.state.read"
)

func accessCoded(err error) error {
	if errors.Is(err, access.ErrUserForbidden) {
		return &CodeError{Code: access.ErrUserForbidden.Error(), Err: err}
	}
	return err
}

// Класс расширения доступа (новый CA, пользователь, sudo, аварийный вход) — DESTRUCTIVE, сужения — CHANGE;
// для помощника оба меняют систему. Точный класс по параметрам считает панель (решение 6).
func accessSpecs() []Spec {
	none, config := agentv1.RollbackKind_ROLLBACK_KIND_NONE, agentv1.RollbackKind_ROLLBACK_KIND_CONFIG
	return []Spec{
		{
			Type: TypeSSHCATrust, Class: Destructive, Rollback: config,
			match:    func(p *agentv1.OperationParams) bool { return p.GetSshcaTrust() != nil },
			Validate: func(b *agentv1.OperationBody) error { return access.ValidateTrust(b.GetParams().GetSshcaTrust()) },
		},
		{
			Type: TypeSSHCAUntrust, Class: Change, Rollback: config,
			match:    func(p *agentv1.OperationParams) bool { return p.GetSshcaUntrust() != nil },
			Validate: func(b *agentv1.OperationBody) error { return access.ValidateUntrust(b.GetParams().GetSshcaUntrust()) },
		},
		{
			Type: TypeAccessUserEnsure, Class: Destructive, Rollback: config,
			match: func(p *agentv1.OperationParams) bool { return p.GetAccessUserEnsure() != nil },
			Validate: func(b *agentv1.OperationBody) error {
				return accessCoded(access.ValidateUserEnsure(b.GetParams().GetAccessUserEnsure()))
			},
		},
		{
			Type: TypeAccessUserRemove, Class: Change, Rollback: config,
			match: func(p *agentv1.OperationParams) bool { return p.GetAccessUserRemove() != nil },
			Validate: func(b *agentv1.OperationBody) error {
				return accessCoded(access.ValidateUserRemove(b.GetParams().GetAccessUserRemove()))
			},
		},
		{
			Type: TypeAccessSessionsTerminate, Class: Change, Rollback: none,
			match: func(p *agentv1.OperationParams) bool { return p.GetAccessSessionsTerminate() != nil },
			Validate: func(b *agentv1.OperationBody) error {
				return access.ValidateTerminate(b.GetParams().GetAccessSessionsTerminate())
			},
		},
		{
			Type: TypeAccessRescueGrant, Class: Destructive, Rollback: config,
			match: func(p *agentv1.OperationParams) bool { return p.GetAccessRescueGrant() != nil },
			Validate: func(b *agentv1.OperationBody) error {
				return access.ValidateRescueGrant(b.GetParams().GetAccessRescueGrant(), b.GetIssuedAtMs())
			},
		},
		{
			Type: TypeAccessRescueRevoke, Class: Change, Rollback: config,
			match:    func(p *agentv1.OperationParams) bool { return p.GetAccessRescueRevoke() != nil },
			Validate: func(*agentv1.OperationBody) error { return nil },
		},
		{
			Type: TypeAccessStateRead, Class: Read, Rollback: none,
			match:    func(p *agentv1.OperationParams) bool { return p.GetAccessStateRead() != nil },
			Validate: func(*agentv1.OperationBody) error { return nil },
		},
	}
}
