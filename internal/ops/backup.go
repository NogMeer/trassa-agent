// SPDX-License-Identifier: AGPL-3.0-only

package ops

import (
	"errors"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/backup"
)

// Типы бэкапов (E13, раздел 6; каталог панели — modules/backups/operation-catalog.ts).
const (
	TypeBackupInit         = "backup.init"
	TypeBackupRun          = "backup.run"
	TypeBackupVerify       = "backup.verify"
	TypeBackupRestore      = "backup.restore"
	TypeBackupDiscover     = "backup.sources.discover"
	TypeBackupSnapshots    = "backup.snapshots.list"
	TypeBackupBrowse       = "backup.snapshot.browse"
	TypeBackupPrune        = "backup.prune"
	TypeBackupTargetEnsure = "backup.target.ensure"
	TypeBackupTargetRemove = "backup.target.remove"
	TypeBackupUnconfigure  = "backup.unconfigure"
	TypeBackupRevokeReader = "backup.target.revoke_reader"
)

// pathCoded — запрещённый путь отклоняется своим кодом, а не общим PARAMS_INVALID.
func pathCoded(err error) error {
	switch {
	case errors.Is(err, backup.ErrPathForbidden):
		return &CodeError{Code: backup.CodePathForbidden, Err: err}
	case errors.Is(err, backup.ErrToolUnknown):
		return &CodeError{Code: backup.CodeToolUnknown, Err: err}
	}
	return err
}

func backupSpecs() []Spec {
	none, config := agentv1.RollbackKind_ROLLBACK_KIND_NONE, agentv1.RollbackKind_ROLLBACK_KIND_CONFIG
	return []Spec{
		{
			Type: TypeBackupInit, Class: Change, Rollback: config, Long: true,
			match: func(p *agentv1.OperationParams) bool { return p.GetBackupInit() != nil },
			Validate: func(b *agentv1.OperationBody) error {
				return pathCoded(backup.ValidateInit(b.GetParams().GetBackupInit()))
			},
		},
		{
			Type: TypeBackupRun, Class: Change, Rollback: none, Long: true,
			match: func(p *agentv1.OperationParams) bool { return p.GetBackupRun() != nil },
			Validate: func(b *agentv1.OperationBody) error {
				return pathCoded(backup.ValidateRun(b.GetParams().GetBackupRun()))
			},
		},
		{
			Type: TypeBackupVerify, Class: Change, Rollback: none, Long: true,
			match:    func(p *agentv1.OperationParams) bool { return p.GetBackupVerify() != nil },
			Validate: func(b *agentv1.OperationBody) error { return backup.ValidateVerify(b.GetParams().GetBackupVerify()) },
		},
		{
			// Класс по режиму (TEMP_DIR — CHANGE, остальное DESTRUCTIVE) считает панель; для помощника оба —
			// изменение. Восстановление на место меняет файлы системы: общая блокировка, не Long.
			Type: TypeBackupRestore, Class: Destructive,
			RollbackOf: func(b *agentv1.OperationBody) error {
				return backup.RestoreRollback(b.GetParams().GetBackupRestore(), b.GetRollback())
			},
			match: func(p *agentv1.OperationParams) bool { return p.GetBackupRestore() != nil },
			Validate: func(b *agentv1.OperationBody) error {
				return pathCoded(backup.ValidateRestore(b.GetParams().GetBackupRestore()))
			},
		},
		{
			Type: TypeBackupDiscover, Class: Read, Rollback: none,
			match:    func(p *agentv1.OperationParams) bool { return p.GetBackupDiscover() != nil },
			Validate: func(*agentv1.OperationBody) error { return nil },
		},
		{
			Type: TypeBackupSnapshots, Class: Read, Rollback: none,
			match: func(p *agentv1.OperationParams) bool { return p.GetBackupSnapshots() != nil },
			Validate: func(b *agentv1.OperationBody) error {
				return backup.ValidateSnapshots(b.GetParams().GetBackupSnapshots())
			},
		},
		{
			Type: TypeBackupBrowse, Class: Read, Rollback: none,
			match: func(p *agentv1.OperationParams) bool { return p.GetBackupBrowse() != nil },
			Validate: func(b *agentv1.OperationBody) error {
				return pathCoded(backup.ValidateBrowse(b.GetParams().GetBackupBrowse()))
			},
		},
		{
			Type: TypeBackupPrune, Class: Change, Rollback: none, Long: true,
			match:    func(p *agentv1.OperationParams) bool { return p.GetBackupPrune() != nil },
			Validate: func(b *agentv1.OperationBody) error { return backup.ValidatePrune(b.GetParams().GetBackupPrune()) },
		},
		{
			Type: TypeBackupTargetEnsure, Class: Destructive, Rollback: config,
			match: func(p *agentv1.OperationParams) bool { return p.GetBackupTargetEnsure() != nil },
			Validate: func(b *agentv1.OperationBody) error {
				p := b.GetParams().GetBackupTargetEnsure()
				if err := backup.ValidateTargetEnsure(p); err != nil {
					return pathCoded(err)
				}
				return backup.ReaderExpiry(p, b.GetIssuedAtMs())
			},
		},
		{
			Type: TypeBackupTargetRemove, Class: Destructive, Rollback: config,
			match: func(p *agentv1.OperationParams) bool { return p.GetBackupTargetRemove() != nil },
			Validate: func(b *agentv1.OperationBody) error {
				return pathCoded(backup.ValidateTargetRemove(b.GetParams().GetBackupTargetRemove()))
			},
		},
		{
			Type: TypeBackupRevokeReader, Class: Change, Rollback: config,
			match: func(p *agentv1.OperationParams) bool { return p.GetBackupTargetRevokeReader() != nil },
			Validate: func(b *agentv1.OperationBody) error {
				return backup.ValidateTargetRevokeReader(b.GetParams().GetBackupTargetRevokeReader())
			},
		},
		{
			Type: TypeBackupUnconfigure, Class: Change, Rollback: none, Long: true,
			match: func(p *agentv1.OperationParams) bool { return p.GetBackupUnconfigure() != nil },
			Validate: func(b *agentv1.OperationBody) error {
				return backup.ValidateUnconfigure(b.GetParams().GetBackupUnconfigure())
			},
		},
	}
}
