// SPDX-License-Identifier: AGPL-3.0-only

package ops

import (
	"errors"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/security"
)

// Типы центра безопасности (E10, раздел 6), блок только чтения.
const (
	TypeSecurityScan        = "security.scan"
	TypePackagesListUpdates = "packages.list_updates"
	TypeSSHHarden           = "ssh.harden"
	TypeFirewallPlan        = "firewall.plan"
	TypeFirewallApply       = "firewall.apply"
	TypePackagesUpgrade     = "packages.upgrade"
	TypeSystemReboot        = "system.reboot"
	TypeServiceRestart      = "service.restart"
	TypeBaselineAccept      = "security.baseline.accept"
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
			// Меняет только базовый список помощника, не систему.
			Type: TypeBaselineAccept, Class: Change, Rollback: agentv1.RollbackKind_ROLLBACK_KIND_NONE,
			match: func(p *agentv1.OperationParams) bool { return p.GetSecurityBaselineAccept() != nil },
			Validate: func(b *agentv1.OperationBody) error {
				return security.ValidateAccept(b.GetParams().GetSecurityBaselineAccept())
			},
		},
		{
			// Откат обновления — снапшот (E12) или согласие человека; точки CONFIG нет.
			Type: TypePackagesUpgrade, Class: Change, Rollback: agentv1.RollbackKind_ROLLBACK_KIND_NONE,
			match: func(p *agentv1.OperationParams) bool { return p.GetPackagesUpgrade() != nil },
			Validate: func(b *agentv1.OperationBody) error {
				switch b.GetParams().GetPackagesUpgrade().GetScope() {
				case agentv1.UpgradeScope_UPGRADE_SCOPE_SECURITY, agentv1.UpgradeScope_UPGRADE_SCOPE_ALL:
					return nil
				}
				return errors.New("scope")
			},
		},
		{
			Type: TypeSystemReboot, Class: Destructive, Rollback: agentv1.RollbackKind_ROLLBACK_KIND_NONE,
			match: func(p *agentv1.OperationParams) bool { return p.GetSystemReboot() != nil },
			Validate: func(b *agentv1.OperationBody) error {
				if b.GetParams().GetSystemReboot().GetDelaySeconds() > security.MaxRebootDelay {
					return errors.New("delay_seconds: до 3600")
				}
				return nil
			},
		},
		{
			Type: TypeServiceRestart, Class: Change, Rollback: agentv1.RollbackKind_ROLLBACK_KIND_NONE,
			match: func(p *agentv1.OperationParams) bool { return p.GetServiceRestart() != nil },
			Validate: func(b *agentv1.OperationBody) error {
				return security.ValidateServiceRestart(b.GetParams().GetServiceRestart())
			},
		},
		{
			Type: TypeFirewallPlan, Class: Read, Rollback: agentv1.RollbackKind_ROLLBACK_KIND_NONE,
			match: func(p *agentv1.OperationParams) bool { return p.GetFirewallPlan() != nil },
			Validate: func(b *agentv1.OperationBody) error {
				p := b.GetParams().GetFirewallPlan()
				switch p.GetMode() {
				case agentv1.FirewallPlanMode_FIREWALL_PLAN_MODE_IMPORT:
					return nil
				case agentv1.FirewallPlanMode_FIREWALL_PLAN_MODE_DIFF:
					return security.ValidateRuleset(p.GetRuleset())
				}
				return errors.New("mode")
			},
		},
		{
			Type: TypeFirewallApply, Class: Destructive, Rollback: agentv1.RollbackKind_ROLLBACK_KIND_CONFIG, AutoRollback: true,
			match: func(p *agentv1.OperationParams) bool { return p.GetFirewallApply() != nil },
			Validate: func(b *agentv1.OperationBody) error {
				if b.GetConfirmWithinSec() == 0 {
					return errors.New("confirm_within_sec обязателен")
				}
				p := b.GetParams().GetFirewallApply()
				switch p.GetMode() {
				case agentv1.FirewallApplyMode_FIREWALL_APPLY_MODE_REMOVE:
					return nil
				case agentv1.FirewallApplyMode_FIREWALL_APPLY_MODE_APPLY:
					if len(p.GetRulesetHash()) != 64 {
						return errors.New("ruleset_hash")
					}
					return security.ValidateRuleset(p.GetRuleset())
				}
				return errors.New("mode")
			},
		},
		{
			Type: TypeSSHHarden, Class: Destructive, Rollback: agentv1.RollbackKind_ROLLBACK_KIND_CONFIG, AutoRollback: true,
			match: func(p *agentv1.OperationParams) bool { return p.GetSshHarden() != nil },
			Validate: func(b *agentv1.OperationBody) error {
				// Без автоотката менять SSH нельзя (R14): потеря доступа должна возвращаться сама.
				if b.GetConfirmWithinSec() == 0 {
					return errors.New("confirm_within_sec обязателен")
				}
				return security.ValidateSSHHarden(b.GetParams().GetSshHarden())
			},
		},
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
