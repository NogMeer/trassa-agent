// SPDX-License-Identifier: AGPL-3.0-only

package ops

import (
	"errors"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/deploy"
)

// Типы деплоя (E17, раздел 6; decisions/E17-deploy.md).
const (
	TypeDockerEnsure    = "docker.ensure"
	TypeProxyEnsure     = "proxy.ensure"
	TypeProxyRouteApply = "proxy.route.apply"
	TypeDeployInspect   = "deploy.inspect"
	TypeDeployRelease   = "deploy.release"
	TypeDeployRollback  = "deploy.rollback"
	TypeDeployControl   = "deploy.control"
	TypeDeployRemove    = "deploy.remove"
	TypeDeployPrune     = "deploy.images.prune"
)

func deployCoded(err error) error {
	for _, e := range []error{deploy.ErrImageNotPinned, deploy.ErrToolUnknown} {
		if errors.Is(err, e) {
			return &CodeError{Code: e.Error(), Err: err}
		}
	}
	return err
}

func deploySpecs() []Spec {
	none, config := agentv1.RollbackKind_ROLLBACK_KIND_NONE, agentv1.RollbackKind_ROLLBACK_KIND_CONFIG
	release := agentv1.RollbackKind_ROLLBACK_KIND_RELEASE
	return []Spec{
		{
			Type: TypeDockerEnsure, Class: Change, Rollback: config,
			match: func(p *agentv1.OperationParams) bool { return p.GetDockerEnsure() != nil },
			Validate: func(b *agentv1.OperationBody) error {
				return deployCoded(deploy.ValidateDockerEnsure(b.GetParams().GetDockerEnsure()))
			},
		},
		{
			Type: TypeProxyEnsure, Class: Change, Rollback: config,
			match: func(p *agentv1.OperationParams) bool { return p.GetProxyEnsure() != nil },
			Validate: func(b *agentv1.OperationBody) error {
				return deployCoded(deploy.ValidateProxyEnsure(b.GetParams().GetProxyEnsure()))
			},
		},
		{
			Type: TypeProxyRouteApply, Class: Change, Rollback: config,
			match: func(p *agentv1.OperationParams) bool { return p.GetProxyRouteApply() != nil },
			Validate: func(b *agentv1.OperationBody) error {
				return deploy.ValidateRouteApply(b.GetParams().GetProxyRouteApply())
			},
		},
		{
			Type: TypeDeployInspect, Class: Read, Rollback: none,
			match:    func(p *agentv1.OperationParams) bool { return p.GetDeployInspect() != nil },
			Validate: func(b *agentv1.OperationBody) error { return deploy.ValidateInspect(b.GetParams().GetDeployInspect()) },
		},
		// Релиз и откат откатывают себя сами (RELEASE): до переключения убирается новый контейнер, после —
		// возвращается маршрут. Идут очередью деплоя без общей блокировки; маршруты пишутся под ней (RouteLock).
		{
			Type: TypeDeployRelease, Class: Change, Rollback: release, Long: true, Queue: QueueDeploy,
			match: func(p *agentv1.OperationParams) bool { return p.GetDeployRelease() != nil },
			Validate: func(b *agentv1.OperationBody) error {
				return deployCoded(deploy.ValidateRelease(b.GetParams().GetDeployRelease(), b.GetIssuedAtMs()))
			},
		},
		{
			Type: TypeDeployRollback, Class: Change, Rollback: release, Long: true, Queue: QueueDeploy,
			match: func(p *agentv1.OperationParams) bool { return p.GetDeployRollback() != nil },
			Validate: func(b *agentv1.OperationBody) error {
				return deployCoded(deploy.ValidateRollback(b.GetParams().GetDeployRollback(), b.GetIssuedAtMs()))
			},
		},
		{
			Type: TypeDeployControl, Class: Change, Rollback: none, Long: true, Queue: QueueDeploy,
			match: func(p *agentv1.OperationParams) bool { return p.GetDeployControl() != nil },
			Validate: func(b *agentv1.OperationBody) error {
				return deploy.ValidateControl(b.GetParams().GetDeployControl(), b.GetIssuedAtMs())
			},
		},
		{
			// С remove_data удаляются тома без возврата: класс по худшему случаю.
			Type: TypeDeployRemove, Class: Destructive, Rollback: none, Long: true, Queue: QueueDeploy,
			match:    func(p *agentv1.OperationParams) bool { return p.GetDeployRemove() != nil },
			Validate: func(b *agentv1.OperationBody) error { return deploy.ValidateRemove(b.GetParams().GetDeployRemove()) },
		},
		{
			Type: TypeDeployPrune, Class: Change, Rollback: none, Long: true, Queue: QueueDeploy,
			match: func(p *agentv1.OperationParams) bool { return p.GetDeployImagesPrune() != nil },
			Validate: func(b *agentv1.OperationBody) error {
				return deployCoded(deploy.ValidateImagesPrune(b.GetParams().GetDeployImagesPrune()))
			},
		},
	}
}
