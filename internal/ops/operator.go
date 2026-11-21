// SPDX-License-Identifier: AGPL-3.0-only

package ops

import (
	"errors"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/fsinspect"
	"github.com/NogMeer/trassa-agent/internal/helper/execrun"
)

// Типы ИИ-оператора (E20, раздел 6).
const (
	TypeDiskUsage  = "disk.usage"
	TypeConfigRead = "config.read"
	TypeExecRun    = "exec.run"
)

// inspectCoded — путь вне списка отклоняется своим кодом (DISK_PATH_FORBIDDEN, CONFIG_PATH_FORBIDDEN).
func inspectCoded(err error) error {
	if c := fsinspect.Code(err); c != "" {
		return &CodeError{Code: c, Err: err}
	}
	return err
}

func operatorSpecs() []Spec {
	return []Spec{
		{
			Type: TypeDiskUsage, Class: Read, Rollback: agentv1.RollbackKind_ROLLBACK_KIND_NONE,
			match: func(p *agentv1.OperationParams) bool { return p.GetDiskUsage() != nil },
			Validate: func(b *agentv1.OperationBody) error {
				return inspectCoded(fsinspect.ValidateDiskUsage(b.GetParams().GetDiskUsage()))
			},
		},
		{
			Type: TypeConfigRead, Class: Read, Rollback: agentv1.RollbackKind_ROLLBACK_KIND_NONE,
			match: func(p *agentv1.OperationParams) bool { return p.GetConfigRead() != nil },
			Validate: func(b *agentv1.OperationBody) error {
				return inspectCoded(fsinspect.ValidateConfigRead(b.GetParams().GetConfigRead()))
			},
		},
		{
			// SNAPSHOT обязателен (R13): снапшот хостера снимает панель до подписи. Флаг allow_exec и запреты R28
			// проверяет обработчик: флаг — раньше всего остального.
			Type: TypeExecRun, Class: Destructive, Rollback: agentv1.RollbackKind_ROLLBACK_KIND_SNAPSHOT,
			match: func(p *agentv1.OperationParams) bool { return p.GetExecRun() != nil },
			Validate: func(b *agentv1.OperationBody) error {
				err := execrun.Validate(b.GetParams().GetExecRun())
				for _, c := range []error{execrun.ErrUserInvalid, execrun.ErrCwdInvalid} {
					if errors.Is(err, c) {
						return &CodeError{Code: c.Error(), Err: err}
					}
				}
				return err
			},
		},
	}
}
