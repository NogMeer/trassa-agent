// SPDX-License-Identifier: AGPL-3.0-only

package helper

import (
	"context"
	"errors"
	"path/filepath"
	"strings"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/imageupdate"
	"github.com/NogMeer/trassa-agent/internal/ops"
	"github.com/NogMeer/trassa-agent/internal/rollback"
)

// CodeContainerUpdateUnavailable — container.update на этой сборке не настроен.
const CodeContainerUpdateUnavailable = "CONTAINER_UPDATE_UNAVAILABLE"

var errBackup = errors.New("backup")

func (e *Executor) containerHandlers() map[string]handler {
	return map[string]handler{ops.TypeContainerUpdate: {apply: e.applyContainerUpdate}}
}

func containerUpdateCode(err error) string {
	switch {
	case errors.Is(err, imageupdate.ErrRollbackFailed):
		return CodeRollbackFailed
	case errors.Is(err, errBackup):
		return CodeRollbackUnavailable
	}
	for _, known := range imageupdate.Codes {
		if errors.Is(err, known) {
			return known.Error()
		}
	}
	return CodeApplyFailed
}

// applyContainerUpdate — container.update: копия изменяемого файла — в каталоге точек отката помощника (возврат
// внутри операции, вид RELEASE), шаги — в журнал операции.
func (e *Executor) applyContainerUpdate(ctx context.Context, r *run) *agentv1.OperationResult {
	if e.Images == nil {
		return r.failed(CodeContainerUpdateUnavailable, "обновление образов на этом сервере недоступно")
	}
	op := strings.ToLower(r.body.GetOperationId())
	var point *agentv1.RollbackPoint
	hooks := imageupdate.Hooks{
		Log: r.system,
		Backup: func(paths []string) error {
			r.phase = agentv1.OperationPhase_OPERATION_PHASE_ROLLBACK_POINT
			m, err := e.Rollback.CreateState(op, paths, nil, rollback.State{})
			if err != nil {
				return errors.Join(errBackup, err)
			}
			point = &agentv1.RollbackPoint{Kind: agentv1.RollbackKind_ROLLBACK_KIND_RELEASE, Ref: filepath.Join(e.Rollback.Dir, op),
				Files: uint32(len(m.Files)), Bytes: uint64(m.TotalBytes)}
			r.phase = agentv1.OperationPhase_OPERATION_PHASE_APPLY
			return nil
		},
		Restore: func() error {
			r.phase = agentv1.OperationPhase_OPERATION_PHASE_ROLLBACK
			_, err := e.Rollback.Restore(op)
			return err
		},
	}
	out, err := e.Images.Update(ctx, r.body.GetParams().GetContainerUpdate(), hooks)
	var res *agentv1.OperationResult
	switch {
	case err == nil:
		res = r.succeeded("Образ обновлён: " + out.GetNewImage())
	case out.GetRolledBack():
		res = r.rolledBack(containerUpdateCode(err), err.Error())
	default:
		res = r.failed(containerUpdateCode(err), err.Error())
	}
	res.RollbackPoint = point
	res.Data = &agentv1.OperationResult_ContainerUpdate{ContainerUpdate: out}
	return res
}
