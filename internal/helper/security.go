// SPDX-License-Identifier: AGPL-3.0-only

package helper

import (
	"context"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/security"
)

// CodeSecurityUnavailable — проверки на этой сборке не выполняются.
const CodeSecurityUnavailable = "SECURITY_UNAVAILABLE"

// CodePackagesFailed — менеджер пакетов не ответил.
const CodePackagesFailed = "PACKAGES_FAILED"

// applySecurityScan — security.scan: проверки только чтением из зашитого списка (параметры уже сверены с ним).
func (e *Executor) applySecurityScan(ctx context.Context, r *run) *agentv1.OperationResult {
	if e.Security == nil {
		return r.failed(CodeSecurityUnavailable, "проверки безопасности на этой сборке не выполняются")
	}
	res := r.succeeded("")
	res.Data = &agentv1.OperationResult_SecurityScan{SecurityScan: security.Run(ctx, e.Security, r.body.GetParams().GetSecurityScan())}
	return res
}

// applyListUpdates — packages.list_updates: кэш apt без сети.
func (e *Executor) applyListUpdates(ctx context.Context, r *run) *agentv1.OperationResult {
	if e.Security == nil {
		return r.failed(CodeSecurityUnavailable, "проверки безопасности на этой сборке не выполняются")
	}
	out, err := security.ListUpdates(ctx, e.Security)
	if err != nil {
		e.log().Warn("helper: packages.list_updates", "err", err)
		return r.failed(CodePackagesFailed, "список обновлений не получен")
	}
	res := r.succeeded("")
	res.Data = &agentv1.OperationResult_PackagesListUpdates{PackagesListUpdates: out}
	return res
}
