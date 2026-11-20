// SPDX-License-Identifier: AGPL-3.0-only

package security

import (
	"context"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
)

// snapshotParts — части снимка, которые дополняют файлы проверок (SSH, firewall, базовый список).
var snapshotParts []func(ctx context.Context, s *Scan, res *agentv1.SecurityScanResult)

// snapshot — слушающие сокеты, адреса интерфейсов и части из snapshotParts. Ошибка части оставляет её пустой:
// проверки, которым она нужна, уже вернули ERROR со своей причиной.
func (s *Scan) snapshot(ctx context.Context, res *agentv1.SecurityScanResult) {
	if ls, err := s.Listeners(ctx); err == nil {
		res.Listeners = ls
	}
	if s.sys.Addresses != nil {
		if as, err := s.sys.Addresses(); err == nil {
			for _, a := range as {
				res.Addresses = append(res.Addresses, a.String())
			}
		}
	}
	for _, part := range snapshotParts {
		part(ctx, s, res)
	}
}
