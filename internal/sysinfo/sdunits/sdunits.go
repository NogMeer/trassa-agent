// SPDX-License-Identifier: AGPL-3.0-only

// Package sdunits — службы systemd через D-Bus для system.inventory. Отдельно от sysinfo, чтобы зависимость D-Bus
// была только у помощника.
package sdunits

import (
	"context"

	"github.com/NogMeer/trassa-agent/internal/sysinfo"

	sdbus "github.com/coreos/go-systemd/v22/dbus"
)

// SystemdUnits — службы через D-Bus org.freedesktop.systemd1.Manager.ListUnits.
func List(ctx context.Context) ([]sysinfo.Unit, error) {
	conn, err := sdbus.NewSystemConnectionContext(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	units, err := conn.ListUnitsContext(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]sysinfo.Unit, 0, len(units))
	for _, u := range units {
		out = append(out, sysinfo.Unit{Name: u.Name, ActiveState: u.ActiveState})
	}
	return out, nil
}
