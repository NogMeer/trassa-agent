// SPDX-License-Identifier: AGPL-3.0-only

// Package sdunits — службы systemd через D-Bus для system.inventory. Отдельно от sysinfo, чтобы зависимость D-Bus
// была только у помощника.
package sdunits

import (
	"context"
	"strings"

	"github.com/NogMeer/trassa-agent/internal/sysinfo"

	sdbus "github.com/coreos/go-systemd/v22/dbus"
)

// MaxTriggers — сколько имён TriggeredBy берётся на службу.
const MaxTriggers = 16

// List — службы через D-Bus org.freedesktop.systemd1.Manager.ListUnits (состояние и подсостояние). Сведения о файле
// юнита, типе и запускающих юнитах не запрашиваются — для них Describe.
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
		out = append(out, sysinfo.Unit{Name: u.Name, ActiveState: u.ActiveState, SubState: u.SubState})
	}
	return out, nil
}

// ListFull — List и для каждой службы (*.service) — UnitFileState, Service.Type и TriggeredBy (system.inventory).
// Сведения службы, которые не прочитались, остаются пустыми: такая служба «не должна работать» не считается — она
// получит признак по пустым полям в панели как неизвестная.
func ListFull(ctx context.Context) ([]sysinfo.Unit, error) {
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
		x := sysinfo.Unit{Name: u.Name, ActiveState: u.ActiveState, SubState: u.SubState}
		if strings.HasSuffix(u.Name, ".service") {
			describe(ctx, conn, &x)
		}
		out = append(out, x)
	}
	return out, nil
}

// Describe — сведения для указанных служб (детектор: только упавшие). Не прочитались — Described = false.
func Describe(ctx context.Context, units []sysinfo.Unit) ([]sysinfo.Unit, error) {
	conn, err := sdbus.NewSystemConnectionContext(ctx)
	if err != nil {
		return units, err
	}
	defer conn.Close()
	out := make([]sysinfo.Unit, len(units))
	for i, u := range units {
		describe(ctx, conn, &u)
		out[i] = u
	}
	return out, nil
}

func describe(ctx context.Context, conn *sdbus.Conn, u *sysinfo.Unit) {
	props, err := conn.GetUnitPropertiesContext(ctx, u.Name)
	if err != nil {
		return
	}
	if v, ok := props["UnitFileState"].(string); ok {
		u.UnitFileState = v
	}
	if v, ok := props["TriggeredBy"].([]string); ok {
		if len(v) > MaxTriggers {
			v = v[:MaxTriggers]
		}
		u.TriggeredBy = append([]string(nil), v...)
	}
	if p, err := conn.GetUnitTypePropertyContext(ctx, u.Name, "Service", "Type"); err == nil {
		if v, ok := p.Value.Value().(string); ok {
			u.Type = v
		}
	}
	u.Described = true
}
