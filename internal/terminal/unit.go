// SPDX-License-Identifier: AGPL-3.0-only

// Package terminal — терминал через помощник (E16, decisions/E16-access.md, часть 9): PTY открывает помощник,
// оболочка запускается transient-службой systemd от PID 1 (не наследует песочницу, UMask и cgroup помощника),
// ведущая сторона PTY уходит агенту, сроки держит помощник.
package terminal

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	sdbus "github.com/coreos/go-systemd/v22/dbus"
	"github.com/godbus/dbus/v5"
)

// UnitPrefix — службы терминалов: trassa-term-<session_id>.service.
const UnitPrefix = "trassa-term-"

// UnitName — служба сеанса.
func UnitName(sessionID string) string { return UnitPrefix + strings.ToLower(sessionID) + ".service" }

// Shell — что запускает служба.
type Shell struct {
	SessionID string
	User      string
	Shell     string // абсолютный путь оболочки пользователя
	Lang      string
	Term      string
	PTSNumber int
	MaxRun    time.Duration
}

// execStart — тип ExecStart в D-Bus systemd: a(sasb).
type execStart struct {
	Path             string
	Args             []string
	UncleanIsFailure bool
}

// Properties — свойства службы по образцу machinectl shell (systemd v249): ведомая сторона PTY — stdin, stdout,
// stderr; PAM-сеанс login от имени пользователя, запись utmp, предельный срок RuntimeMaxSec; оболочка входа
// (argv[0] с «-»).
func Properties(s Shell, slaveFD int) []sdbus.Property {
	fd := dbus.MakeVariant(dbus.UnixFD(int32(slaveFD)))
	return []sdbus.Property{
		sdbus.PropDescription("Trassa terminal " + s.SessionID + " (" + s.User + ")"),
		{Name: "StandardInputFileDescriptor", Value: fd},
		{Name: "StandardOutputFileDescriptor", Value: fd},
		{Name: "StandardErrorFileDescriptor", Value: fd},
		{Name: "SendSIGHUP", Value: dbus.MakeVariant(true)},
		{Name: "KillMode", Value: dbus.MakeVariant("mixed")},
		{Name: "TTYReset", Value: dbus.MakeVariant(true)},
		{Name: "UtmpIdentifier", Value: dbus.MakeVariant(fmt.Sprintf("pts/%d", s.PTSNumber))},
		{Name: "UtmpMode", Value: dbus.MakeVariant("user")},
		{Name: "PAMName", Value: dbus.MakeVariant("login")},
		{Name: "User", Value: dbus.MakeVariant(s.User)},
		{Name: "WorkingDirectory", Value: dbus.MakeVariant("-~")},
		{Name: "Environment", Value: dbus.MakeVariant([]string{"TERM=" + s.Term, "LANG=" + s.Lang})},
		{Name: "RuntimeMaxUSec", Value: dbus.MakeVariant(uint64(s.MaxRun / time.Microsecond))},
		{Name: "CollectMode", Value: dbus.MakeVariant("inactive-or-failed")},
		{Name: "ExecStart", Value: dbus.MakeVariant([]execStart{{Path: s.Shell, Args: []string{"-" + filepath.Base(s.Shell)}}})},
	}
}

// Systemd — службы терминалов через системную шину.
type Systemd struct{}

func (Systemd) conn(ctx context.Context) (*sdbus.Conn, error) {
	return sdbus.NewSystemConnectionContext(ctx)
}

// Start — запустить службу сеанса; ведомую сторону вызывающий закрывает после возврата.
func (d Systemd) Start(ctx context.Context, s Shell, slave *os.File) error {
	c, err := d.conn(ctx)
	if err != nil {
		return fmt.Errorf("systemd: %w", err)
	}
	defer c.Close()
	done := make(chan string, 1)
	if _, err := c.StartTransientUnitContext(ctx, UnitName(s.SessionID), "fail", Properties(s, int(slave.Fd())), done); err != nil {
		return fmt.Errorf("StartTransientUnit: %w", err)
	}
	select {
	case r := <-done:
		if r != "done" {
			return fmt.Errorf("служба терминала не запустилась: %s", r)
		}
	case <-ctx.Done():
		return ctx.Err()
	}
	return nil
}

// Active — служба ещё работает (active, activating, deactivating).
func (d Systemd) Active(ctx context.Context, sessionID string) (bool, error) {
	c, err := d.conn(ctx)
	if err != nil {
		return false, err
	}
	defer c.Close()
	p, err := c.GetUnitPropertyContext(ctx, UnitName(sessionID), "ActiveState")
	if err != nil {
		return false, err
	}
	st, _ := p.Value.Value().(string)
	return st == "active" || st == "activating" || st == "deactivating" || st == "reloading", nil
}

// Stop — остановить службу сеанса (SIGTERM и SIGHUP оболочке, KillMode=mixed).
func (d Systemd) Stop(ctx context.Context, sessionID string) error {
	c, err := d.conn(ctx)
	if err != nil {
		return err
	}
	defer c.Close()
	done := make(chan string, 1)
	if _, err := c.StopUnitContext(ctx, UnitName(sessionID), "replace", done); err != nil {
		var de dbus.Error
		if errors.As(err, &de) && strings.HasSuffix(de.Name, "NoSuchUnit") {
			return nil
		}
		return err
	}
	select {
	case <-done:
	case <-ctx.Done():
		return ctx.Err()
	}
	return nil
}

// StopAll — остановить все службы терминалов (старт помощника: сеанс без таймеров продления жить не должен).
func (d Systemd) StopAll(ctx context.Context) error {
	c, err := d.conn(ctx)
	if err != nil {
		return err
	}
	defer c.Close()
	units, err := c.ListUnitsByPatternsContext(ctx, nil, []string{UnitPrefix + "*.service"})
	if err != nil {
		return err
	}
	var errs []error
	for _, u := range units {
		if _, err := c.StopUnitContext(ctx, u.Name, "replace", nil); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", u.Name, err))
		}
	}
	return errors.Join(errs...)
}
