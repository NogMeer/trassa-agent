// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package terminal

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// OpenPTY — ведущая и ведомая стороны PTY (decisions E16, 9.2): ведомая — через TIOCGPTPEER, без поиска по пути
// /dev/pts/N и без гонки с подменой. n — номер pts (для utmp).
func OpenPTY() (master, slave *os.File, n int, err error) {
	mfd, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("ptmx: %w", err)
	}
	m := os.NewFile(uintptr(mfd), "ptmx")
	fail := func(e error) (*os.File, *os.File, int, error) {
		m.Close()
		return nil, nil, 0, e
	}
	if err := unix.IoctlSetPointerInt(mfd, unix.TIOCSPTLCK, 0); err != nil {
		return fail(fmt.Errorf("TIOCSPTLCK: %w", err))
	}
	n, err = unix.IoctlGetInt(mfd, unix.TIOCGPTN)
	if err != nil {
		return fail(fmt.Errorf("TIOCGPTN: %w", err))
	}
	// Аргумент TIOCGPTPEER — флаги open(2) для ведомой стороны (unix.IoctlRetInt передал бы 0 = O_RDONLY).
	sfd, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(mfd), uintptr(unix.TIOCGPTPEER), uintptr(unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC))
	if errno != 0 {
		return fail(fmt.Errorf("TIOCGPTPEER: %w", errno))
	}
	return m, os.NewFile(sfd, fmt.Sprintf("pts/%d", n)), n, nil
}

// SetSize — размер окна (TIOCSWINSZ): cols 1–1000, rows 1–500.
func SetSize(f *os.File, cols, rows uint32) error {
	if cols < 1 || cols > 1000 || rows < 1 || rows > 500 {
		return fmt.Errorf("размер %dx%d", cols, rows)
	}
	return unix.IoctlSetWinsize(int(f.Fd()), unix.TIOCSWINSZ, &unix.Winsize{Col: uint16(cols), Row: uint16(rows)})
}
