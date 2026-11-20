// SPDX-License-Identifier: AGPL-3.0-only

package security

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// AptLocks — блокировки менеджера пакетов: dpkg (через apt и без него), списки apt, кэш пакетов. apt и dpkg
// держат их блокировкой fcntl на весь файл.
var AptLocks = []string{"/var/lib/dpkg/lock-frontend", "/var/lib/dpkg/lock", "/var/lib/apt/lists/lock", "/var/cache/apt/archives/lock"}

// LockHolder — кто держит блокировку менеджера пакетов. PID 0 — держатель не виден (блокировка OFD).
type LockHolder struct {
	Path string
	PID  int
	Comm string
}

func (h *LockHolder) String() string {
	if h.PID <= 0 {
		return "занят " + h.Path + " (процесс не определён)"
	}
	return fmt.Sprintf("занят %s: %s (pid %d)", h.Path, h.Comm, h.PID)
}

// PackageManagerBusy — первая занятая чужим процессом блокировка apt/dpkg (F_GETLK, файл не создаётся и не
// блокируется). nil — свободно. Нет файла блокировки — менеджер им не пользовался, свободно.
func PackageManagerBusy(sys *System) (*LockHolder, error) {
	for _, p := range AptLocks {
		f, err := os.OpenFile(sys.path(p), os.O_RDWR|unix.O_NOFOLLOW, 0)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		lk := unix.Flock_t{Type: unix.F_WRLCK, Whence: 0, Start: 0, Len: 0}
		err = unix.FcntlFlock(f.Fd(), unix.F_GETLK, &lk)
		f.Close()
		if err != nil {
			return nil, fmt.Errorf("%s: F_GETLK: %w", p, err)
		}
		if lk.Type == unix.F_UNLCK {
			continue
		}
		h := &LockHolder{Path: p, PID: int(lk.Pid)}
		if h.PID > 0 {
			if b, err := os.ReadFile(sys.path("/proc/" + strconv.Itoa(h.PID) + "/comm")); err == nil {
				h.Comm = strings.TrimSpace(string(b))
			}
		}
		return h, nil
	}
	return nil, nil
}
