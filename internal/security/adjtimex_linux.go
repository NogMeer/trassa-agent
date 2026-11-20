// SPDX-License-Identifier: AGPL-3.0-only

package security

import "golang.org/x/sys/unix"

// adjtimex читает состояние часов ядра без изменения (modes = 0, прав не требует).
func adjtimex() (int64, error) {
	var t unix.Timex
	if _, err := unix.Adjtimex(&t); err != nil {
		return 0, err
	}
	return int64(t.Maxerror), nil
}
