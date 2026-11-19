// SPDX-License-Identifier: AGPL-3.0-only

package helperrpc

import "golang.org/x/sys/unix"

// peerUID на macOS — LOCAL_PEERCRED. Агент работает только на Linux; это для тестов на машине разработчика.
func peerUID(fd uintptr) (int, error) {
	c, err := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	if err != nil {
		return -1, err
	}
	return int(c.Uid), nil
}
