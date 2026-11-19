// SPDX-License-Identifier: AGPL-3.0-only

package helperrpc

import "golang.org/x/sys/unix"

// peerUID — uid процесса на другом конце сокета (SO_PEERCRED, снят ядром в момент connect(2)).
func peerUID(fd uintptr) (int, error) {
	c, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil {
		return -1, err
	}
	return int(c.Uid), nil
}
