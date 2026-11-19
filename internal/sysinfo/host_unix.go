// SPDX-License-Identifier: AGPL-3.0-only

package sysinfo

import (
	"net"
	"os"

	"golang.org/x/sys/unix"
)

// Real — настоящая система.
func Real() *Host {
	return &Host{
		Root: "/",
		Statfs: func(p string) (uint64, error) {
			var st unix.Statfs_t
			if err := unix.Statfs(p, &st); err != nil {
				return 0, err
			}
			return uint64(st.Blocks) * uint64(st.Bsize), nil
		},
		Uname: func() (string, error) {
			var u unix.Utsname
			if err := unix.Uname(&u); err != nil {
				return "", err
			}
			return unix.ByteSliceToString(u.Release[:]), nil
		},
		Addrs:    net.InterfaceAddrs,
		Hostname: os.Hostname,
	}
}
