// SPDX-License-Identifier: AGPL-3.0-only

package metrics

import "golang.org/x/sys/unix"

func statfs(path string) (FS, error) {
	var s unix.Statfs_t
	if err := unix.Statfs(path, &s); err != nil {
		return FS{}, err
	}
	return FS{Blocks: s.Blocks, Bfree: s.Bfree, Bavail: s.Bavail, Files: s.Files, Ffree: s.Ffree, Bsize: blockSize(s)}, nil
}

// blockSize — размер блока для счётчиков: f_frsize, как у df; старые ядра его не заполняют — тогда f_bsize.
func blockSize(s unix.Statfs_t) int64 {
	if s.Frsize > 0 {
		return int64(s.Frsize)
	}
	return int64(s.Bsize)
}
