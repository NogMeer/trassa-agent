// SPDX-License-Identifier: AGPL-3.0-only

package backup

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"

	"github.com/NogMeer/trassa-agent/internal/fsutil"
)

// treeSize — сумма размеров обычных файлов под path (ссылки не проходятся); нет пути — 0. Только оценка места.
func treeSize(path string) (uint64, error) {
	var total uint64
	err := filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) && p == path {
				return filepath.SkipAll
			}
			return err
		}
		if d.Type().IsRegular() {
			info, err := d.Info()
			if err != nil {
				return err
			}
			total += uint64(info.Size())
		}
		return nil
	})
	return total, err
}

// copyTree копирует src в dst (dst не существует) с правами, владельцами и временем. И чтение, и запись идут
// относительно дескрипторов каталогов, открытых без ссылок: пользователь, владеющий каталогом на пути, не может
// подменой компонента на ссылку увести root читать или писать в чужое место. Ссылки копируются ссылками,
// устройства, сокеты и каналы пропускаются.
func copyTree(src, dst string) error {
	sp, err := fsutil.OpenDirNoFollow(filepath.Dir(src))
	if err != nil {
		return err
	}
	defer unix.Close(sp)
	dp, err := fsutil.MkdirAllNoFollow(filepath.Dir(dst), 0o755)
	if err != nil {
		return err
	}
	defer unix.Close(dp)
	return copyAt(sp, filepath.Base(src), dp, filepath.Base(dst))
}

func unixMode(st *unix.Stat_t) uint32 { return uint32(st.Mode) & 0o7777 }

// copyAt — srcName из каталога sdir в dstName каталога ddir.
func copyAt(sdir int, srcName string, ddir int, dstName string) error {
	var st unix.Stat_t
	if err := unix.Fstatat(sdir, srcName, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	switch uint32(st.Mode) & unix.S_IFMT {
	case unix.S_IFDIR:
		sfd, err := unix.Openat(sdir, srcName, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		sf := os.NewFile(uintptr(sfd), srcName)
		defer sf.Close()
		if err := unix.Mkdirat(ddir, dstName, 0o700); err != nil {
			return err
		}
		dfd, err := unix.Openat(ddir, dstName, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		defer unix.Close(dfd)
		names, err := sf.Readdirnames(-1)
		if err != nil {
			return err
		}
		for _, n := range names {
			if err := copyAt(sfd, n, dfd, n); err != nil {
				return err
			}
		}
		// Права и время каталога — после содержимого и по его дескриптору.
		var cur unix.Stat_t
		if err := unix.Fstat(sfd, &cur); err != nil {
			return err
		}
		return applyMetaFd(dfd, &cur)
	case unix.S_IFREG:
		sfd, err := unix.Openat(sdir, srcName, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		in := os.NewFile(uintptr(sfd), srcName)
		defer in.Close()
		var cur unix.Stat_t
		if err := unix.Fstat(sfd, &cur); err != nil || uint32(cur.Mode)&unix.S_IFMT != unix.S_IFREG {
			return fmt.Errorf("%s: не обычный файл", srcName)
		}
		dfd, err := unix.Openat(ddir, dstName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
		if err != nil {
			return err
		}
		out := os.NewFile(uintptr(dfd), dstName)
		defer out.Close()
		if _, err := io.Copy(out, in); err != nil {
			return err
		}
		return applyMetaFd(dfd, &cur)
	case unix.S_IFLNK:
		buf := make([]byte, 4096)
		n, err := unix.Readlinkat(sdir, srcName, buf)
		if err != nil {
			return err
		}
		if err := unix.Symlinkat(string(buf[:n]), ddir, dstName); err != nil {
			return err
		}
		if err := unix.Fchownat(ddir, dstName, int(st.Uid), int(st.Gid), unix.AT_SYMLINK_NOFOLLOW); err != nil && !errors.Is(err, unix.EPERM) {
			return err
		}
		return nil
	}
	return nil // устройства, сокеты, каналы
}

// applyMetaFd — владелец (до прав: chown снимает setuid), права с особыми битами и время — по дескриптору.
func applyMetaFd(fd int, st *unix.Stat_t) error {
	if err := unix.Fchown(fd, int(st.Uid), int(st.Gid)); err != nil && !errors.Is(err, unix.EPERM) {
		return err
	}
	if err := unix.Fchmod(fd, unixMode(st)); err != nil {
		return err
	}
	mt := unix.NsecToTimeval(unix.TimespecToNsec(statMtime(st)))
	return unix.Futimes(fd, []unix.Timeval{mt, mt})
}

// copyBack возвращает копию на место: прежнее содержимое пути удаляется, копия переносится (renameat) или,
// на другой файловой системе, копируется. Всё — относительно дескриптора каталога-родителя без ссылок.
func copyBack(copyPath, dst string) error {
	dp, err := fsutil.MkdirAllNoFollow(filepath.Dir(dst), 0o755)
	if err != nil {
		return err
	}
	defer unix.Close(dp)
	name := filepath.Base(dst)
	if err := fsutil.RemoveAllAt(dp, name); err != nil {
		return err
	}
	sp, err := fsutil.OpenDirNoFollow(filepath.Dir(copyPath))
	if err != nil {
		return err
	}
	defer unix.Close(sp)
	if err := unix.Renameat(sp, filepath.Base(copyPath), dp, name); err == nil {
		return nil
	} else if !errors.Is(err, unix.EXDEV) {
		return fmt.Errorf("возврат %s: %w", dst, err)
	}
	if err := copyAt(sp, filepath.Base(copyPath), dp, name); err != nil {
		return fmt.Errorf("возврат %s: %w", dst, err)
	}
	return nil
}

// removeNoFollow — удалить path со всем содержимым через дескриптор родителя без ссылок; нет пути — не ошибка.
func removeNoFollow(path string) error {
	dp, err := fsutil.OpenDirNoFollow(filepath.Dir(path))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer unix.Close(dp)
	return fsutil.RemoveAllAt(dp, filepath.Base(path))
}

func statMtime(st *unix.Stat_t) unix.Timespec { return st.Mtim }
