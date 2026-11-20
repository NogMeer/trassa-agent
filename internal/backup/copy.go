// SPDX-License-Identifier: AGPL-3.0-only

package backup

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/NogMeer/trassa-agent/internal/fsutil"
)

// treeSize — сумма размеров обычных файлов под path (ссылки не проходятся); нет пути — 0.
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

// copyTree копирует src в dst с правами, владельцами и временем: ссылки — ссылками (не проходятся), устройства,
// сокеты и каналы пропускаются (их нет в копиях restic). dst не должен существовать.
func copyTree(src, dst string) error {
	// Права и время каталогов — после содержимого: иначе запись внутрь сдвинет время, а 0555 запретит запись.
	type dirMeta struct {
		path string
		info fs.FileInfo
	}
	var dirs []dirMeta
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		to := filepath.Join(dst, rel)
		info, err := d.Info()
		if err != nil {
			return err
		}
		switch {
		case d.IsDir():
			if err := os.Mkdir(to, 0o700); err != nil {
				return err
			}
			dirs = append(dirs, dirMeta{to, info})
			return nil
		case d.Type()&fs.ModeSymlink != 0:
			target, err := os.Readlink(p)
			if err != nil {
				return err
			}
			if err := os.Symlink(target, to); err != nil {
				return err
			}
		case d.Type().IsRegular():
			if err := copyFile(p, to); err != nil {
				return err
			}
		default:
			return nil
		}
		return applyMeta(to, info)
	})
	if err != nil {
		return err
	}
	for i := len(dirs) - 1; i >= 0; i-- {
		if err := applyMeta(dirs[i].path, dirs[i].info); err != nil {
			return err
		}
	}
	return nil
}

// copyFile — содержимое по дескриптору, открытому без ссылок: подмена файла ссылкой во время копии не даёт root
// прочитать чужой файл (его содержимое вернулось бы потом на место откатом).
func copyFile(src, dst string) error {
	in, err := fsutil.OpenNoFollow(src, unix.O_RDONLY)
	if err != nil {
		return err
	}
	defer in.Close()
	if st, err := in.Stat(); err != nil || !st.Mode().IsRegular() {
		return fmt.Errorf("%s: не обычный файл", src)
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// applyMeta — владелец, права (с особыми битами — после chown) и время изменения; для ссылки — только владелец.
func applyMeta(p string, info fs.FileInfo) error {
	st, ok := info.Sys().(*syscall.Stat_t)
	if ok {
		if err := os.Lchown(p, int(st.Uid), int(st.Gid)); err != nil && !errors.Is(err, fs.ErrPermission) {
			return err
		}
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		return nil
	}
	mode := info.Mode().Perm() | info.Mode()&(fs.ModeSetuid|fs.ModeSetgid|fs.ModeSticky)
	if err := os.Chmod(p, mode); err != nil {
		return err
	}
	return os.Chtimes(p, time.Now(), info.ModTime())
}

// copyBack возвращает копию на место: прежнее содержимое пути удаляется, копия переносится.
func copyBack(copyPath, dst string) error {
	if err := os.RemoveAll(dst); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	if err := os.Rename(copyPath, dst); err == nil {
		return nil
	}
	if err := copyTree(copyPath, dst); err != nil {
		return fmt.Errorf("возврат %s: %w", dst, err)
	}
	return nil
}
