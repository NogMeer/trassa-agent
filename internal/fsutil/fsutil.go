// SPDX-License-Identifier: AGPL-3.0-only

// Package fsutil — запись файлов, которая переживает обрыв питания: временный файл в том же каталоге, fsync,
// rename(2), fsync каталога. Частично записанный файл на месте цели не появляется никогда.
package fsutil

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Owner — владелец файла. Пустой Owner (-1, -1) оставляет владельца процесса.
type Owner struct{ UID, GID int }

// Keep — не менять владельца.
var Keep = Owner{UID: -1, GID: -1}

// WriteFileAtomic записывает data в path с правами perm и владельцем owner.
func WriteFileAtomic(path string, data []byte, perm os.FileMode, owner Owner) error {
	return WriteAtomic(path, perm, owner, func(w io.Writer) error {
		_, err := w.Write(data)
		return err
	})
}

// WriteAtomic — как WriteFileAtomic, содержимое пишет fill.
func WriteAtomic(path string, perm os.FileMode, owner Owner, fill func(io.Writer) error) (err error) {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() {
		if err != nil {
			_ = f.Close()
			_ = os.Remove(tmp)
		}
	}()
	if err = f.Chmod(perm); err != nil {
		return err
	}
	if owner != Keep {
		if err = f.Chown(owner.UID, owner.GID); err != nil {
			return err
		}
	}
	if err = fill(f); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmp, path); err != nil {
		return err
	}
	return SyncDir(dir)
}

// SyncDir делает fsync каталога: без него rename и удаление могут потеряться при сбое питания.
func SyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("fsync %s: %w", dir, err)
	}
	return nil
}

// RemoveSync удаляет файл и делает fsync каталога. Отсутствие файла — не ошибка.
func RemoveSync(path string) error {
	if err := os.Remove(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	return SyncDir(filepath.Dir(path))
}

// ReadLimited читает файл не больше max байт; больше — ошибка, а не обрезка.
func ReadLimited(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("%s: больше %d байт", path, max)
	}
	return b, nil
}
