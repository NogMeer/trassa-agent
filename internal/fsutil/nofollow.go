// SPDX-License-Identifier: AGPL-3.0-only

package fsutil

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// ErrSymlink — на пути есть символическая ссылка или компонент не того вида: root по такому пути не идёт.
var ErrSymlink = errors.New("ссылка на пути")

// openDirNoFollow — каталог path, пройденный от «/» по компонентам с O_NOFOLLOW: ни одна ссылка не проходится,
// подмена компонента на ссылку между проверкой и действием даёт ошибку, а не чужой файл.
func openDirNoFollow(path string) (int, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return -1, fmt.Errorf("путь %q не абсолютный или не очищен", path)
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	for _, c := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if c == "" {
			continue
		}
		next, err := unix.Openat(fd, c, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if err != nil {
			if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) {
				return -1, fmt.Errorf("%w: %s (%s)", ErrSymlink, path, c)
			}
			return -1, err
		}
		fd = next
	}
	return fd, nil
}

// OpenNoFollow открывает path без следования по ссылкам ни в одном компоненте (O_NOFOLLOW на каждом шаге).
// flags — дополнительные флаги для последнего компонента (O_RDONLY, O_WRONLY|O_TRUNC, O_DIRECTORY…).
func OpenNoFollow(path string, flags int) (*os.File, error) {
	dir, err := openDirNoFollow(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer unix.Close(dir)
	fd, err := unix.Openat(dir, filepath.Base(path), flags|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return nil, fmt.Errorf("%w: %s", ErrSymlink, path)
		}
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}

// FileID — устройство и inode: план и применение сверяют, что это тот же файл.
type FileID struct{ Dev, Ino uint64 }

// IDOf — dev и inode открытого файла.
func IDOf(f *os.File) (FileID, error) {
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		return FileID{}, err
	}
	return FileID{Dev: uint64(st.Dev), Ino: uint64(st.Ino)}, nil
}

// ChmodChownNoFollow — права и владелец path по дескриптору, открытому без ссылок. want ≠ нулю — файл обязан
// быть тем же (dev, inode), что видел план. Владелец ставится первым: chown снимает setuid и setgid.
func ChmodChownNoFollow(path string, want FileID, mode os.FileMode, uid, gid int) error {
	f, err := OpenNoFollow(path, unix.O_RDONLY)
	if err != nil {
		return err
	}
	defer f.Close()
	if want != (FileID{}) {
		got, err := IDOf(f)
		if err != nil {
			return err
		}
		if got != want {
			return fmt.Errorf("%s подменён после проверки (inode %d, был %d)", path, got.Ino, want.Ino)
		}
	}
	if uid >= 0 || gid >= 0 {
		if err := f.Chown(uid, gid); err != nil {
			return err
		}
	}
	return f.Chmod(mode)
}

// WriteAtomicNoFollow — как WriteAtomic, но каталог открыт без ссылок и временный файл создаётся и
// переименовывается относительно его дескриптора (openat, renameat): подмена каталога ссылкой не уводит запись
// в чужое место. Цель — точка монтирования (EBUSY) — переписывается на месте по дескриптору без ссылок.
func WriteAtomicNoFollow(path string, perm os.FileMode, owner Owner, fill func(io.Writer) error) error {
	dir, err := openDirNoFollow(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer unix.Close(dir)
	base := filepath.Base(path)
	tmp := "." + base + ".tmp-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	fd, err := unix.Openat(dir, tmp, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), tmp)
	ok := false
	defer func() {
		if !ok {
			f.Close()
			_ = unix.Unlinkat(dir, tmp, 0)
		}
	}()
	if owner != Keep {
		if err := f.Chown(owner.UID, owner.GID); err != nil {
			return err
		}
	}
	if err := fill(f); err != nil {
		return err
	}
	// Права — после записи: запись снимает setuid и setgid.
	if err := f.Chmod(perm); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := unix.Renameat(dir, tmp, dir, base); err != nil {
		if !errors.Is(err, unix.EBUSY) {
			return err
		}
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			return err
		}
		dst, err := OpenNoFollow(path, unix.O_WRONLY|unix.O_TRUNC)
		if err != nil {
			return err
		}
		defer dst.Close()
		if _, err := io.Copy(dst, f); err != nil {
			return err
		}
		if owner != Keep {
			if err := dst.Chown(owner.UID, owner.GID); err != nil {
				return err
			}
		}
		if err := dst.Chmod(perm); err != nil {
			return err
		}
		if err := dst.Sync(); err != nil {
			return err
		}
		return nil
	}
	ok = true
	f.Close()
	return unix.Fsync(dir)
}

// RemoveNoFollow — удалить path (не каталог) через дескриптор каталога без ссылок; нет файла — не ошибка.
func RemoveNoFollow(path string) error {
	dir, err := openDirNoFollow(filepath.Dir(path))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer unix.Close(dir)
	if err := unix.Unlinkat(dir, filepath.Base(path), 0); err != nil && !errors.Is(err, unix.ENOENT) {
		return err
	}
	return unix.Fsync(dir)
}

// OpenDirNoFollow — дескриптор каталога path, пройденного от «/» без ссылок (закрывает вызывающий).
func OpenDirNoFollow(path string) (int, error) { return openDirNoFollow(path) }

// MkdirAllNoFollow — каталог path и недостающие предки (perm), пройденные без ссылок: подмена компонента
// ссылкой даёт ошибку, а не каталог в чужом месте. Возвращает дескриптор path (закрывает вызывающий).
func MkdirAllNoFollow(path string, perm os.FileMode) (int, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return -1, fmt.Errorf("путь %q не абсолютный или не очищен", path)
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	for _, c := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if c == "" {
			continue
		}
		if err := unix.Mkdirat(fd, c, uint32(perm)); err != nil && !errors.Is(err, unix.EEXIST) {
			unix.Close(fd)
			return -1, err
		}
		next, err := unix.Openat(fd, c, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if err != nil {
			if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) {
				return -1, fmt.Errorf("%w: %s (%s)", ErrSymlink, path, c)
			}
			return -1, err
		}
		fd = next
	}
	return fd, nil
}

// RemoveAllAt — удалить name в каталоге dirfd со всем содержимым, не проходя ссылки (сами ссылки удаляются);
// нет name — не ошибка. Каждый уровень открывается O_NOFOLLOW от уже открытого родителя.
func RemoveAllAt(dirfd int, name string) error {
	if name == "" || name == "." || name == ".." || strings.ContainsRune(name, '/') {
		return fmt.Errorf("имя %q", name)
	}
	err := unix.Unlinkat(dirfd, name, 0)
	if err == nil || errors.Is(err, unix.ENOENT) {
		return nil
	}
	if !errors.Is(err, unix.EISDIR) && !errors.Is(err, unix.EPERM) {
		return err
	}
	fd, err := unix.Openat(dirfd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	d := os.NewFile(uintptr(fd), name)
	names, err := d.Readdirnames(-1)
	if err != nil {
		d.Close()
		return err
	}
	for _, n := range names {
		if err := RemoveAllAt(fd, n); err != nil {
			d.Close()
			return err
		}
	}
	d.Close()
	return unix.Unlinkat(dirfd, name, unix.AT_REMOVEDIR)
}
