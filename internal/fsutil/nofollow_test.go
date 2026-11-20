// SPDX-License-Identifier: AGPL-3.0-only

package fsutil

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// tempRoot — каталог без ссылок на пути (на macOS /var — ссылка на /private/var).
func tempRoot(t *testing.T) string {
	t.Helper()
	d, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func write(t *testing.T, p, s string, m os.FileMode) {
	t.Helper()
	if err := os.WriteFile(p, []byte(s), m); err != nil {
		t.Fatal(err)
	}
}

// Ссылка в последнем и в промежуточном компоненте — отказ ErrSymlink; обычный путь открывается.
func TestOpenNoFollow(t *testing.T) {
	root := tempRoot(t)
	other := filepath.Join(root, "other")
	if err := os.Mkdir(other, 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(other, "secret"), "x", 0o600)
	if err := os.Symlink(filepath.Join(other, "secret"), filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(other, filepath.Join(root, "dirlink")); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{filepath.Join(root, "link"), filepath.Join(root, "dirlink", "secret")} {
		if f, err := OpenNoFollow(p, unix.O_RDONLY); !errors.Is(err, ErrSymlink) {
			if f != nil {
				f.Close()
			}
			t.Errorf("%s: %v", p, err)
		}
	}
	f, err := OpenNoFollow(filepath.Join(other, "secret"), unix.O_RDONLY)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if _, err := OpenNoFollow("relative/path", unix.O_RDONLY); err == nil {
		t.Fatal("относительный путь принят")
	}
	if _, err := OpenNoFollow(root+"/../x", unix.O_RDONLY); err == nil {
		t.Fatal("неочищенный путь принят")
	}
}

// Права по дескриптору: ссылка не проходится, подменённый файл (другой inode) не трогается.
func TestChmodChownNoFollow(t *testing.T) {
	root := tempRoot(t)
	p := filepath.Join(root, "f")
	victim := filepath.Join(root, "victim")
	write(t, p, "a", 0o666)
	write(t, victim, "v", 0o600)
	f, _ := OpenNoFollow(p, unix.O_RDONLY)
	id, _ := IDOf(f)
	f.Close()
	// Подмена другим файлом под тем же именем.
	_ = os.Remove(p)
	write(t, p, "b", 0o666)
	if err := ChmodChownNoFollow(p, id, 0o644, -1, -1); err == nil || !strings.Contains(err.Error(), "подменён") {
		t.Fatalf("подмена файлом: %v", err)
	}
	// Подмена ссылкой на чужой файл.
	_ = os.Remove(p)
	if err := os.Symlink(victim, p); err != nil {
		t.Fatal(err)
	}
	if err := ChmodChownNoFollow(p, id, 0o666, -1, -1); !errors.Is(err, ErrSymlink) {
		t.Fatalf("подмена ссылкой: %v", err)
	}
	if st, _ := os.Stat(victim); st.Mode().Perm() != 0o600 {
		t.Fatalf("права цели ссылки изменены: %v", st.Mode())
	}
	// Тот же файл — права меняются, особые биты ставятся.
	_ = os.Remove(p)
	write(t, p, "c", 0o666)
	f, _ = OpenNoFollow(p, unix.O_RDONLY)
	id, _ = IDOf(f)
	f.Close()
	if err := ChmodChownNoFollow(p, id, 0o755|os.ModeSetgid, os.Getuid(), os.Getgid()); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(p); st.Mode()&(os.ModePerm|os.ModeSetgid) != 0o755|os.ModeSetgid {
		t.Fatalf("%v", st.Mode())
	}
}

// Запись и удаление: каталог-ссылка — отказ, запись не уходит за ссылку; файл-ссылка заменяется самой записью.
func TestWriteRemoveNoFollow(t *testing.T) {
	root := tempRoot(t)
	other := filepath.Join(root, "other")
	if err := os.Mkdir(other, 0o755); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(other, "victim")
	write(t, victim, "v", 0o600)
	if err := os.Symlink(other, filepath.Join(root, "dir")); err != nil {
		t.Fatal(err)
	}
	fill := func(w io.Writer) error { _, err := io.WriteString(w, "new"); return err }
	if err := WriteAtomicNoFollow(filepath.Join(root, "dir", "victim"), 0o644, Keep, fill); !errors.Is(err, ErrSymlink) {
		t.Fatalf("запись через каталог-ссылку: %v", err)
	}
	if err := RemoveNoFollow(filepath.Join(root, "dir", "victim")); !errors.Is(err, ErrSymlink) {
		t.Fatalf("удаление через каталог-ссылку: %v", err)
	}
	if raw, _ := os.ReadFile(victim); string(raw) != "v" {
		t.Fatalf("цель изменена: %q", raw)
	}
	// Файл-ссылка: запись заменяет саму ссылку обычным файлом, цель ссылки не меняется.
	link := filepath.Join(root, "conf")
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}
	if err := WriteAtomicNoFollow(link, 0o640, Owner{UID: os.Getuid(), GID: os.Getgid()}, fill); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Lstat(link)
	if raw, _ := os.ReadFile(link); string(raw) != "new" || st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm() != 0o640 {
		t.Fatalf("%q %v", raw, st.Mode())
	}
	if raw, _ := os.ReadFile(victim); string(raw) != "v" {
		t.Fatalf("цель ссылки изменена: %q", raw)
	}
	if err := RemoveNoFollow(link); err != nil {
		t.Fatal(err)
	}
	if err := RemoveNoFollow(link); err != nil {
		t.Fatalf("нет файла — не ошибка: %v", err)
	}
	if _, err := os.Lstat(link); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("файл не удалён")
	}
	// Временных файлов не осталось.
	ents, _ := os.ReadDir(root)
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".") {
			t.Fatalf("остался %s", e.Name())
		}
	}
}
