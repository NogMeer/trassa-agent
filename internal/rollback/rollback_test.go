// SPDX-License-Identifier: AGPL-3.0-only

package rollback

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const op = "01a1f4b6-f2f2-7e66-85b4-8ff564561ccb"

func TestCreateRestore(t *testing.T) {
	root := t.TempDir()
	s := &Store{Dir: filepath.Join(root, "rollback")}
	a := filepath.Join(root, "a.conf")
	b := filepath.Join(root, "new.conf")
	if err := os.WriteFile(a, []byte("old"), 0o640); err != nil {
		t.Fatal(err)
	}
	m, err := s.Create(op, []string{a, b}, []string{"nginx.service"})
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Files) != 2 || !m.Files[0].Existed || m.Files[1].Existed || m.TotalBytes != 3 {
		t.Fatalf("манифест %+v", m)
	}
	// Операция меняет файл, права и создаёт новый.
	_ = os.WriteFile(a, []byte("changed!"), 0o600)
	_ = os.Chmod(a, 0o600)
	_ = os.WriteFile(b, []byte("x"), 0o644)
	got, err := s.Restore(op)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(a)
	st, _ := os.Stat(a)
	if string(raw) != "old" || st.Mode().Perm() != 0o640 {
		t.Fatalf("после возврата: %q %v", raw, st.Mode().Perm())
	}
	if _, err := os.Stat(b); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("созданный операцией файл не удалён")
	}
	for _, f := range got.Files {
		if err := Matches(f); err != nil {
			t.Fatalf("%s: %v", f.Path, err)
		}
	}
	// Повторный возврат идемпотентен.
	if _, err := s.Restore(op); err != nil {
		t.Fatal(err)
	}
}

func TestUnavailable(t *testing.T) {
	root := t.TempDir()
	big := filepath.Join(root, "big")
	if err := os.WriteFile(big, make([]byte, 2048), 0o600); err != nil {
		t.Fatal(err)
	}
	s := &Store{Dir: filepath.Join(root, "rb"), MaxBytes: 1024}
	if _, err := s.Create(op, []string{big}, nil); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("сверх лимита: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "rb", op)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("недосозданная точка осталась")
	}
	// Каталог только для чтения — как заполненный диск: точку не создать.
	ro := filepath.Join(root, "ro")
	_ = os.Mkdir(ro, 0o500)
	t.Cleanup(func() { _ = os.Chmod(ro, 0o700) })
	if os.Geteuid() != 0 {
		s2 := &Store{Dir: ro}
		if _, err := s2.Create(op, []string{big}, nil); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("нет места: %v", err)
		}
	}
	link := filepath.Join(root, "link")
	_ = os.Symlink(big, link)
	if _, err := (&Store{Dir: filepath.Join(root, "rb2")}).Create(op, []string{link}, nil); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("ссылка принята: %v", err)
	}
	if _, err := (&Store{Dir: filepath.Join(root, "rb3")}).Create(op, []string{"relative"}, nil); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("относительный путь принят: %v", err)
	}
}

func TestRestoreDetectsTamper(t *testing.T) {
	root := t.TempDir()
	s := &Store{Dir: filepath.Join(root, "rb")}
	a := filepath.Join(root, "a")
	_ = os.WriteFile(a, []byte("v1"), 0o600)
	if _, err := s.Create(op, []string{a}, nil); err != nil {
		t.Fatal(err)
	}
	// Копия в точке подменена: возврат замечает расхождение sha256.
	_ = os.WriteFile(filepath.Join(root, "rb", op, "files", "0"), []byte("evil"), 0o600)
	if _, err := s.Restore(op); !errors.Is(err, ErrFailed) {
		t.Fatalf("подмена не замечена: %v", err)
	}
}

func TestPrune(t *testing.T) {
	root := t.TempDir()
	now := time.Unix(1_800_000_000, 0)
	s := &Store{Dir: filepath.Join(root, "rb"), MaxCount: 3, Now: func() time.Time { return now }}
	ops := make([]string, 6)
	for i := range ops {
		ops[i] = fmt.Sprintf("01a1f4b6-f2f2-7e66-85b4-%012d", i)
		now = now.Add(time.Minute)
		if _, err := s.Create(ops[i], nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Prune(map[string]bool{ops[0]: true}); err != nil {
		t.Fatal(err)
	}
	for i, o := range ops {
		_, err := s.Load(o)
		keep := i == 0 || i >= 3
		if keep != (err == nil) {
			t.Fatalf("точка %d: keep=%v err=%v", i, keep, err)
		}
	}
	now = now.Add(31 * 24 * time.Hour)
	if err := s.Prune(nil); err != nil {
		t.Fatal(err)
	}
	if ents, _ := os.ReadDir(s.Dir); len(ents) != 0 {
		t.Fatalf("старые точки остались: %d", len(ents))
	}
}
