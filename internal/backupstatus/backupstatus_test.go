// SPDX-License-Identifier: AGPL-3.0-only

package backupstatus

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAge(t *testing.T) {
	path := filepath.Join(t.TempDir(), "backup", "status.json")
	f, err := Read(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := f.Age(time.Now()); ok {
		t.Fatal("без планов есть возраст")
	}
	now := time.UnixMilli(1_800_000_000_000)
	if err := Update(path, func(f *File) {
		f.Plans["a"] = Plan{ConfiguredMs: now.Add(-48 * time.Hour).UnixMilli(), LastSuccessMs: now.Add(-time.Hour).UnixMilli()}
		f.Plans["b"] = Plan{ConfiguredMs: now.Add(-3 * time.Hour).UnixMilli()} // успехов ещё не было
	}); err != nil {
		t.Fatal(err)
	}
	f, err = Read(path)
	if err != nil {
		t.Fatal(err)
	}
	if age, ok := f.Age(now); !ok || age != 3*3600 {
		t.Fatalf("возраст %v %v", age, ok)
	}
	if st, _ := os.Stat(path); st.Mode().Perm() != 0o644 {
		t.Fatalf("права %v", st.Mode())
	}
	if st, _ := os.Stat(filepath.Dir(path)); st.Mode().Perm() != 0o755 {
		t.Fatalf("права каталога %v", st.Mode())
	}
	// Повреждённый файл: чтение — ошибка, запись начинает учёт заново.
	_ = os.WriteFile(path, []byte("{"), 0o644)
	if _, err := Read(path); err == nil {
		t.Fatal("повреждённый файл прочитан")
	}
	if err := Update(path, func(f *File) { f.Plans["c"] = Plan{ConfiguredMs: now.UnixMilli()} }); err != nil {
		t.Fatal(err)
	}
	if f, err := Read(path); err != nil || len(f.Plans) != 1 {
		t.Fatalf("%+v %v", f, err)
	}
}
