// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

func writeLocal(t *testing.T, body string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "agent.toml")
	if err := os.WriteFile(p, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadLocal(t *testing.T) {
	me := uint32(os.Getuid())
	if l, err := loadLocal(filepath.Join(t.TempDir(), "none.toml"), me); err != nil || l.AllowExec {
		t.Fatalf("нет файла: %+v %v", l, err)
	}
	ok := writeLocal(t, "# комментарий\n\nallow_exec = true # включено\n", 0o644)
	if l, err := loadLocal(ok, me); err != nil || !l.AllowExec {
		t.Fatalf("true: %+v %v", l, err)
	}
	// Чужой владелец (в проде — не root): выключено.
	if l, err := loadLocal(ok, me+1); !errors.Is(err, ErrLocalInvalid) || l.AllowExec {
		t.Fatalf("владелец: %+v %v", l, err)
	}
	for name, c := range map[string]struct {
		body string
		mode os.FileMode
	}{
		"запись группе": {"allow_exec = true\n", 0o664},
		"запись всем":   {"allow_exec = true\n", 0o646},
		"неизвестный":   {"allow_exec = true\nallow_root = true\n", 0o644},
		"повтор":        {"allow_exec = false\nallow_exec = true\n", 0o644},
		"строка":        {"allow_exec = \"true\"\n", 0o644},
		"без знака":     {"allow_exec true\n", 0o644},
		"заглавные":     {"allow_exec = TRUE\n", 0o644},
		"раздел":        {"[agent]\nallow_exec = true\n", 0o644},
		"большой":       {string(make([]byte, MaxLocalBytes+1)), 0o644},
	} {
		p := writeLocal(t, c.body, c.mode)
		if l, err := loadLocal(p, me); !errors.Is(err, ErrLocalInvalid) || l.AllowExec {
			t.Errorf("%s: %+v %v", name, l, err)
		}
	}
	// Ссылка — отказ, даже если цель верная.
	link := filepath.Join(t.TempDir(), "agent.toml")
	if err := os.Symlink(ok, link); err != nil {
		t.Fatal(err)
	}
	if l, err := loadLocal(link, me); !errors.Is(err, ErrLocalInvalid) || l.AllowExec {
		t.Fatalf("ссылка: %+v %v", l, err)
	}
	// Каталог вместо файла.
	if l, err := loadLocal(t.TempDir(), me); err == nil || l.AllowExec {
		t.Fatalf("каталог: %+v %v", l, err)
	}
}

// Установщик ставит тот же шаблон, что LocalTemplate, и он выключает exec.run.
func TestInstallerLocalTemplate(t *testing.T) {
	raw, err := os.ReadFile("../../scripts/install.sh")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?s)<<'TOML'\n(.*?)TOML\n`).FindSubmatch(raw)
	if m == nil || string(m[1]) != LocalTemplate {
		t.Fatalf("шаблон установщика расходится с LocalTemplate: %q", m)
	}
	p := writeLocal(t, LocalTemplate, 0o644)
	if l, err := loadLocal(p, uint32(os.Getuid())); err != nil || l.AllowExec {
		t.Fatalf("%+v %v", l, err)
	}
}
