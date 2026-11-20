// SPDX-License-Identifier: AGPL-3.0-only

package tools

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Каждая сумма таблицы записана в decisions своего эпика в одной строке с именем файла выпуска. Отдельный
// репозиторий агента decisions не содержит — там проверка пропускается с причиной.
func TestKnownMatchesDecisions(t *testing.T) {
	dir := filepath.Join("..", "..", "..", "docs", "plan", "decisions")
	if _, err := os.Stat(dir); errors.Is(err, os.ErrNotExist) {
		t.Skip("decisions нет рядом: агент вне монорепозитория Trassa")
	}
	docs := map[string][]string{}
	n := 0
	for tool, versions := range Known {
		src, ok := Sources[tool]
		if !ok {
			t.Fatalf("%s: нет источника в Sources", tool)
		}
		if docs[src.Decisions] == nil {
			raw, err := os.ReadFile(filepath.Join(dir, src.Decisions))
			if err != nil {
				t.Fatal(err)
			}
			docs[src.Decisions] = strings.Split(string(raw), "\n")
		}
		for v, arches := range versions {
			for arch, sum := range arches {
				file := src.File(v, arch)
				found := false
				for _, l := range docs[src.Decisions] {
					if strings.Contains(l, "`"+file+"`") && strings.Contains(l, sum) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("в %s нет строки с %s и %s", src.Decisions, file, sum)
				}
				n++
			}
		}
	}
	if n != 2*len(Known) {
		t.Fatalf("сумм %d, ждали по две (amd64, arm64) на программу", n)
	}
}

func TestCheck(t *testing.T) {
	sum := Known["caddy"]["2.11.9"]["arm64"]
	if err := CheckArch("caddy", "2.11.9", sum, "arm64"); err != nil {
		t.Fatal(err)
	}
	for _, c := range [][4]string{
		{"caddy", "2.11.9", strings.Repeat("0", 64), "arm64"}, // чужая сумма
		{"caddy", "2.11.9", sum, "amd64"},                     // сумма другой архитектуры
		{"caddy", "2.11.8", sum, "arm64"},                     // версии нет
		{"nginx", "1.0.0", sum, "arm64"},                      // программы нет
	} {
		if err := CheckArch(c[0], c[1], c[2], c[3]); !errors.Is(err, ErrUnknown) {
			t.Errorf("%v: %v", c, err)
		}
	}
}
