// SPDX-License-Identifier: AGPL-3.0-only

package uninstall

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NogMeer/trassa-agent/internal/config"
)

func layout(t *testing.T) (string, config.Paths) {
	root := t.TempDir()
	p := config.Under(root)
	for _, d := range []string{p.AgentDir, p.HelperDir, p.RollbackDir + "/op", p.BinPrevDir, p.EtcDir, p.RunDir, p.BinDir, p.UnitDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{p.AgentKey, p.Enrollment, filepath.Join(p.BinDir, "trassa-agent"), filepath.Join(p.BinDir, "trassa-helper"),
		filepath.Join(p.BinDir, "other-tool"), filepath.Join(p.UnitDir, "trassa-agent.service"), filepath.Join(p.UnitDir, "trassa-helper.service")} {
		if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root, p
}

func leftovers(root string) []string {
	var out []string
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err == nil && strings.Contains(filepath.Base(path), "trassa") {
			out = append(out, strings.TrimPrefix(path, root))
		}
		return nil
	})
	return out
}

func TestRunPurge(t *testing.T) {
	root, p := layout(t)
	var calls []string
	run := func(_ context.Context, name string, args ...string) error {
		calls = append(calls, name+" "+strings.Join(args, " "))
		return nil
	}
	if err := Run(context.Background(), p, true, run); err != nil {
		t.Fatal(err)
	}
	if left := leftovers(root); len(left) != 0 {
		t.Fatalf("осталось: %v", left)
	}
	if _, err := os.Stat(filepath.Join(p.BinDir, "other-tool")); err != nil {
		t.Fatal("удалён чужой файл")
	}
	want := []string{"/usr/bin/systemctl disable --now trassa-agent.service trassa-helper.service", "/usr/bin/systemctl daemon-reload", "/usr/sbin/userdel trassa"}
	if strings.Join(calls, "\n") != strings.Join(want, "\n") {
		t.Fatalf("%v", calls)
	}
}

func TestRunKeepsRollback(t *testing.T) {
	_, p := layout(t)
	if err := Run(context.Background(), p, false, func(context.Context, string, ...string) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(p.RollbackDir, "op")); err != nil {
		t.Fatal("точки отката удалены без purge_rollback")
	}
	for _, gone := range []string{p.AgentDir, p.HelperDir, p.EtcDir} {
		if _, err := os.Stat(gone); !os.IsNotExist(err) {
			t.Fatalf("%s остался", gone)
		}
	}
}

// Служба firewall Trassa удаляется вместе с агентом (её ExecStop снимает таблицу inet trassa).
func TestPlanFirewallUnit(t *testing.T) {
	p := config.Under(t.TempDir())
	if s := Plan(p, false); len(s.Units) != 2 {
		t.Fatalf("без firewall: %v", s.Units)
	}
	if err := os.MkdirAll(p.UnitDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(p.UnitDir, FirewallUnit), []byte("[Unit]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := Plan(p, false)
	if len(s.Units) != 3 || s.Units[2] != FirewallUnit || s.Paths[2] != filepath.Join(p.UnitDir, FirewallUnit) {
		t.Fatalf("%v %v", s.Units, s.Paths)
	}
}
