// SPDX-License-Identifier: AGPL-3.0-only

package helper

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/ops"
	"github.com/NogMeer/trassa-agent/internal/remedy"
)

func TestDiskCleanupOperation(t *testing.T) {
	f := newFixture(t)
	params := &agentv1.OperationParams{Params: &agentv1.OperationParams_DiskCleanup{DiskCleanup: &agentv1.DiskCleanupParams{
		Categories: []agentv1.DiskCleanupCategory{agentv1.DiskCleanupCategory_DISK_CLEANUP_CATEGORY_APT_CACHE}}}}
	if o := f.exec(sealed(f.body(ops.TypeDiskCleanup, params))); o.result.GetErrorCode() != CodeRemedyUnavailable {
		t.Fatalf("без remedy: %+v", o.result)
	}
	deb := filepath.Join(f.root, "var/cache/apt/archives/x.deb")
	_ = os.MkdirAll(filepath.Dir(deb), 0o755)
	_ = os.WriteFile(deb, make([]byte, 4096), 0o644)
	ran := 0
	f.e.Remedy = &remedy.Env{Root: f.root, Run: func(context.Context, string, ...string) ([]byte, error) { ran++; return nil, nil }}
	b := f.body(ops.TypeDiskCleanup, params)
	b.DryRun = true
	o := f.exec(sealed(b))
	if o.result.GetOutcome() != agentv1.OperationOutcome_OPERATION_OUTCOME_SUCCEEDED || o.result.GetDiskCleanup().GetFreed()[0].GetBytes() != 4096 || ran != 0 {
		t.Fatalf("оценка: %+v ran=%d", o.result, ran)
	}
	if _, err := os.Stat(deb); err != nil {
		t.Fatal("оценка удалила файл")
	}
	// Менеджер пакетов занят — PACKAGE_MANAGER_BUSY, команда не запускалась.
	f.e.Remedy.PackagesBusy = func(context.Context) string { return "lock-frontend (apt, pid 7)" }
	if o := f.exec(sealed(f.body(ops.TypeDiskCleanup, params))); o.result.GetErrorCode() != "PACKAGE_MANAGER_BUSY" || ran != 0 {
		t.Fatalf("занят: %+v", o.result)
	}
}
