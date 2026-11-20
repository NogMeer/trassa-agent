// SPDX-License-Identifier: AGPL-3.0-only

package helper

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/backup"
	"github.com/NogMeer/trassa-agent/internal/ops"
	secretkey "github.com/NogMeer/trassa-agent/internal/sealed"
)

const testPlan = "01a1f4b6-f2f2-7e66-85b4-8ff5645600aa"

// fakeRestic — restic для сквозного теста: версия, «репозитория нет», init, backup. Аргументы — в calls.
const fakeRestic = `#!/bin/sh
D="$(dirname "$0")"
printf '%s\n' "$*" >> "$D/calls"
case "$*" in
	version) echo 'restic 0.20.0 compiled with go1.26.10 on linux/amd64' ;;
	*"cat config"*) exit 10 ;;
	*" init"*) echo '{"message_type":"initialized","id":"r1","repository":"x"}' ;;
	*" backup "*) echo '{"message_type":"summary","snapshot_id":"ffffffff55","data_added":42,"files_new":2}' ;;
esac
`

func (f *fixture) enableBackup(t *testing.T) *secretkey.Key {
	t.Helper()
	k, err := secretkey.LoadOrCreate(filepath.Join(f.root, "encryption.key"))
	if err != nil {
		t.Fatal(err)
	}
	f.e.Secrets = k
	f.e.Backup = &backup.Env{
		Store: backup.Store{Dir: f.paths.BackupDir}, BinDir: f.paths.HelperBin, CacheDir: filepath.Join(f.paths.CacheDir, "restic"),
		WorkDir: f.paths.BackupWorkDir, Look: func(n string) (string, error) { return "/usr/bin/" + n, nil },
	}
	return k
}

func TestBackupInitAndRun(t *testing.T) {
	bz, err := exec.LookPath("bzip2")
	if err != nil {
		t.Skip("нет bzip2")
	}
	f := newFixture(t)
	k := f.enableBackup(t)
	b := f.body(ops.TypeBackupInit, nil)
	b.Rollback = agentv1.RollbackKind_ROLLBACK_KIND_CONFIG
	seal := func(field, v string) *agentv1.SealedSecret {
		s, err := secretkey.Seal(k.Public(), secretkey.Info(b.GetServerId(), k.ID, b.GetOperationId(), b.GetType(), testPlan, field), []byte(v))
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	// Агент скачал архив restic в каталог операции.
	stage := StageDir(f.paths, b.GetOperationId())
	_ = os.MkdirAll(stage, 0o700)
	raw := filepath.Join(stage, "restic")
	_ = os.WriteFile(raw, []byte(fakeRestic), 0o755)
	if out, err := exec.Command(bz, raw).CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	_ = os.Rename(raw+".bz2", filepath.Join(stage, backup.ResticStaged))
	arch, _ := os.ReadFile(filepath.Join(stage, backup.ResticStaged))
	sum := sha256.Sum256(arch)
	b.Params = &agentv1.OperationParams{Params: &agentv1.OperationParams_BackupInit{BackupInit: &agentv1.BackupInitParams{
		PlanId: testPlan, ResticVersion: "0.20.0", ResticSha256: hex.EncodeToString(sum[:]),
		ResticUrl: "https://github.com/restic/restic/releases/download/v0.20.0/restic_0.20.0_linux_amd64.bz2",
		Repo: &agentv1.BackupRepo{Url: "s3:https://s3.example.com/bucket/p", Password: seal("password", "repo-pass-1"),
			Env: map[string]*agentv1.SealedSecret{"AWS_SECRET_ACCESS_KEY": seal("env:AWS_SECRET_ACCESS_KEY", "aws-secret-1")}},
	}}}
	o := f.exec(sealed(b))
	if o.result.GetOutcome() != agentv1.OperationOutcome_OPERATION_OUTCOME_SUCCEEDED || o.result.GetBackupInit().GetRepoExisted() {
		t.Fatalf("init: %+v", o.result)
	}
	if o.result.GetRollbackPoint() == nil {
		t.Fatal("у init нет точки отката")
	}
	pw, err := os.ReadFile(filepath.Join(f.paths.BackupDir, testPlan, "password"))
	if err != nil || string(pw) != "repo-pass-1" {
		t.Fatalf("пароль плана: %q %v", pw, err)
	}
	// Секреты не уходят в итог и журнал.
	if s := o.result.String(); strings.Contains(s, "repo-pass-1") || strings.Contains(s, "aws-secret-1") {
		t.Fatal("секрет в итоге")
	}
	run := f.body(ops.TypeBackupRun, &agentv1.OperationParams{Params: &agentv1.OperationParams_BackupRun{BackupRun: &agentv1.BackupRunParams{
		PlanId: testPlan, Sources: []*agentv1.BackupSource{{Name: "files", Source: &agentv1.BackupSource_Path{Path: &agentv1.PathSource{Path: f.root}}}},
	}}})
	o = f.exec(sealed(run))
	if o.result.GetOutcome() != agentv1.OperationOutcome_OPERATION_OUTCOME_SUCCEEDED {
		t.Fatalf("run: %+v", o.result)
	}
	if src := o.result.GetBackupRun().GetSources(); len(src) != 1 || src[0].GetSnapshotId() != "ffffffff55" || src[0].GetBytesAdded() != 42 {
		t.Fatalf("run: %+v", o.result.GetBackupRun())
	}
	// Запрещённый путь — свой код отказа до выполнения.
	bad := f.body(ops.TypeBackupRun, &agentv1.OperationParams{Params: &agentv1.OperationParams_BackupRun{BackupRun: &agentv1.BackupRunParams{
		PlanId: testPlan, Sources: []*agentv1.BackupSource{{Name: "x", Source: &agentv1.BackupSource_Path{Path: &agentv1.PathSource{Path: "/var/lib/trassa/helper"}}}},
	}}})
	expectReject(t, f, sealed(bad), backup.CodePathForbidden)
	// Без настроек плана — понятный код.
	other := f.body(ops.TypeBackupSnapshots, &agentv1.OperationParams{Params: &agentv1.OperationParams_BackupSnapshots{BackupSnapshots: &agentv1.BackupSnapshotsParams{PlanId: "01a1f4b6-f2f2-7e66-85b4-8ff5645600bb"}}})
	if o := f.exec(sealed(other)); o.result.GetErrorCode() != "BACKUP_NOT_CONFIGURED" {
		t.Fatalf("нет плана: %+v", o.result)
	}
	// unconfigure удаляет каталог плана.
	unc := f.body(ops.TypeBackupUnconfigure, &agentv1.OperationParams{Params: &agentv1.OperationParams_BackupUnconfigure{BackupUnconfigure: &agentv1.BackupUnconfigureParams{PlanId: testPlan}}})
	if o := f.exec(sealed(unc)); o.result.GetOutcome() != agentv1.OperationOutcome_OPERATION_OUTCOME_SUCCEEDED {
		t.Fatalf("unconfigure: %+v", o.result)
	}
	if _, err := os.Stat(filepath.Join(f.paths.BackupDir, testPlan)); !os.IsNotExist(err) {
		t.Fatal("каталог плана остался")
	}
}
