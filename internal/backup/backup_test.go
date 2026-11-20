// SPDX-License-Identifier: AGPL-3.0-only

package backup

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	secretkey "github.com/NogMeer/trassa-agent/internal/sealed"
)

const planID = "01a1f4b6-f2f2-7e66-85b4-8ff564561ccb"

func tmp(t *testing.T) string {
	t.Helper()
	d, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestAllowedPath(t *testing.T) {
	for _, p := range []string{"/srv/app", "/home/u/data", "/var/lib/docker/volumes/x/_data", "/etc/nginx"} {
		if !AllowedPath(p) {
			t.Errorf("%s запрещён", p)
		}
	}
	for _, p := range []string{"", "/", "rel", "/proc", "/proc/1", "/sys/x", "/dev/sda", "/run/x", "/etc/trassa", "/etc/trassa/backup",
		"/var/lib/trassa", "/var/lib/trassa/helper", "/a/../b", "/a/./b", "/a//b", "/a/", "/a\nb", "/a\x00b"} {
		if AllowedPath(p) {
			t.Errorf("%q разрешён", p)
		}
	}
	if !AllowedPath("/etc/trassa2") || !AllowedPath("/devices") {
		t.Fatal("префикс без разделителя не запрещает")
	}
}

func TestRepoURL(t *testing.T) {
	for _, u := range []string{"s3:https://s3.example.com/bucket/prefix", "rest:https://bk.example:8000/plan", "rest:http://127.0.0.1:8000/",
		"sftp:trassa-bk-a1@10.0.0.2:/srv/bk/repo"} {
		if err := RepoURL(u); err != nil {
			t.Errorf("%s: %v", u, err)
		}
	}
	for _, u := range []string{"s3:http://s3.example.com/b", "s3:https://user:pw@s3.example.com/b", "rest:https://169.254.169.254/",
		"rest:http://[fe80::1]/", "ftp://x", "/local/path", "sftp:root@host:relative", "s3:https://x.example/b c", "rest:https://0.0.0.0/"} {
		if RepoURL(u) == nil {
			t.Errorf("%s принят", u)
		}
	}
}

func sealedOK() *agentv1.SealedSecret {
	return &agentv1.SealedSecret{Kid: "0123456789abcdef", EncCt: make([]byte, 64)}
}

func TestValidate(t *testing.T) {
	repo := &agentv1.BackupRepo{Url: "s3:https://s3.example.com/b", Password: sealedOK(), Env: map[string]*agentv1.SealedSecret{"AWS_ACCESS_KEY_ID": sealedOK()}}
	init := &agentv1.BackupInitParams{PlanId: planID, Repo: repo, ResticVersion: "0.20.0", ResticSha256: KnownTools["restic"]["0.20.0"][runtime.GOARCH], ResticUrl: "https://github.com/restic/restic/releases/download/v0.20.0/restic_0.20.0_linux_amd64.bz2"}
	if err := ValidateInit(init); err != nil {
		t.Fatal(err)
	}
	badEnv := &agentv1.BackupRepo{Url: repo.Url, Password: sealedOK(), Env: map[string]*agentv1.SealedSecret{"LD_PRELOAD": sealedOK()}}
	for name, p := range map[string]*agentv1.BackupInitParams{
		"план":       {PlanId: "x", Repo: repo, ResticVersion: "0.20.0", ResticSha256: init.ResticSha256, ResticUrl: init.ResticUrl},
		"env":        {PlanId: planID, Repo: badEnv, ResticVersion: "0.20.0", ResticSha256: init.ResticSha256, ResticUrl: init.ResticUrl},
		"http":       {PlanId: planID, Repo: repo, ResticVersion: "0.20.0", ResticSha256: init.ResticSha256, ResticUrl: "http://x/restic.bz2"},
		"сумма":      {PlanId: planID, Repo: repo, ResticVersion: "0.20.0", ResticSha256: "AB", ResticUrl: init.ResticUrl},
		"без пароля": {PlanId: planID, Repo: &agentv1.BackupRepo{Url: repo.Url}, ResticVersion: "0.20.0", ResticSha256: init.ResticSha256, ResticUrl: init.ResticUrl},
	} {
		if ValidateInit(p) == nil {
			t.Errorf("init %s принят", name)
		}
	}
	path := func(p string) *agentv1.BackupSource {
		return &agentv1.BackupSource{Name: "files", Source: &agentv1.BackupSource_Path{Path: &agentv1.PathSource{Path: p}}}
	}
	if err := ValidateRun(&agentv1.BackupRunParams{PlanId: planID, Sources: []*agentv1.BackupSource{path("/srv")}}); err != nil {
		t.Fatal(err)
	}
	if err := ValidateRun(&agentv1.BackupRunParams{PlanId: planID, Sources: []*agentv1.BackupSource{path("/etc/trassa")}}); !errors.Is(err, ErrPathForbidden) {
		t.Fatalf("запрещённый путь: %v", err)
	}
	for name, p := range map[string]*agentv1.BackupRunParams{
		"пусто":    {PlanId: planID},
		"дважды":   {PlanId: planID, Sources: []*agentv1.BackupSource{path("/a"), path("/b")}},
		"без вида": {PlanId: planID, Sources: []*agentv1.BackupSource{{Name: "x"}}},
		"база с -": {PlanId: planID, Sources: []*agentv1.BackupSource{{Name: "db", Source: &agentv1.BackupSource_Postgres{Postgres: &agentv1.DatabaseSource{Database: "-x"}}}}},
	} {
		if ValidateRun(p) == nil {
			t.Errorf("run %s принят", name)
		}
	}
	tempAll := &agentv1.BackupRestoreParams{PlanId: planID, SnapshotId: "abcdef12", Mode: agentv1.RestoreMode_RESTORE_MODE_TEMP_DIR, Selection: &agentv1.RestoreSelection{All: true}}
	if err := ValidateRestore(tempAll); err != nil {
		t.Fatal(err)
	}
	for name, p := range map[string]*agentv1.BackupRestoreParams{
		"пустой выбор": {PlanId: planID, SnapshotId: "abcdef12", Mode: agentv1.RestoreMode_RESTORE_MODE_TEMP_DIR, Selection: &agentv1.RestoreSelection{}},
		"всё и пути":   {PlanId: planID, SnapshotId: "abcdef12", Mode: agentv1.RestoreMode_RESTORE_MODE_TEMP_DIR, Selection: &agentv1.RestoreSelection{All: true, Paths: []string{"/a"}}},
		"dest не тот":  {PlanId: planID, SnapshotId: "abcdef12", Mode: agentv1.RestoreMode_RESTORE_MODE_IN_PLACE, Selection: &agentv1.RestoreSelection{All: true}, DestPath: "/x"},
		"другой без":   {PlanId: planID, SnapshotId: "abcdef12", Mode: agentv1.RestoreMode_RESTORE_MODE_OTHER_SERVER, Selection: &agentv1.RestoreSelection{All: true}},
		"режим":        {PlanId: planID, SnapshotId: "abcdef12", Selection: &agentv1.RestoreSelection{All: true}},
		"снимок":       {PlanId: planID, SnapshotId: "XYZ", Mode: agentv1.RestoreMode_RESTORE_MODE_TEMP_DIR, Selection: &agentv1.RestoreSelection{All: true}},
	} {
		if ValidateRestore(p) == nil {
			t.Errorf("restore %s принят", name)
		}
	}
	if RestoreRollback(tempAll, agentv1.RollbackKind_ROLLBACK_KIND_NONE) != nil ||
		RestoreRollback(tempAll, agentv1.RollbackKind_ROLLBACK_KIND_LOCAL_COPY) == nil {
		t.Fatal("точка отката во временный каталог")
	}
	inPlace := &agentv1.BackupRestoreParams{Mode: agentv1.RestoreMode_RESTORE_MODE_IN_PLACE}
	if RestoreRollback(inPlace, agentv1.RollbackKind_ROLLBACK_KIND_NONE) == nil || RestoreRollback(inPlace, agentv1.RollbackKind_ROLLBACK_KIND_CONFIG) == nil ||
		RestoreRollback(inPlace, agentv1.RollbackKind_ROLLBACK_KIND_LOCAL_COPY) != nil || RestoreRollback(inPlace, agentv1.RollbackKind_ROLLBACK_KIND_SNAPSHOT) != nil {
		t.Fatal("точка отката на место (R13)")
	}
	if ValidatePrune(&agentv1.BackupPruneParams{PlanId: planID, Retention: &agentv1.Retention{}, MaintenanceRepo: repo}) == nil {
		t.Fatal("пустая политика принята (R1)")
	}
	if err := ValidatePrune(&agentv1.BackupPruneParams{PlanId: planID, Retention: &agentv1.Retention{KeepWithinDaily: "7d"}, MaintenanceRepo: repo}); err != nil {
		t.Fatal(err)
	}
	key := "ssh-ed25519 " + strings.Repeat("A", 68) + " src"
	rcl, res := knownTool("rclone", "1.75.2"), knownTool("restic", "0.20.0")
	if err := ValidateTargetEnsure(&agentv1.BackupTargetEnsureParams{Path: "/srv/bk", UnixUser: "trassa-bk-a1", SourcePublicKey: key, SourceAddress: "10.0.0.5", Rclone: rcl, Restic: res}); err != nil {
		t.Fatal(err)
	}
	if ValidateTargetEnsure(&agentv1.BackupTargetEnsureParams{Path: "/srv/bk", UnixUser: "root", SourcePublicKey: key, SourceAddress: "10.0.0.5", Rclone: rcl, Restic: res}) == nil {
		t.Fatal("чужой пользователь принят")
	}
	if ValidateBrowse(&agentv1.BackupBrowseParams{PlanId: planID, SnapshotId: "abcdef12", Path: "/", Limit: 1001}) == nil {
		t.Fatal("limit 1001 принят")
	}
}

// Секрет открывается только для своего сервера, операции, типа, плана и поля.
func TestOpenRepo(t *testing.T) {
	k, err := secretkey.LoadOrCreate(filepath.Join(t.TempDir(), "k"))
	if err != nil {
		t.Fatal(err)
	}
	b := &agentv1.OperationBody{ServerId: "srv", OperationId: "01A1F4B6-F2F2-7E66-85B4-8FF564561CCB", Type: "backup.init"}
	seal := func(field, v string) *agentv1.SealedSecret {
		s, err := secretkey.Seal(k.Public(), secretkey.Info("srv", k.ID, b.OperationId, b.Type, planID, field), []byte(v))
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	repo := &agentv1.BackupRepo{Url: "s3:https://s3.example.com/b", Password: seal("password", "pw-1"),
		Env: map[string]*agentv1.SealedSecret{"AWS_SECRET_ACCESS_KEY": seal("env:AWS_SECRET_ACCESS_KEY", "sk-1")}}
	r, err := OpenRepo(k, b, planID, repo, "")
	if err != nil {
		t.Fatal(err)
	}
	if string(r.Password) != "pw-1" || r.Env["AWS_SECRET_ACCESS_KEY"] != "sk-1" {
		t.Fatalf("%+v", r)
	}
	// Секрет пароля, переложенный в переменную, и секреты для обслуживания (другое поле) не открываются.
	swapped := &agentv1.BackupRepo{Url: repo.Url, Password: repo.Env["AWS_SECRET_ACCESS_KEY"]}
	if _, err := OpenRepo(k, b, planID, swapped, ""); !errors.Is(err, secretkey.ErrOpen) {
		t.Fatalf("переложенный секрет: %v", err)
	}
	if _, err := OpenRepo(k, b, planID, repo, FieldMaintPrefix); !errors.Is(err, secretkey.ErrOpen) {
		t.Fatalf("другое поле: %v", err)
	}
	other := &agentv1.OperationBody{ServerId: "srv", OperationId: "01a1f4b6-0000-7e66-85b4-8ff564561ccb", Type: "backup.init"}
	if _, err := OpenRepo(k, other, planID, repo, ""); !errors.Is(err, secretkey.ErrOpen) {
		t.Fatalf("другая операция: %v", err)
	}
}

func TestStore(t *testing.T) {
	s := Store{Dir: filepath.Join(tmp(t), "backup")}
	if _, err := s.Load(planID); !errors.Is(err, ErrNoPlan) {
		t.Fatalf("нет плана: %v", err)
	}
	in := &Repo{URL: "rest:https://bk.example/p", Password: []byte("pw"), Env: map[string]string{"RESTIC_REST_USERNAME": "u"}, ResticVersion: "0.20.0"}
	if err := s.Save(planID, in); err != nil {
		t.Fatal(err)
	}
	got, err := s.Load(strings.ToUpper(planID))
	if err != nil || got.URL != in.URL || string(got.Password) != "pw" || got.Env["RESTIC_REST_USERNAME"] != "u" || got.ResticVersion != "0.20.0" {
		t.Fatalf("%+v %v", got, err)
	}
	d, _ := s.PlanDir(planID)
	if st, _ := os.Stat(d); st.Mode().Perm() != 0o700 {
		t.Fatalf("каталог %v", st.Mode())
	}
	for _, f := range []string{"plan.json", "password", "env.json"} {
		if st, _ := os.Stat(filepath.Join(d, f)); st.Mode().Perm() != 0o600 {
			t.Fatalf("%s %v", f, st.Mode())
		}
	}
	if err := s.Remove(planID); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(d); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("каталог плана остался")
	}
}

// Пароль — файлом, ключи — окружением; ни один секрет не попадает в аргументы.
func TestResticEnvAndArgs(t *testing.T) {
	f := newFake(t)
	r := f.restic("s3:https://s3.example.com/b", map[string]string{"AWS_ACCESS_KEY_ID": "AKIDEXAMPLE", "AWS_SECRET_ACCESS_KEY": "s3cr3t-value"})
	f.on("snapshots", `[{"id":"aaaaaaaa11","time":"2026-11-20T10:00:00Z","paths":["/srv"],"tags":["trassa","source=files","kind=path"]}]`, 0)
	snaps, err := Snapshots(context.Background(), r)
	if err != nil || len(snaps) != 1 || snaps[0].Tag(TagSourcePrefix) != "files" {
		t.Fatalf("%+v %v", snaps, err)
	}
	env := f.env("snapshots")
	for _, want := range []string{"RESTIC_PASSWORD_FILE=" + r.PasswordFile, "AWS_SECRET_ACCESS_KEY=s3cr3t-value", "RESTIC_REPOSITORY=s3:https://s3.example.com/b"} {
		if !strings.Contains(env, want+"\n") {
			t.Errorf("нет %s", want)
		}
	}
	if strings.Contains(env, "RESTIC_PASSWORD=") {
		t.Fatal("пароль в окружении")
	}
	for _, c := range f.calls() {
		if strings.Contains(c, "s3cr3t") || strings.Contains(c, "correct horse") {
			t.Fatalf("секрет в аргументах: %s", c)
		}
	}
	// Ошибка restic с секретом в тексте — без секрета.
	f.on("snapshots", "", 1, "", `{"message_type":"exit_error","code":1,"message":"auth failed for s3cr3t-value"}`)
	_, err = Snapshots(context.Background(), r)
	if err == nil || strings.Contains(err.Error(), "s3cr3t") {
		t.Fatalf("ошибка: %v", err)
	}
}

func TestResticSFTPCommand(t *testing.T) {
	f := newFake(t)
	r := f.restic("sftp:trassa-bk-a1@10.0.0.2:/repo", nil)
	f.on("snapshots", "[]", 0)
	if _, err := Snapshots(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	c := f.calls()[0]
	for _, want := range []string{"sftp.command=ssh -i " + r.SSHKey, "UserKnownHostsFile=" + r.KnownHosts, "BatchMode=yes", "trassa-bk-a1@10.0.0.2 -s sftp"} {
		if !strings.Contains(c, want) {
			t.Errorf("нет %q в %s", want, c)
		}
	}
}

func TestInitRepo(t *testing.T) {
	f := newFake(t)
	r := f.restic("rest:https://bk.example/p", nil)
	cases := []struct {
		code    int
		existed bool
		err     error
	}{{0, true, nil}, {10, false, nil}, {12, false, ErrRepoExists}, {11, false, ErrRepoLocked}, {1, false, ErrTargetDown}}
	for _, c := range cases {
		f.on("cat", "", c.code)
		f.on("init", `{"message_type":"initialized","id":"x","repository":"r"}`, 0)
		existed, err := InitRepo(context.Background(), r)
		if existed != c.existed || (c.err == nil) != (err == nil) || (c.err != nil && !errors.Is(err, c.err)) {
			t.Errorf("код %d: %v %v", c.code, existed, err)
		}
	}
	// init без сообщения «initialized» — не успех.
	f.on("cat", "", 10)
	f.on("init", "", 0)
	if _, err := InitRepo(context.Background(), r); err == nil {
		t.Fatal("init без подтверждения")
	}
}

func TestBackupSummaryAndPartial(t *testing.T) {
	f := newFake(t)
	r := f.restic("rest:https://bk.example/p", nil)
	out := `{"message_type":"status","bytes_done":5,"total_bytes":10,"files_done":1}
{"message_type":"summary","snapshot_id":"bbbbbbbb22","files_new":3,"files_changed":1,"data_added":100,"total_bytes_processed":1000}
`
	f.on("backup", out, 0)
	var seen Status
	sum, warn, err := Backup(context.Background(), r, BackupSpec{Source: "files", Kind: KindPath, Paths: []string{"/srv"}, Excludes: []string{"*.tmp"}, LimitKiB: 512, Progress: func(s Status) { seen = s }})
	if err != nil || warn != "" || sum.SnapshotID != "bbbbbbbb22" || sum.DataAdded != 100 || seen.BytesDone != 5 {
		t.Fatalf("%+v %q %v", sum, warn, err)
	}
	c := f.calls()[0]
	for _, want := range []string{"--limit-upload 512", "--tag trassa", "--tag source=files", "--tag kind=path", "--exclude *.tmp", "-- /srv"} {
		if !strings.Contains(c, want) {
			t.Errorf("нет %q в %s", want, c)
		}
	}
	f.on("backup", out, 3)
	if _, warn, err := Backup(context.Background(), r, BackupSpec{Source: "files", Kind: KindPath, Paths: []string{"/srv"}}); err != nil || warn == "" {
		t.Fatalf("код 3: %q %v", warn, err)
	}
	f.on("backup", "", 1)
	if _, _, err := Backup(context.Background(), r, BackupSpec{Source: "files", Kind: KindPath, Paths: []string{"/srv"}}); err == nil {
		t.Fatal("сбой без ошибки")
	}
	// Дамп: команда после --, без оболочки.
	f.on("backup", out, 0)
	if _, _, err := Backup(context.Background(), r, BackupSpec{Source: "db", Kind: KindPostgres, Database: "app", StdinCommand: []string{"/usr/bin/docker", "exec", "-u", "postgres", "pg", "pg_dump", "-Fc", "--", "app"}, StdinName: "postgres-app.pgdump"}); err != nil {
		t.Fatal(err)
	}
	last := f.calls()[len(f.calls())-1]
	if !strings.Contains(last, "--stdin-from-command --stdin-filename postgres-app.pgdump -- /usr/bin/docker exec -u postgres pg pg_dump -Fc -- app") || !strings.Contains(last, "--tag database=app") {
		t.Fatalf("%s", last)
	}
}

// Срок окна: restic получает SIGTERM, итог — ErrDeadline.
func TestResticDeadline(t *testing.T) {
	f := newFake(t)
	r := f.restic("rest:https://bk.example/p", nil)
	f.on("backup", "", 0, `trap 'exit 130' TERM; sleep 30 & wait`)
	start := time.Now()
	_, _, err := Backup(context.Background(), r, BackupSpec{Source: "files", Kind: KindPath, Paths: []string{"/srv"}, Deadline: time.Now().Add(300 * time.Millisecond)})
	if !errors.Is(err, ErrDeadline) {
		t.Fatalf("срок: %v", err)
	}
	if time.Since(start) > 10*time.Second {
		t.Fatal("restic не остановлен по сроку")
	}
}

func TestRunPlanSources(t *testing.T) {
	f := newFake(t)
	r := f.restic("rest:https://bk.example/p", nil)
	f.on("backup", `{"message_type":"summary","snapshot_id":"cccccccc33","data_added":7}`+"\n", 0)
	dir := tmp(t)
	e := &Env{Look: func(n string) (string, error) { return "/usr/bin/" + n, nil }}
	res, code, err := e.RunPlan(context.Background(), r, RunJob{Params: &agentv1.BackupRunParams{PlanId: planID, Sources: []*agentv1.BackupSource{
		{Name: "ok", Source: &agentv1.BackupSource_Path{Path: &agentv1.PathSource{Path: dir}}},
		{Name: "gone", Source: &agentv1.BackupSource_Path{Path: &agentv1.PathSource{Path: dir + "/missing"}}},
		{Name: "db", Source: &agentv1.BackupSource_Mysql{Mysql: &agentv1.DatabaseSource{Container: "maria", Database: "shop"}}},
	}}, Deadline: time.Now().Add(time.Minute)})
	if err != nil || code != CodeSourceFailed {
		t.Fatalf("%v %q", err, code)
	}
	if !res.Sources[0].GetOk() || res.Sources[0].GetSnapshotId() != "cccccccc33" || res.Sources[1].GetOk() || res.Sources[1].GetError() == "" || !res.Sources[2].GetOk() {
		t.Fatalf("%+v", res.Sources)
	}
	dump := f.calls()[1]
	if !strings.Contains(dump, "/usr/bin/docker exec maria sh -c") || !strings.HasSuffix(dump, "sh shop") || strings.Contains(dump, "-p") && strings.Contains(dump, "-p\"") {
		t.Fatalf("дамп MySQL: %s", dump)
	}
}

func TestCopyTreeAndBack(t *testing.T) {
	root := tmp(t)
	src := filepath.Join(root, "src")
	if err := os.MkdirAll(filepath.Join(src, "sub"), 0o750); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(src, "sub", "a"), []byte("hello"), 0o640)
	_ = os.Symlink("sub/a", filepath.Join(src, "link"))
	_ = os.Chmod(filepath.Join(src, "sub"), 0o555)
	t.Cleanup(func() { _ = os.Chmod(filepath.Join(src, "sub"), 0o755) })
	if n, err := treeSize(src); err != nil || n != 5 {
		t.Fatalf("%d %v", n, err)
	}
	dst := filepath.Join(root, "copy")
	if err := copyTree(src, dst); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(filepath.Join(dst, "sub"), 0o755) })
	if raw, _ := os.ReadFile(filepath.Join(dst, "sub", "a")); string(raw) != "hello" {
		t.Fatal("содержимое")
	}
	if st, _ := os.Stat(filepath.Join(dst, "sub")); st.Mode().Perm() != 0o555 {
		t.Fatalf("права каталога %v", st.Mode())
	}
	if l, _ := os.Readlink(filepath.Join(dst, "link")); l != "sub/a" {
		t.Fatal("ссылка")
	}
}

// Восстановление на место: локальная копия до замены; проверка не прошла — копия возвращена (ROLLED_BACK).
func TestRestoreInPlaceRollsBack(t *testing.T) {
	f := newFake(t)
	r := f.restic("rest:https://bk.example/p", nil)
	root := tmp(t)
	data := filepath.Join(root, "srv", "app")
	if err := os.MkdirAll(data, 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(data, "config"), []byte("current"), 0o644)
	f.on("snapshots", `[{"id":"dddddddd44","time":"2026-11-20T10:00:00Z","paths":["`+data+`"],"tags":["trassa","source=app","kind=path"]}]`, 0)
	f.on("ls", `{"message_type":"snapshot","id":"dddddddd44"}
{"message_type":"node","name":"app","type":"dir","path":"`+data+`","size":0}
{"message_type":"node","name":"config","type":"file","path":"`+data+`/config","size":8}
`, 0)
	// restore пишет файл не того размера (как оборванное восстановление).
	f.on("restore", `{"message_type":"summary","total_files":1,"files_restored":1,"total_bytes":8,"bytes_restored":3}`+"\n", 0,
		`t=""; prev=""; for a in "$@"; do [ "$prev" = "--target" ] && t="$a"; prev="$a"; done; mkdir -p "$t`+data+`"; printf bad > "$t`+data+`/config"`)
	e := &Env{WorkDir: filepath.Join(root, "work")}
	op := "01a1f4b6-f2f2-7e66-85b4-000000000001"
	out, err := e.Restore(context.Background(), r, RestoreJob{OpID: op, Rollback: agentv1.RollbackKind_ROLLBACK_KIND_LOCAL_COPY,
		Params: &agentv1.BackupRestoreParams{PlanId: planID, SnapshotId: "dddddddd", Mode: agentv1.RestoreMode_RESTORE_MODE_IN_PLACE, Selection: &agentv1.RestoreSelection{All: true}}})
	if !errors.Is(err, ErrRestoreVerify) || out == nil || !out.RolledBack {
		t.Fatalf("%+v %v", out, err)
	}
	if raw, _ := os.ReadFile(filepath.Join(data, "config")); string(raw) != "current" {
		t.Fatalf("локальная копия не вернулась: %q", raw)
	}
	// Удачное восстановление: файл нужного размера.
	f.on("restore", `{"message_type":"summary","total_files":1,"files_restored":1,"total_bytes":8,"bytes_restored":8}`+"\n", 0,
		`t=""; prev=""; for a in "$@"; do [ "$prev" = "--target" ] && t="$a"; prev="$a"; done; mkdir -p "$t`+data+`"; printf restored > "$t`+data+`/config"`)
	op2 := "01a1f4b6-f2f2-7e66-85b4-000000000002"
	out, err = e.Restore(context.Background(), r, RestoreJob{OpID: op2, Rollback: agentv1.RollbackKind_ROLLBACK_KIND_LOCAL_COPY,
		Params: &agentv1.BackupRestoreParams{PlanId: planID, SnapshotId: "dddddddd", Mode: agentv1.RestoreMode_RESTORE_MODE_IN_PLACE, Selection: &agentv1.RestoreSelection{All: true}}})
	if err != nil || out.Result.GetRestoredBytes() != 8 || out.Result.GetPath() != "/" {
		t.Fatalf("%+v %v", out, err)
	}
	// restic распаковывает в каталог помощника и только выбранные пути; на место их переносит помощник.
	if c := f.calls()[len(f.calls())-1]; !strings.Contains(c, "restore dddddddd44 --target "+e.WorkDir+"/restore/") || !strings.Contains(c, "--include "+data) {
		t.Fatalf("%s", c)
	}
	if _, err := os.Stat(filepath.Join(e.WorkDir, "restore", op2)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("каталог распаковки остался")
	}
	// Копия хранится 72 часа: потом её убирает задача помощника.
	if _, err := os.Stat(e.LocalCopyDir(op2)); err != nil {
		t.Fatal("копии нет")
	}
	e.Now = func() time.Time { return time.Now().Add(LocalCopyTTL + time.Hour) }
	if err := e.PruneLocalCopies(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(e.LocalCopyDir(op2)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("копия старше 72 часов осталась")
	}
	// Путь не из снимка — отказ.
	_, err = e.Restore(context.Background(), r, RestoreJob{OpID: op2, Rollback: agentv1.RollbackKind_ROLLBACK_KIND_LOCAL_COPY,
		Params: &agentv1.BackupRestoreParams{PlanId: planID, SnapshotId: "dddddddd", Mode: agentv1.RestoreMode_RESTORE_MODE_IN_PLACE, Selection: &agentv1.RestoreSelection{Paths: []string{"/etc/passwd"}}}})
	if err == nil || !strings.Contains(err.Error(), "нет в снимке") {
		t.Fatalf("чужой путь: %v", err)
	}
	// Снимка нет — BACKUP_SNAPSHOT_PRUNED.
	_, err = e.Restore(context.Background(), r, RestoreJob{OpID: op2, Params: &agentv1.BackupRestoreParams{SnapshotId: "eeeeeeee", Mode: agentv1.RestoreMode_RESTORE_MODE_TEMP_DIR, Selection: &agentv1.RestoreSelection{All: true}}})
	if !errors.Is(err, ErrSnapshotMissing) {
		t.Fatalf("нет снимка: %v", err)
	}
}

func TestInstallRestic(t *testing.T) {
	bz, err := exec.LookPath("bzip2")
	if err != nil {
		t.Skip("нет bzip2")
	}
	root := tmp(t)
	stage, bin := filepath.Join(root, "stage"), filepath.Join(root, "bin")
	_ = os.MkdirAll(stage, 0o700)
	script := "#!/bin/sh\necho 'restic 0.20.0 compiled with go1.26.10 on linux/amd64'\n"
	raw := filepath.Join(stage, "restic")
	_ = os.WriteFile(raw, []byte(script), 0o755)
	if out, err := exec.Command(bz, "-k", raw).CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	_ = os.Rename(raw+".bz2", filepath.Join(stage, ResticStaged))
	arch, _ := os.ReadFile(filepath.Join(stage, ResticStaged))
	sum := sha256hex(arch)
	// Сумма из таблицы агента, а архив другой — не ставится.
	if _, err := InstallRestic(context.Background(), stage, KnownTools["restic"]["0.20.0"][runtime.GOARCH], "0.20.0", bin); !errors.Is(err, ErrResticChecksum) {
		t.Fatalf("архив с другой суммой: %v", err)
	}
	// Сумма архива верна, но её нет в таблице — не ставится.
	if _, err := InstallRestic(context.Background(), stage, sum, "0.20.0", bin); !errors.Is(err, ErrToolUnknown) {
		t.Fatalf("сумма не из таблицы: %v", err)
	}
	withTool(t, "restic", "0.20.0", sum)
	withTool(t, "restic", "0.19.1", sum)
	if _, err := InstallRestic(context.Background(), stage, sum, "0.19.1", bin); err == nil {
		t.Fatal("не та версия принята")
	}
	if _, err := os.Stat(ResticPath(bin, "0.19.1")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("бинарник не той версии остался")
	}
	p, err := InstallRestic(context.Background(), stage, sum, "0.20.0", bin)
	if err != nil || p != ResticPath(bin, "0.20.0") {
		t.Fatalf("%s %v", p, err)
	}
	if v, err := ResticVersion(context.Background(), p); err != nil || v != "0.20.0" {
		t.Fatalf("%s %v", v, err)
	}
}

func TestTargetAppendOnly(t *testing.T) {
	root := tmp(t)
	tg := &Target{Root: root, BinDir: "/usr/local/lib/trassa", Run: func(context.Context, string, ...string) ([]byte, error) { return nil, nil }}
	cmd := RcloneCommand(RclonePath(tg.BinDir, "1.75.2"), "/srv/bk")
	txt := dropInText("trassa-bk-a1", keyFile("trassa-bk-a1"), cmd)
	for _, want := range []string{"Match User trassa-bk-a1", "ForceCommand /usr/local/lib/trassa/rclone-1.75.2 serve restic --stdio --append-only /srv/bk",
		"AuthorizedKeysFile /etc/ssh/trassa-bk/trassa-bk-a1.keys", "PermitTTY no", "AllowTcpForwarding no", "PasswordAuthentication no", "PermitUserRC no"} {
		if !strings.Contains(txt, want+"\n") {
			t.Errorf("нет %q", want)
		}
	}
	// Удаление: путь обязан совпадать с каталогом из состояния Trassa.
	_ = os.MkdirAll(filepath.Join(root, TargetStateDir), 0o700)
	_ = os.WriteFile(filepath.Join(root, stateFile("trassa-bk-a1")), []byte(`{"path":"/srv/bk","rclone":"1.75.2","restic":"0.20.0"}`), 0o600)
	_ = os.MkdirAll(filepath.Join(root, "srv/other"), 0o755)
	err := tg.Remove(context.Background(), &agentv1.BackupTargetRemoveParams{UnixUser: "trassa-bk-a1", Path: "/srv/other", DeleteData: true})
	if !errors.Is(err, ErrTargetPrecondition) {
		t.Fatalf("чужой каталог: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "srv/other")); err != nil {
		t.Fatal("чужой каталог удалён")
	}
	if err := tg.Remove(context.Background(), &agentv1.BackupTargetRemoveParams{UnixUser: "trassa-bk-zz", Path: "/srv/bk"}); !errors.Is(err, ErrTargetPrecondition) {
		t.Fatalf("нет цели: %v", err)
	}
	// Каталог репозитория: чужой непустой — отказ; пустой свой — владелец меняется.
	busy := filepath.Join(root, "srv/busy")
	_ = os.MkdirAll(busy, 0o755)
	_ = os.WriteFile(filepath.Join(busy, "data"), []byte("x"), 0o644)
	if err := tg.repoDir("/srv/busy", os.Getuid()+1, os.Getgid()); !errors.Is(err, ErrTargetPrecondition) {
		t.Fatalf("занятый каталог: %v", err)
	}
	if err := tg.repoDir("/srv/fresh", os.Getuid(), os.Getgid()); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(filepath.Join(root, "srv/fresh")); st.Mode().Perm() != 0o700 {
		t.Fatalf("права каталога %v", st.Mode())
	}
	// Ссылка вместо каталога — отказ.
	_ = os.Symlink(filepath.Join(root, "srv/other"), filepath.Join(root, "srv/link"))
	if err := tg.repoDir("/srv/link", os.Getuid(), os.Getgid()); err == nil {
		t.Fatal("ссылка принята")
	}
}

func TestValidateTargetTools(t *testing.T) {
	key := "ssh-ed25519 " + strings.Repeat("A", 68)
	ok := &agentv1.BackupTargetEnsureParams{Path: "/srv/bk", UnixUser: "trassa-bk-a1", SourcePublicKey: key, SourceAddress: "10.0.0.5",
		Rclone: knownTool("rclone", "1.75.2"), Restic: knownTool("restic", "0.20.0")}
	if err := ValidateTargetEnsure(ok); err != nil {
		t.Fatal(err)
	}
	for name, mod := range map[string]func(p *agentv1.BackupTargetEnsureParams){
		"без rclone":   func(p *agentv1.BackupTargetEnsureParams) { p.Rclone = nil },
		"http":         func(p *agentv1.BackupTargetEnsureParams) { p.Restic.Url = "http://x/r.bz2" },
		"чужая сумма":  func(p *agentv1.BackupTargetEnsureParams) { p.Rclone.Sha256 = strings.Repeat("c", 64) },
		"чужая версия": func(p *agentv1.BackupTargetEnsureParams) { p.Rclone.Version = "1.76.0" },
		"пробел":       func(p *agentv1.BackupTargetEnsureParams) { p.Path = "/srv/b k" },
		"кавычка":      func(p *agentv1.BackupTargetEnsureParams) { p.Path = "/srv/b'k" },
	} {
		p := proto.Clone(ok).(*agentv1.BackupTargetEnsureParams)
		mod(p)
		if ValidateTargetEnsure(p) == nil {
			t.Errorf("%s принят", name)
		}
	}
	if err := RepoURL("rclone:trassa-bk-a1@10.0.0.2:repo"); err != nil {
		t.Fatal(err)
	}
	if RepoURL("rclone:b2:bucket") == nil {
		t.Fatal("rclone без пользователя принят")
	}
	// Чистка на цели: без адреса, с паролем.
	prune := &agentv1.BackupPruneParams{PlanId: planID, TargetUnixUser: "trassa-bk-a1", Retention: &agentv1.Retention{KeepLast: 3},
		MaintenanceRepo: &agentv1.BackupRepo{Password: sealedOK()}}
	if err := ValidatePrune(prune); err != nil {
		t.Fatal(err)
	}
	prune.MaintenanceRepo.Url = "s3:https://x.example/b"
	if ValidatePrune(prune) == nil {
		t.Fatal("чистка на цели с адресом принята")
	}
	init := &agentv1.BackupInitParams{PlanId: planID, Repo: &agentv1.BackupRepo{Url: "rclone:trassa-bk-a1@10.0.0.2:repo", Password: sealedOK()},
		ResticVersion: "0.20.0", ResticSha256: strings.Repeat("a", 64), ResticUrl: "https://x.example/r.bz2", SshHostKey: "ssh-rsa AAAA"}
	if ValidateInit(init) == nil {
		t.Fatal("ключ хоста не ed25519 принят")
	}
}

// rclone: — restic ходит к цели через ssh с ключом плана; ключ хоста закреплён — StrictHostKeyChecking=yes.
func TestResticRcloneTarget(t *testing.T) {
	f := newFake(t)
	r := f.restic("rclone:trassa-bk-a1@10.0.0.2:repo", nil)
	f.on("snapshots", "[]", 0)
	if _, err := Snapshots(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	c := f.calls()[0]
	for _, want := range []string{"rclone.program=ssh -i " + r.SSHKey, "StrictHostKeyChecking=accept-new", "trassa-bk-a1@10.0.0.2", "rclone.args=serve restic --stdio"} {
		if !strings.Contains(c, want) {
			t.Errorf("нет %q в %s", want, c)
		}
	}
	if strings.Contains(c, "-s sftp") {
		t.Fatal("для rclone — не подсистема sftp")
	}
	e := &Env{Store: Store{Dir: filepath.Join(tmp(t), "plans")}}
	d, _ := e.Store.PlanDir(planID)
	_ = os.MkdirAll(d, 0o700)
	key := "ssh-ed25519 " + strings.Repeat("A", 68)
	if err := e.PinHostKey(planID, "rclone:trassa-bk-a1@10.0.0.2:repo", key); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(d, knownHostsFile))
	if string(raw) != "10.0.0.2 "+key+"\n" {
		t.Fatalf("known_hosts: %q", raw)
	}
	if e.PinHostKey(planID, "s3:https://x.example/b", key) == nil {
		t.Fatal("ключ хоста для s3 принят")
	}
	r.KnownHosts = filepath.Join(d, knownHostsFile)
	if _, err := Snapshots(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	if c := f.calls()[1]; !strings.Contains(c, "StrictHostKeyChecking=yes") {
		t.Fatalf("закреплённый ключ: %s", c)
	}
}

func TestInstallRclone(t *testing.T) {
	root := tmp(t)
	stage, bin := filepath.Join(root, "stage"), filepath.Join(root, "bin")
	_ = os.MkdirAll(stage, 0o700)
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	h := &zip.FileHeader{Name: "rclone-v1.75.2-linux-amd64/rclone", Method: zip.Deflate}
	h.SetMode(0o755)
	w, _ := zw.CreateHeader(h)
	_, _ = w.Write([]byte("#!/bin/sh\necho 'rclone v1.75.2'\necho '- os/version: test'\n"))
	rd, _ := zw.Create("rclone-v1.75.2-linux-amd64/README.txt")
	_, _ = rd.Write([]byte("readme"))
	_ = zw.Close()
	_ = os.WriteFile(filepath.Join(stage, RcloneStaged), buf.Bytes(), 0o600)
	sum := sha256hex(buf.Bytes())
	if _, err := InstallRclone(context.Background(), stage, KnownTools["rclone"]["1.75.2"][runtime.GOARCH], "1.75.2", bin); !errors.Is(err, ErrResticChecksum) {
		t.Fatalf("архив с другой суммой: %v", err)
	}
	if _, err := InstallRclone(context.Background(), stage, sum, "1.75.2", bin); !errors.Is(err, ErrToolUnknown) {
		t.Fatalf("сумма не из таблицы: %v", err)
	}
	withTool(t, "rclone", "1.75.2", sum)
	withTool(t, "rclone", "1.76.0", sum)
	if _, err := InstallRclone(context.Background(), stage, sum, "1.76.0", bin); err == nil {
		t.Fatal("не та версия принята")
	}
	p, err := InstallRclone(context.Background(), stage, sum, "1.75.2", bin)
	if err != nil || p != RclonePath(bin, "1.75.2") {
		t.Fatalf("%s %v", p, err)
	}
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o755 {
		t.Fatalf("права %v", st.Mode())
	}
}

// Откат и перенос на место не идут по ссылкам: каталог-родитель, подменённый ссылкой, — отказ, чужое не тронуто.
func TestCopyBackRefusesSymlinkedParent(t *testing.T) {
	root := tmp(t)
	cp := filepath.Join(root, "copy", "site")
	_ = os.MkdirAll(cp, 0o755)
	_ = os.WriteFile(filepath.Join(cp, "ld.so.preload"), []byte("/home/x.so"), 0o644)
	victim := filepath.Join(root, "etc")
	_ = os.MkdirAll(victim, 0o755)
	home := filepath.Join(root, "home")
	if err := os.Symlink(victim, home); err != nil {
		t.Fatal(err)
	}
	if err := copyBack(cp, filepath.Join(home, "site")); err == nil {
		t.Fatal("перенос через каталог-ссылку прошёл")
	}
	if _, err := os.Stat(filepath.Join(victim, "site")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("запись ушла за ссылку")
	}
	// Удаление «созданного восстановлением» тоже не уходит за ссылку.
	_ = os.WriteFile(filepath.Join(victim, "keep"), []byte("x"), 0o644)
	if err := removeNoFollow(filepath.Join(home, "keep")); err == nil {
		t.Fatal("удаление через каталог-ссылку прошло")
	}
	if _, err := os.Stat(filepath.Join(victim, "keep")); err != nil {
		t.Fatal("чужой файл удалён")
	}
	// Ссылка внутри удаляемого дерева удаляется сама, её цель цела.
	tree := filepath.Join(root, "tree")
	_ = os.MkdirAll(tree, 0o755)
	_ = os.Symlink(victim, filepath.Join(tree, "link"))
	if err := removeNoFollow(tree); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(victim, "keep")); err != nil {
		t.Fatal("удаление прошло по ссылке внутри дерева")
	}
}

// Пути снимка с шаблонами restic и дампы не в корне — отказ до восстановления.
func TestRestoreRejectsPatternPaths(t *testing.T) {
	f := newFake(t)
	r := f.restic("rest:https://bk.example/p", nil)
	f.on("snapshots", `[{"id":"abababab11","time":"2026-11-20T10:00:00Z","paths":["/srv/*"],"tags":["trassa","source=x","kind=path"]},
{"id":"cdcdcdcd22","time":"2026-11-20T10:00:00Z","paths":["/../../etc/x.pgdump"],"tags":["trassa","source=db","kind=postgres","database=app"]}]`, 0)
	e := &Env{WorkDir: filepath.Join(tmp(t), "work")}
	for _, id := range []string{"abababab", "cdcdcdcd"} {
		_, err := e.Restore(context.Background(), r, RestoreJob{OpID: "01a1f4b6-f2f2-7e66-85b4-000000000009",
			Params: &agentv1.BackupRestoreParams{SnapshotId: id, Mode: agentv1.RestoreMode_RESTORE_MODE_TEMP_DIR, Selection: &agentv1.RestoreSelection{All: true}}})
		if !errors.Is(err, ErrPathForbidden) {
			t.Errorf("%s: %v", id, err)
		}
	}
}

func knownTool(tool, version string) *agentv1.BackupTool {
	return &agentv1.BackupTool{Version: version, Sha256: KnownTools[tool][version][runtime.GOARCH], Url: "https://x.example/" + tool}
}

// withTool — временно разрешить сумму в таблице (поддельные архивы тестов).
func withTool(t *testing.T, tool, version, sha string) {
	t.Helper()
	prev, had := KnownTools[tool][version]
	m := map[string]string{}
	for k, v := range prev {
		m[k] = v
	}
	m[runtime.GOARCH] = sha
	KnownTools[tool][version] = m
	t.Cleanup(func() {
		if had {
			KnownTools[tool][version] = prev
		} else {
			delete(KnownTools[tool], version)
		}
	})
}
