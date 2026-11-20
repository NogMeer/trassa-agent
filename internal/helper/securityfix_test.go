// SPDX-License-Identifier: AGPL-3.0-only

package helper

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/ops"
	"github.com/NogMeer/trassa-agent/internal/security"
)

func fixBody(f *fixture, code string, subjects ...string) *agentv1.OperationBody {
	b := f.body(ops.FixPrefix+code, &agentv1.OperationParams{Params: &agentv1.OperationParams_SecurityFix{
		SecurityFix: &agentv1.SecurityFixParams{Subjects: subjects}}})
	b.Rollback = agentv1.RollbackKind_ROLLBACK_KIND_CONFIG
	return b
}

func restoreBody(f *fixture, target string) *agentv1.OperationBody {
	b := f.body(ops.TypeRollbackRestore, &agentv1.OperationParams{Params: &agentv1.OperationParams_RollbackRestore{
		RollbackRestore: &agentv1.RollbackRestoreParams{TargetOperationId: target}}})
	b.Rollback = agentv1.RollbackKind_ROLLBACK_KIND_CONFIG
	return b
}

func mode(t *testing.T, p string) os.FileMode {
	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	return st.Mode().Perm()
}

// Цикл E10-T10: предпросмотр, применение с проверкой, возврат rollback.restore — файл тот же побайтно и с теми же правами.
func TestSecurityFixCycle(t *testing.T) {
	f := newFixture(t)
	root := t.TempDir()
	bad := filepath.Join(root, "etc", "bad.conf")
	if err := os.MkdirAll(filepath.Dir(bad), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bad, []byte("x=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(bad, 0o666); err != nil {
		t.Fatal(err)
	}
	f.e.Security = &security.System{Root: root, RootUID: os.Getuid(), Now: time.Now}
	f.open() // исполнитель пересоздаётся — Security задаётся снова
	f.e.Security = &security.System{Root: root, RootUID: os.Getuid(), Now: time.Now}

	pv := fixBody(f, "PERM_WORLD_WRITABLE", "/etc/bad.conf")
	pv.DryRun = true
	o := f.exec(sealed(pv))
	if ch := o.result.GetPreview().GetFiles(); len(ch) != 1 || !strings.Contains(ch[0].GetDiff(), "0666 → 0664") {
		t.Fatalf("предпросмотр: %+v", o.result)
	}
	if mode(t, bad) != 0o666 {
		t.Fatal("предпросмотр изменил файл")
	}
	fix := fixBody(f, "PERM_WORLD_WRITABLE", "/etc/bad.conf")
	o = f.exec(sealed(fix))
	if o.result.GetOutcome() != agentv1.OperationOutcome_OPERATION_OUTCOME_SUCCEEDED || mode(t, bad) != 0o664 || o.result.GetRollbackPoint().GetFiles() != 1 {
		t.Fatalf("исправление: %+v, права %o", o.result, mode(t, bad))
	}
	o = f.exec(sealed(restoreBody(f, fix.GetOperationId())))
	if o.result.GetOutcome() != agentv1.OperationOutcome_OPERATION_OUTCOME_SUCCEEDED || mode(t, bad) != 0o666 || readText(t, bad) != "x=1\n" {
		t.Fatalf("возврат: %+v, права %o", o.result, mode(t, bad))
	}

	// Объекта нет среди находок — исправлять нечего.
	if o := f.exec(sealed(fixBody(f, "PERM_WORLD_WRITABLE", "/etc/other"))); o.result.GetErrorCode() != CodeFixSubject {
		t.Fatalf("чужой объект: %+v", o.result)
	}
	// Пустой список объектов и неизвестный код отклоняются до выполнения (R1, R7).
	if o := f.exec(sealed(fixBody(f, "PERM_WORLD_WRITABLE"))); o.accepted || o.code != ops.CodeParamsInvalid {
		t.Fatalf("пустой список: %+v", o)
	}
	unknown := fixBody(f, "OPEN_PORTS", "tcp/22")
	if o := f.exec(sealed(unknown)); o.accepted || o.code != ops.CodeTypeUnknown {
		t.Fatalf("код без исправления: %+v", o)
	}
}

// Применение упало посреди исправления — файлы и параметры ядра возвращаются сами, итог ROLLED_BACK.
func TestSecurityFixAutoRevert(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("от root запись в файл только для чтения не падает")
	}
	f := newFixture(t)
	root := t.TempDir()
	write := func(p, s string, m os.FileMode) {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(s), m); err != nil {
			t.Fatal(err)
		}
	}
	write("proc/sys/net/ipv4/conf/all/accept_redirects", "1\n", 0o644)
	write("proc/sys/net/ipv4/tcp_syncookies", "0\n", 0o444) // запись сюда упадёт
	f.e.Security = &security.System{Root: root, RootUID: os.Getuid(), Now: time.Now}
	f.e.Rollback.ProcSys = filepath.Join(root, "proc/sys")
	f.e.Rollback.Exec = func(string, ...string) error { return nil }
	o := f.exec(sealed(fixBody(f, "SYSCTL_NETWORK", "net.ipv4.conf.all.accept_redirects", "net.ipv4.tcp_syncookies")))
	if o.result.GetOutcome() != agentv1.OperationOutcome_OPERATION_OUTCOME_ROLLED_BACK {
		t.Fatalf("%+v", o.result)
	}
	if _, err := os.Stat(filepath.Join(root, security.SysctlFile)); !os.IsNotExist(err) {
		t.Fatal("файл параметров Trassa остался после возврата")
	}
	if b := readText(t, filepath.Join(root, "proc/sys/net/ipv4/conf/all/accept_redirects")); b != "1\n" {
		t.Fatalf("параметр не вернулся: %q", b)
	}
}

func readText(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// system.reboot — таймером systemd не раньше чем через 5 с (итог успевает уйти шлюзу).
func TestSystemReboot(t *testing.T) {
	f := newFixture(t)
	b := f.body(ops.TypeSystemReboot, &agentv1.OperationParams{Params: &agentv1.OperationParams_SystemReboot{SystemReboot: &agentv1.SystemRebootParams{}}})
	o := f.exec(sealed(b))
	if o.result.GetOutcome() != agentv1.OperationOutcome_OPERATION_OUTCOME_SUCCEEDED || !strings.Contains(o.result.GetMessage(), "5 с") {
		t.Fatalf("%+v", o.result)
	}
	f.services.mu.Lock()
	defer f.services.mu.Unlock()
	if len(f.services.scheduled) != 1 || f.services.scheduled[0].unit != "trassa-reboot" || strings.Join(f.services.scheduled[0].argv, " ") != "/usr/bin/systemctl reboot" {
		t.Fatalf("%+v", f.services.scheduled)
	}
	long := f.body(ops.TypeSystemReboot, &agentv1.OperationParams{Params: &agentv1.OperationParams_SystemReboot{SystemReboot: &agentv1.SystemRebootParams{DelaySeconds: 3601}}})
	if o := f.exec(sealed(long)); o.accepted || o.code != ops.CodeParamsInvalid {
		t.Fatalf("%+v", o)
	}
}

// apt/dpkg занят чужим процессом — PACKAGE_MANAGER_BUSY с держателем до начала работы, apt не запускается.
func TestPackagesBusy(t *testing.T) {
	f := newFixture(t)
	root := t.TempDir()
	lock := filepath.Join(root, "var/lib/dpkg/lock-frontend")
	_ = os.MkdirAll(filepath.Dir(lock), 0o755)
	_ = os.WriteFile(lock, nil, 0o640)
	var ran []string
	f.e.Security = &security.System{Root: root, RootUID: os.Getuid(), Now: time.Now,
		Run: func(_ context.Context, name string, args ...string) ([]byte, error) {
			ran = append(ran, name+" "+strings.Join(args, " "))
			return nil, nil
		}}
	pid := holdLock(t, lock)
	// Предусловие: блокировка видна напрямую (если тест упадёт, видно, на каком шаге).
	if h, err := security.PackageManagerBusy(f.e.Security); err != nil || h == nil || h.PID != pid {
		t.Fatalf("держатель не виден напрямую: %+v %v (pid %d)", h, err, pid)
	}
	list := f.body(ops.TypePackagesListUpdates, &agentv1.OperationParams{Params: &agentv1.OperationParams_PackagesListUpdates{PackagesListUpdates: &agentv1.PackagesListUpdatesParams{}}})
	upg := f.body(ops.TypePackagesUpgrade, &agentv1.OperationParams{Params: &agentv1.OperationParams_PackagesUpgrade{PackagesUpgrade: &agentv1.PackagesUpgradeParams{Scope: agentv1.UpgradeScope_UPGRADE_SCOPE_SECURITY}}})
	for _, b := range []*agentv1.OperationBody{list, upg} {
		o := f.exec(sealed(b))
		if o.result.GetErrorCode() != CodePackageManagerBusy || !strings.Contains(o.result.GetMessage(), "pid "+strconv.Itoa(pid)) {
			t.Fatalf("%s: %+v", b.GetType(), o.result)
		}
	}
	for _, c := range ran {
		if strings.HasPrefix(c, "apt-get") {
			t.Fatalf("apt запущен при занятой блокировке: %v", ran)
		}
	}
}
