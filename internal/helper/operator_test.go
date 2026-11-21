// SPDX-License-Identifier: AGPL-3.0-only

package helper

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/config"
	"github.com/NogMeer/trassa-agent/internal/fsinspect"
	"github.com/NogMeer/trassa-agent/internal/helper/execpolicy"
	"github.com/NogMeer/trassa-agent/internal/helper/execrun"
	"github.com/NogMeer/trassa-agent/internal/helperrpc"
	"github.com/NogMeer/trassa-agent/internal/ops"
)

type fakeRunner struct {
	jobs    []execrun.Job
	prepErr error
	verdict *execpolicy.Verdict
	out     execrun.Outcome
	print   string
}

func (f *fakeRunner) Prepare(p *agentv1.ExecRunParams) (string, execpolicy.Verdict, error) {
	if f.prepErr != nil {
		return "", execpolicy.Verdict{}, f.prepErr
	}
	if f.verdict != nil {
		return "/usr/bin/" + p.GetArgv()[0], *f.verdict, nil
	}
	return "/usr/bin/" + p.GetArgv()[0], execpolicy.Verdict{Allowed: true}, nil
}
func (f *fakeRunner) Run(_ context.Context, j execrun.Job) (execrun.Outcome, error) {
	f.jobs = append(f.jobs, j)
	if f.print != "" {
		j.Output(agentv1.LogStream_LOG_STREAM_STDOUT, f.print)
	}
	return f.out, nil
}

func execParams(cmd string) *agentv1.OperationParams {
	return &agentv1.OperationParams{Params: &agentv1.OperationParams_ExecRun{ExecRun: &agentv1.ExecRunParams{
		Argv: strings.Fields(cmd), TimeoutSec: 30, MaxOutputBytes: 4096}}}
}

func (f *fixture) execBody(cmd string) *agentv1.OperationBody {
	b := f.body(ops.TypeExecRun, execParams(cmd))
	b.Rollback = agentv1.RollbackKind_ROLLBACK_KIND_SNAPSHOT
	return b
}

func caps(t *testing.T, e *Executor) []string {
	t.Helper()
	var out []string
	e.Serve(context.Background(), helperrpc.Request{Method: helperrpc.MethodHello}, func(r helperrpc.Response) error {
		out = r.Capabilities
		return nil
	})
	return out
}

// Без allow_exec команда не запускается даже с верной подписью, а exec.run нет в capabilities (R7, T4).
func TestExecDisabledWithoutLocalFlag(t *testing.T) {
	f := newFixture(t)
	r := &fakeRunner{}
	f.e.Exec = r
	if slices.Contains(caps(t, f.e), ops.TypeExecRun) {
		t.Fatal("exec.run в capabilities без флага")
	}
	for _, dry := range []bool{false, true} {
		b := f.execBody("systemctl status nginx")
		b.DryRun = dry
		o := f.exec(sealed(b))
		if !o.accepted || o.result.GetErrorCode() != execrun.CodeDisabled {
			t.Fatalf("dry=%v: %+v %+v", dry, o, o.result)
		}
	}
	// Файл есть, но доступен на запись группе (агент мог бы его переписать) — тоже выключено.
	if err := os.MkdirAll(f.paths.EtcDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.paths.LocalConfig, []byte("allow_exec = true\n"), 0o664); err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(f.paths.LocalConfig, 0o664)
	if o := f.exec(sealed(f.execBody("uptime"))); o.result.GetErrorCode() != execrun.CodeDisabled {
		t.Fatalf("файл 0664: %+v", o.result)
	}
	if len(r.jobs) != 0 {
		t.Fatal("команда запускалась")
	}
	// Флаг включён: тип появляется в Hello и в system.info.
	f.e.LocalConfig = func() (config.Local, error) { return config.Local{AllowExec: true}, nil }
	if !slices.Contains(caps(t, f.e), ops.TypeExecRun) {
		t.Fatal("нет exec.run при флаге")
	}
	if o := f.exec(sealed(f.body(ops.TypeSystemInfo, infoParams()))); !o.result.GetSystemInfo().GetAllowExec() {
		t.Fatalf("system.info: %+v", o.result)
	}
	// Повреждённый файл — выключено.
	f.e.LocalConfig = func() (config.Local, error) { return config.Local{}, config.ErrLocalInvalid }
	if slices.Contains(caps(t, f.e), ops.TypeExecRun) {
		t.Fatal("exec.run при ошибке файла")
	}
}

func TestExecRunPolicyAndOutput(t *testing.T) {
	f := newFixture(t)
	f.e.LocalConfig = func() (config.Local, error) { return config.Local{AllowExec: true}, nil }
	r := &fakeRunner{print: "ok\npassword=hunter2hunter2\n"}
	f.e.Exec = r

	// Запрет R28 — EXEC_DENIED с кодом причины, запуска нет.
	o := f.exec(sealed(f.execBody("cat /etc//shadow")))
	if o.result.GetErrorCode() != execrun.CodeDenied || o.result.GetExecRun().GetDeniedCode() != "EXEC_SECRETS_READ" || len(r.jobs) != 0 {
		t.Fatalf("запрет: %+v", o.result)
	}
	// Без SNAPSHOT в теле — отказ проверки (R13).
	b := f.execBody("uptime")
	b.Rollback = agentv1.RollbackKind_ROLLBACK_KIND_NONE
	if o := f.exec(sealed(b)); o.accepted || o.code != ops.CodeParamsInvalid {
		t.Fatalf("без снапшота: %+v", o)
	}
	// Строка command (прежняя форма) не принимается.
	b = f.execBody("uptime")
	b.GetParams().GetExecRun().Command = "uptime"
	if o := f.exec(sealed(b)); o.accepted || o.code != ops.CodeParamsInvalid {
		t.Fatalf("command: %+v", o)
	}
	// Запрет, найденный только после ссылок (Prepare), — тоже EXEC_DENIED; программа, которую может подменить не
	// root, — EXEC_DENIED с EXEC_PROGRAM_INVALID.
	r.verdict = &execpolicy.Verdict{Code: "EXEC_RUNS_COMMANDS", Detail: "dash"}
	if o := f.exec(sealed(f.execBody("sh2"))); o.result.GetErrorCode() != execrun.CodeDenied || o.result.GetExecRun().GetDeniedCode() != "EXEC_RUNS_COMMANDS" {
		t.Fatalf("после ссылок: %+v", o.result)
	}
	r.verdict = nil
	r.prepErr = execrun.ErrProgramInvalid
	if o := f.exec(sealed(f.execBody("tool"))); o.result.GetErrorCode() != execrun.CodeDenied || o.result.GetExecRun().GetDeniedCode() != "EXEC_PROGRAM_INVALID" {
		t.Fatalf("программа: %+v", o.result)
	}
	r.prepErr = nil
	// run_as trassa — EXEC_USER_INVALID до запуска.
	b = f.execBody("uptime")
	b.GetParams().GetExecRun().RunAs = "trassa"
	if o := f.exec(sealed(b)); o.accepted || o.code != execrun.CodeUserInvalid {
		t.Fatalf("run_as trassa: %+v", o)
	}
	// Предпросмотр: точный argv и полный путь программы, без запуска.
	b = f.execBody("systemctl status nginx")
	b.GetParams().GetExecRun().Argv = []string{"grep", "-r", "server name", "/etc/nginx"}
	b.DryRun = true
	o = f.exec(sealed(b))
	if o.result.GetPreview().GetSummary() != "grep -r 'server name' /etc/nginx" || len(r.jobs) != 0 ||
		!strings.Contains(strings.Join(o.result.GetPreview().GetNotes(), "\n"), "/usr/bin/grep") {
		t.Fatalf("предпросмотр: %+v", o.result)
	}
	// Запуск: вывод в журнал с вычищенными секретами, код 0 — успех.
	o = f.exec(sealed(f.execBody("systemctl status nginx")))
	if o.result.GetOutcome() != agentv1.OperationOutcome_OPERATION_OUTCOME_SUCCEEDED || len(r.jobs) != 1 {
		t.Fatalf("запуск: %+v", o.result)
	}
	if j := r.jobs[0]; !strings.HasPrefix(j.Name, "trassa-exec-") || len(j.Name) != len("trassa-exec-")+16 || j.Timeout != 30*time.Second ||
		j.Program != "/usr/bin/systemctl" || o.result.GetExecRun().GetPrograms()[0] != "/usr/bin/systemctl" {
		t.Fatalf("job: %+v", j)
	}
	var log strings.Builder
	for _, p := range o.progress {
		log.WriteString(p.GetChunk() + "\n")
	}
	if !strings.Contains(log.String(), "ok") || strings.Contains(log.String(), "hunter2") {
		t.Fatalf("журнал: %q", log.String())
	}
	// Код возврата не 0 — EXEC_FAILED; таймаут — EXEC_TIMEOUT.
	r.out = execrun.Outcome{ExitCode: 3}
	if o := f.exec(sealed(f.execBody("false"))); o.result.GetErrorCode() != execrun.CodeFailed || o.result.GetExecRun().GetExitCode() != 3 {
		t.Fatalf("код 3: %+v", o.result)
	}
	r.out = execrun.Outcome{ExitCode: -1, TimedOut: true}
	if o := f.exec(sealed(f.execBody("sleep 100"))); o.result.GetErrorCode() != execrun.CodeTimeout || !o.result.GetExecRun().GetTimedOut() {
		t.Fatalf("таймаут: %+v", o.result)
	}
	// Каталога нет — EXEC_CWD_INVALID.
	r.prepErr = errors.Join(execrun.ErrCwdInvalid)
	if o := f.exec(sealed(f.execBody("uptime"))); o.result.GetErrorCode() != execrun.CodeCwdInvalid {
		t.Fatalf("cwd: %+v", o.result)
	}
}

func TestDiskUsageAndConfigReadOperations(t *testing.T) {
	f := newFixture(t)
	root := t.TempDir()
	f.e.Inspect = &fsinspect.Env{Root: root}
	if err := os.MkdirAll(filepath.Join(root, "etc/nginx"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc/nginx/nginx.conf"), []byte("worker_processes 1;\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	read := func(p string) outcome {
		return f.exec(sealed(f.body(ops.TypeConfigRead, &agentv1.OperationParams{Params: &agentv1.OperationParams_ConfigRead{
			ConfigRead: &agentv1.ConfigReadParams{Path: p}}})))
	}
	if o := read("/etc/nginx/nginx.conf"); o.result.GetConfigRead().GetContent() != "worker_processes 1;\n" {
		t.Fatalf("чтение: %+v", o)
	}
	// Вне списка — свой код ещё на проверке параметров.
	for _, p := range []string{"/etc/shadow", "/etc/nginx/../shadow", "/etc/trassa/agent.toml"} {
		if o := read(p); o.accepted || o.code != fsinspect.CodeConfigPathForbidden {
			t.Fatalf("%s: %+v", p, o)
		}
	}
	if o := read("/etc/nginx/none.conf"); o.result.GetErrorCode() != fsinspect.CodeConfigNotFound {
		t.Fatalf("нет файла: %+v", o.result)
	}
	du := f.exec(sealed(f.body(ops.TypeDiskUsage, &agentv1.OperationParams{Params: &agentv1.OperationParams_DiskUsage{
		DiskUsage: &agentv1.DiskUsageParams{Path: "/", Depth: 2, Top: 5}}})))
	if du.result.GetOutcome() != agentv1.OperationOutcome_OPERATION_OUTCOME_SUCCEEDED || len(du.result.GetDiskUsage().GetEntries()) == 0 {
		t.Fatalf("disk.usage: %+v", du.result)
	}
	if o := f.exec(sealed(f.body(ops.TypeDiskUsage, &agentv1.OperationParams{Params: &agentv1.OperationParams_DiskUsage{
		DiskUsage: &agentv1.DiskUsageParams{Path: "/etc", Depth: 1, Top: 5}}}))); o.accepted || o.code != fsinspect.CodeDiskPathForbidden {
		t.Fatalf("/etc: %+v", o)
	}
}
