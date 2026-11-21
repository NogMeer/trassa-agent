// SPDX-License-Identifier: AGPL-3.0-only

package helper

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/config"
	"github.com/NogMeer/trassa-agent/internal/fsinspect"
	"github.com/NogMeer/trassa-agent/internal/helper/execpolicy"
	"github.com/NogMeer/trassa-agent/internal/helper/execrun"
	"github.com/NogMeer/trassa-agent/internal/ops"
)

// CodeInspectUnavailable — disk.usage и config.read на этой сборке не настроены.
const CodeInspectUnavailable = "INSPECT_UNAVAILABLE"

func (e *Executor) operatorHandlers() map[string]handler {
	return map[string]handler{
		ops.TypeDiskUsage:  {apply: e.applyDiskUsage},
		ops.TypeConfigRead: {apply: e.applyConfigRead},
		ops.TypeExecRun:    {preview: e.previewExec, apply: e.applyExec},
	}
}

func inspectFail(r *run, err error) *agentv1.OperationResult {
	code := fsinspect.Code(err)
	if code == "" {
		code = CodeApplyFailed
	}
	return r.failed(code, err.Error())
}

func (e *Executor) applyDiskUsage(ctx context.Context, r *run) *agentv1.OperationResult {
	if e.Inspect == nil {
		return r.failed(CodeInspectUnavailable, "чтение для оператора на этом сервере недоступно")
	}
	out, err := e.Inspect.DiskUsage(ctx, r.body.GetParams().GetDiskUsage())
	if err != nil {
		return inspectFail(r, err)
	}
	msg := ""
	if out.GetTruncated() {
		msg = "обход прерван по времени или числу записей: суммы — нижняя граница"
	}
	res := r.succeeded(msg)
	res.Data = &agentv1.OperationResult_DiskUsage{DiskUsage: out}
	return res
}

func (e *Executor) applyConfigRead(_ context.Context, r *run) *agentv1.OperationResult {
	if e.Inspect == nil {
		return r.failed(CodeInspectUnavailable, "чтение для оператора на этом сервере недоступно")
	}
	out, err := e.Inspect.ConfigRead(r.body.GetParams().GetConfigRead())
	if err != nil {
		return inspectFail(r, err)
	}
	res := r.succeeded("")
	res.Data = &agentv1.OperationResult_ConfigRead{ConfigRead: out}
	return res
}

// ExecAllowed — allow_exec из /etc/trassa/agent.toml; файл не прошёл проверку — false и предупреждение в журнал
// помощника. Читается на каждый вызов: выключение действует сразу, без перезапуска.
func (e *Executor) ExecAllowed() bool {
	load := e.LocalConfig
	if load == nil {
		load = func() (config.Local, error) { return config.LoadLocal(e.Paths.LocalConfig) }
	}
	l, err := load()
	if err != nil {
		e.log().Warn("helper: agent.toml не принят, exec.run выключена", "err", err)
		return false
	}
	return l.AllowExec
}

// capabilities — типы каталога (exec.run — только при allow_exec) и дополнительные возможности.
func (e *Executor) capabilities() []string {
	allow := e.ExecAllowed()
	out := make([]string, 0, len(e.Checker.Catalog.Types())+len(ExtraCapabilities))
	for _, t := range e.Checker.Catalog.Types() {
		if t == ops.TypeExecRun && !allow {
			continue
		}
		out = append(out, t)
	}
	return append(out, ExtraCapabilities...)
}

// execGate — общие проверки предпросмотра и запуска: флаг (раньше всего), запреты R28 над argv, пользователь,
// каталог, программа и запреты ещё раз с путями после ссылок. Возвращает полный путь программы.
func (e *Executor) execGate(r *run) (*agentv1.ExecRunParams, string, *agentv1.OperationResult) {
	if !e.ExecAllowed() {
		return nil, "", r.failed(execrun.CodeDisabled,
			"произвольные команды на этом сервере выключены: allow_exec = true в /etc/trassa/agent.toml включает их")
	}
	if e.Exec == nil {
		return nil, "", r.failed(execrun.CodeUnavailable, "запуск команд на этой сборке не настроен")
	}
	p := r.body.GetParams().GetExecRun()
	denied := func(code, detail string) *agentv1.OperationResult {
		res := r.failed(execrun.CodeDenied, code+": "+detail)
		res.Data = &agentv1.OperationResult_ExecRun{ExecRun: &agentv1.ExecRunResult{ExitCode: -1, DeniedCode: code}}
		return res
	}
	if v := execpolicy.Check(p.GetArgv(), p.GetCwd(), execpolicy.Options{}); !v.Allowed {
		return nil, "", denied(v.Code, v.Detail)
	}
	prog, v, err := e.Exec.Prepare(p)
	switch {
	case errors.Is(err, execrun.ErrProgramInvalid):
		return nil, "", denied(execrun.ErrProgramInvalid.Error(), err.Error())
	case errors.Is(err, execrun.ErrUserInvalid):
		return nil, "", r.failed(execrun.CodeUserInvalid, err.Error())
	case errors.Is(err, execrun.ErrCwdInvalid):
		return nil, "", r.failed(execrun.CodeCwdInvalid, err.Error())
	case err != nil:
		return nil, "", r.failed(execrun.CodeUnavailable, err.Error())
	case !v.Allowed:
		return nil, "", denied(v.Code, v.Detail)
	}
	return p, prog, nil
}

// previewExec — точный текст, пользователь, каталог и разобранные программы; режима dry_run у команды нет.
func (e *Executor) previewExec(_ context.Context, r *run) (*agentv1.Preview, *agentv1.OperationResult) {
	p, prog, fail := e.execGate(r)
	if fail != nil {
		return nil, fail
	}
	return &agentv1.Preview{
		Summary: quoteArgv(p.GetArgv()),
		Notes: []string{
			"Пользователь: " + orDefault(p.GetRunAs(), "root"), "Каталог: " + orDefault(p.GetCwd(), "/"),
			"Программа: " + prog, "Без оболочки: аргументы передаются как есть",
			fmt.Sprintf("Предел: %d с, вывод до %d байт", p.GetTimeoutSec(), p.GetMaxOutputBytes()),
			"Это произвольная команда: Trassa не может предсказать её результат",
		},
	}, nil
}

// quoteArgv — argv для показа: слова с пробелами и кавычками — в одинарных кавычках.
func quoteArgv(argv []string) string {
	out := make([]string, len(argv))
	for i, a := range argv {
		if a == "" || strings.ContainsAny(a, " \t'\"\\|&;<>()*?[]#~`!{}") {
			a = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
		}
		out[i] = a
	}
	return strings.Join(out, " ")
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

func (e *Executor) applyExec(ctx context.Context, r *run) *agentv1.OperationResult {
	p, prog, fail := e.execGate(r)
	if fail != nil {
		return fail
	}
	op := strings.ToLower(r.body.GetOperationId())
	r.system("Команда от %s в %s: %s", orDefault(p.GetRunAs(), "root"), orDefault(p.GetCwd(), "/"), quoteArgv(append([]string{prog}, p.GetArgv()[1:]...)))
	o, err := e.Exec.Run(ctx, execrun.Job{
		Name: "trassa-exec-" + strings.ReplaceAll(op, "-", "")[:16], Program: prog, Params: p,
		Timeout: time.Duration(p.GetTimeoutSec()) * time.Second,
		Output:  func(stream agentv1.LogStream, chunk string) { r.log(stream, chunk) },
	})
	data := &agentv1.ExecRunResult{ExitCode: o.ExitCode, TimedOut: o.TimedOut, OutputBytes: o.Total,
		OutputTruncated: o.Truncated, DurationMs: uint64(o.Duration.Milliseconds()), Programs: []string{prog}}
	var res *agentv1.OperationResult
	switch {
	case err != nil && errors.Is(err, execrun.ErrUnavailable):
		res = r.failed(execrun.CodeUnavailable, err.Error())
	case err != nil:
		res = r.failed(CodeApplyFailed, err.Error())
	case o.TimedOut:
		res = r.failed(execrun.CodeTimeout, fmt.Sprintf("команда не завершилась за %d с: остановлена вместе с дочерними процессами", p.GetTimeoutSec()))
	case o.ExitCode != 0:
		res = r.failed(execrun.CodeFailed, fmt.Sprintf("код возврата %d", o.ExitCode))
	default:
		res = r.succeeded("")
	}
	if o.Truncated {
		r.system("Вывод обрезан: %d байт из %d", p.GetMaxOutputBytes(), o.Total)
	}
	res.Data = &agentv1.OperationResult_ExecRun{ExecRun: data}
	return res
}
