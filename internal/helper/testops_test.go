// SPDX-License-Identifier: AGPL-3.0-only

//go:build testops

package helper

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/ops"
)

func (f *fixture) configWrite(path, content string, breakVerify bool, cw uint32) *agentv1.OperationBody {
	b := f.body(ops.TypeTestConfigWrite, &agentv1.OperationParams{Params: &agentv1.OperationParams_TestConfigWrite{
		TestConfigWrite: &agentv1.TestConfigWriteParams{Path: path, Content: content, BreakVerify: breakVerify, ConfirmWithin: cw},
	}})
	b.Rollback = agentv1.RollbackKind_ROLLBACK_KIND_CONFIG
	b.ConfirmWithinSec = cw
	return b
}

func (f *fixture) target(content string) string {
	p := filepath.Join(f.root, "etc", "demo.conf")
	_ = os.MkdirAll(filepath.Dir(p), 0o755)
	if err := os.WriteFile(p, []byte(content), 0o640); err != nil {
		f.t.Fatal(err)
	}
	return p
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestConfigWriteSucceeds(t *testing.T) {
	f := newFixture(t)
	p := f.target("old\n")
	pv := f.configWrite(p, "new\n", false, 0)
	pv.DryRun = true
	o := f.exec(sealed(pv))
	if d := o.result.GetPreview().GetFiles()[0].GetDiff(); !strings.Contains(d, "-old") || !strings.Contains(d, "+new") {
		t.Fatalf("разница: %q", d)
	}
	if readFile(t, p) != "old\n" {
		t.Fatal("предпросмотр изменил файл")
	}
	o = f.exec(sealed(f.configWrite(p, "new\n", false, 0)))
	if o.result.GetOutcome() != agentv1.OperationOutcome_OPERATION_OUTCOME_SUCCEEDED || readFile(t, p) != "new\n" {
		t.Fatalf("%+v", o.result)
	}
	if o.result.GetRollbackPoint().GetFiles() != 1 {
		t.Fatal("нет точки отката в итоге")
	}
	st, _ := os.Stat(p)
	if st.Mode().Perm() != 0o640 {
		t.Fatalf("права сменились: %v", st.Mode().Perm())
	}
}

// break_verify: проверка не прошла → файл возвращён, ROLLED_BACK VERIFY_FAILED (приёмка п. 5).
func TestConfigWriteBreakVerify(t *testing.T) {
	f := newFixture(t)
	p := f.target("old\n")
	o := f.exec(sealed(f.configWrite(p, "new\n", true, 0)))
	if o.result.GetOutcome() != agentv1.OperationOutcome_OPERATION_OUTCOME_ROLLED_BACK || o.result.GetErrorCode() != CodeVerifyFailed {
		t.Fatalf("%+v", o.result)
	}
	if readFile(t, p) != "old\n" {
		t.Fatal("файл не возвращён")
	}
	if len(o.progress) == 0 {
		t.Fatal("нет вывода хода")
	}
}

func TestRollbackUnavailable(t *testing.T) {
	f := newFixture(t)
	p := f.target("old\n")
	f.e.Rollback.MaxBytes = 1
	o := f.exec(sealed(f.configWrite(p, "new\n", false, 0)))
	if o.result.GetOutcome() != agentv1.OperationOutcome_OPERATION_OUTCOME_FAILED || o.result.GetErrorCode() != CodeRollbackUnavailable {
		t.Fatalf("%+v", o.result)
	}
	if readFile(t, p) != "old\n" {
		t.Fatal("операция выполнена без точки отката (R13)")
	}
	// Таймер не заводится — тоже ROLLBACK_UNAVAILABLE, файл не тронут.
	f.e.Rollback.MaxBytes = 0
	f.timer.failOn = true
	o = f.exec(sealed(f.configWrite(p, "new\n", false, 30)))
	if o.result.GetErrorCode() != CodeRollbackUnavailable || readFile(t, p) != "old\n" {
		t.Fatalf("%+v", o.result)
	}
	if recs, _ := f.e.Auto.List(); len(recs) != 0 {
		t.Fatal("запись автооткатa осталась без таймера")
	}
}

// S5: подтверждение снимает таймер.
func TestAutoRollbackConfirmed(t *testing.T) {
	f := newFixture(t)
	p := f.target("old\n")
	b := f.configWrite(p, "new\n", false, 30)
	o := f.exec(sealed(b))
	if o.result.GetOutcome() != agentv1.OperationOutcome_OPERATION_OUTCOME_AWAITING_CONFIRM {
		t.Fatalf("%+v", o.result)
	}
	a, ok := f.timer.get(b.GetOperationId())
	if !ok || a.after != 30*time.Second || a.helper != filepath.Join(f.paths.BinDir, "trassa-helper") {
		t.Fatalf("таймер: %+v %v", a, ok)
	}
	res, code := f.confirm(b.GetOperationId())
	if code != "" || res.GetOutcome() != agentv1.OperationOutcome_OPERATION_OUTCOME_SUCCEEDED {
		t.Fatalf("%q %+v", code, res)
	}
	if _, ok := f.timer.get(b.GetOperationId()); ok {
		t.Fatal("таймер не снят")
	}
	// Сработавший позже таймер ничего не делает.
	if err := f.e.AutoRollback(context.Background(), b.GetOperationId()); err != nil {
		t.Fatal(err)
	}
	if readFile(t, p) != "new\n" {
		t.Fatal("откат после подтверждения")
	}
	// Повторное подтверждение возвращает тот же итог.
	if res, code := f.confirm(b.GetOperationId()); code != "" || res.GetOutcome() != agentv1.OperationOutcome_OPERATION_OUTCOME_SUCCEEDED {
		t.Fatalf("повтор: %q %+v", code, res)
	}
}

// S5: подтверждения нет — таймер возвращает файл, итог AUTO_ROLLBACK_NO_CONFIRM ждёт отправки.
func TestAutoRollbackFires(t *testing.T) {
	f := newFixture(t)
	p := f.target("old\n")
	b := f.configWrite(p, "new\n", false, 30)
	f.exec(sealed(b))
	_ = f.e.Reported(b.GetOperationId(), int32(agentv1.OperationOutcome_OPERATION_OUTCOME_AWAITING_CONFIRM))
	// Таймер запускает отдельный процесс: новый исполнитель на тех же каталогах.
	f.open()
	if err := f.e.AutoRollback(context.Background(), b.GetOperationId()); err != nil {
		t.Fatal(err)
	}
	if readFile(t, p) != "old\n" {
		t.Fatal("файл не возвращён")
	}
	st := f.state(b.GetOperationId())
	if st.Status != StatusDone || st.Reported {
		t.Fatalf("%+v", st)
	}
	reps, _ := f.e.Reports()
	if len(reps) != 1 {
		t.Fatal("итог автооткатa не ждёт отправки")
	}
	if _, code := f.confirm(b.GetOperationId()); code != "" {
		t.Fatalf("подтверждение после отката: %q", code)
	}
	if readFile(t, p) != "old\n" {
		t.Fatal("подтверждение после отката вернуло изменение")
	}
	o := f.exec(sealed(b))
	if o.result.GetErrorCode() != CodeAutoRollback || o.result.GetOutcome() != agentv1.OperationOutcome_OPERATION_OUTCOME_ROLLED_BACK {
		t.Fatalf("повторная доставка: %+v", o.result)
	}
}

// Перезагрузка во время ожидания: таймер пропал, помощник заводит новый на остаток; срок вышел — откат сразу.
func TestAutoRollbackAfterReboot(t *testing.T) {
	f := newFixture(t)
	p := f.target("old\n")
	b := f.configWrite(p, "new\n", false, 60)
	f.exec(sealed(b))
	op := b.GetOperationId()
	f.timer.armed = nil // /run очищен
	f.boot = "boot-2"
	f.clock.Add(20 * time.Second)
	f.open()
	if err := f.e.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	a, ok := f.timer.get(op)
	if !ok || a.after != 40*time.Second {
		t.Fatalf("таймер на остаток: %+v %v", a, ok)
	}
	if readFile(t, p) != "new\n" {
		t.Fatal("откат раньше срока")
	}
	rec, _ := f.e.Auto.Get(op)
	if rec.BootID != "boot-2" {
		t.Fatal("boot_id не обновлён")
	}
	// Ещё перезагрузка, теперь после срока.
	f.timer.armed = nil
	f.boot = "boot-3"
	f.clock.Add(time.Minute)
	f.open()
	if err := f.e.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if readFile(t, p) != "old\n" || f.state(op).Status != StatusDone {
		t.Fatal("просроченный автооткат не выполнен при старте")
	}
}

// Помощник упал посреди операции: при старте возврат по точке отката.
func TestRecoverInterrupted(t *testing.T) {
	f := newFixture(t)
	p := f.target("old\n")
	op := newUUID()
	if _, err := f.e.Rollback.Create(op, []string{p}, nil); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(p, []byte("half"), 0o640)
	_ = f.e.States.Put(&OpState{OperationID: op, Type: ops.TypeTestConfigWrite, Mutating: true, Status: StatusRunning})
	f.open()
	if err := f.e.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if readFile(t, p) != "old\n" {
		t.Fatal("прерванная операция не откатилась")
	}
	reps, _ := f.e.Reports()
	if len(reps) != 1 {
		t.Fatal("нет итога прерванной операции")
	}
}

// S7: rollback.restore возвращает файл, хэши и права равны сохранённым; у возврата своя точка отката.
func TestRollbackRestore(t *testing.T) {
	f := newFixture(t)
	p := f.target("old\n")
	w := f.configWrite(p, "new\n", false, 0)
	f.exec(sealed(w))
	restore := func() *agentv1.OperationBody {
		b := f.body(ops.TypeRollbackRestore, &agentv1.OperationParams{Params: &agentv1.OperationParams_RollbackRestore{
			RollbackRestore: &agentv1.RollbackRestoreParams{TargetOperationId: w.GetOperationId()}}})
		b.Rollback = agentv1.RollbackKind_ROLLBACK_KIND_CONFIG
		return b
	}
	pv := restore()
	pv.DryRun = true
	if o := f.exec(sealed(pv)); len(o.result.GetPreview().GetFiles()) != 1 {
		t.Fatalf("предпросмотр: %+v", o.result)
	}
	rb := restore()
	o := f.exec(sealed(rb))
	if o.result.GetOutcome() != agentv1.OperationOutcome_OPERATION_OUTCOME_SUCCEEDED || readFile(t, p) != "old\n" {
		t.Fatalf("%+v", o.result)
	}
	if _, err := f.e.Rollback.Load(rb.GetOperationId()); err != nil {
		t.Fatal("у возврата нет своей точки отката")
	}
	// Нет точки — ROLLBACK_NOT_AVAILABLE.
	none := f.body(ops.TypeRollbackRestore, &agentv1.OperationParams{Params: &agentv1.OperationParams_RollbackRestore{
		RollbackRestore: &agentv1.RollbackRestoreParams{TargetOperationId: newUUID()}}})
	none.Rollback = agentv1.RollbackKind_ROLLBACK_KIND_CONFIG
	if o := f.exec(sealed(none)); o.result.GetErrorCode() != CodeRollbackNotAvailable {
		t.Fatalf("%+v", o.result)
	}
}

func TestTestOpsPathGuard(t *testing.T) {
	f := newFixture(t)
	for _, p := range []string{"/var/lib/trassa/helper/nonces", "/etc/trassa/enrollment.json", "relative", "/etc/../etc/x", "/"} {
		expectReject(t, f, sealed(f.configWrite(p, "x", false, 0)), ops.CodeParamsInvalid)
	}
	b := f.configWrite("/tmp/x", "x", false, 30)
	b.ConfirmWithinSec = 10
	expectReject(t, f, sealed(b), ops.CodeParamsInvalid)
}

func (f *fixture) state(op string) *OpState {
	st, err := f.e.States.Get(op)
	if err != nil {
		f.t.Fatal(err)
	}
	return st
}

// Автооткат дольше предела каталога — отказ проверки 6 до выполнения: сервер без связи не должен ждать часами.
func TestConfirmWithinAboveMax(t *testing.T) {
	f := newFixture(t)
	b := f.configWrite(f.target("old"), "new", false, ops.MaxConfirmWithin+1)
	b.GetParams().GetTestConfigWrite().ConfirmWithin = 30 // предел — по полю тела, а не по параметрам типа
	expectReject(t, f, sealed(b), ops.CodeParamsInvalid)
}

// Возврат операции с автооткатом — тоже только с автооткатом; у точки возврата флаг Confirm.
func TestRollbackRestoreNeedsConfirm(t *testing.T) {
	f := newFixture(t)
	p := f.target("old\n")
	w := f.configWrite(p, "new\n", false, 30)
	if o := f.exec(sealed(w)); o.result.GetOutcome() != agentv1.OperationOutcome_OPERATION_OUTCOME_AWAITING_CONFIRM {
		t.Fatalf("%+v", o.result)
	}
	if _, code := f.confirm(w.GetOperationId()); code != "" {
		t.Fatal(code)
	}
	restore := func(cw uint32) *agentv1.OperationBody {
		b := f.body(ops.TypeRollbackRestore, &agentv1.OperationParams{Params: &agentv1.OperationParams_RollbackRestore{
			RollbackRestore: &agentv1.RollbackRestoreParams{TargetOperationId: w.GetOperationId()}}})
		b.Rollback = agentv1.RollbackKind_ROLLBACK_KIND_CONFIG
		b.ConfirmWithinSec = cw
		return b
	}
	if o := f.exec(sealed(restore(0))); o.result.GetErrorCode() != ops.CodeParamsInvalid || readFile(t, p) != "new\n" {
		t.Fatalf("возврат без автооткатa: %+v", o.result)
	}
	rb := restore(30)
	if o := f.exec(sealed(rb)); o.result.GetOutcome() != agentv1.OperationOutcome_OPERATION_OUTCOME_AWAITING_CONFIRM || readFile(t, p) != "old\n" {
		t.Fatalf("возврат с автооткатом: %+v", o.result)
	}
	m, err := f.e.Rollback.Load(rb.GetOperationId())
	if err != nil || !m.State.Confirm {
		t.Fatalf("точка возврата: %+v %v", m, err)
	}
	// Связь не подтверждена — автооткат возврата: файл снова как после операции.
	if err := f.e.AutoRollback(context.Background(), rb.GetOperationId()); err != nil {
		t.Fatal(err)
	}
	if readFile(t, p) != "new\n" {
		t.Fatalf("автооткат возврата: %q", readFile(t, p))
	}
}
