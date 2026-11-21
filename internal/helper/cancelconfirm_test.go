// SPDX-License-Identifier: AGPL-3.0-only

//go:build testops

package helper

import (
	"context"
	"strings"
	"sync"
	"testing"

	"google.golang.org/protobuf/proto"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
)

func (f *fixture) cancelRaw(op string, n []byte) []byte {
	return f.signedCancel(f.t, op, serverID, n)
}

func (f *fixture) armed(op string) bool {
	f.timer.mu.Lock()
	defer f.timer.mu.Unlock()
	_, ok := f.timer.armed[strings.ToLower(op)]
	return ok
}

// E10-T14 «Вернуть как было»: отмена операции в ожидании подтверждения — немедленный откат тем же путём, что у
// таймера (тип операции не важен: KindConfig, как у ssh.harden и firewall.apply), итог ROLLED_BACK с CANCELLED.
func TestCancelAwaitingConfirm(t *testing.T) {
	f := newFixture(t)
	p := f.target("old\n")
	w := f.configWrite(p, "new\n", false, 30)
	if o := f.exec(sealed(w)); o.result.GetOutcome() != agentv1.OperationOutcome_OPERATION_OUTCOME_AWAITING_CONFIRM || readFile(t, p) != "new\n" {
		t.Fatalf("%+v", o.result)
	}
	op := w.GetOperationId()
	if !f.armed(op) {
		t.Fatal("таймер не взведён")
	}
	n := newNonce()
	raw, code := f.e.Cancel(context.Background(), f.cancelRaw(op, n))
	if code != "" {
		t.Fatalf("отмена: %s", code)
	}
	var res agentv1.OperationResult
	if err := proto.Unmarshal(raw, &res); err != nil {
		t.Fatal(err)
	}
	if res.GetOutcome() != agentv1.OperationOutcome_OPERATION_OUTCOME_ROLLED_BACK || res.GetErrorCode() != CodeCancelled || readFile(t, p) != "old\n" {
		t.Fatalf("итог отмены: %+v, файл %q", &res, readFile(t, p))
	}
	if f.armed(op) {
		t.Fatal("таймер не снят")
	}
	if rec, _ := f.e.Auto.Get(op); rec != nil {
		t.Fatal("запись автооткатa осталась")
	}
	// Повтор той же отмены (тот же nonce) — CANCEL_INVALID.
	if _, code := f.e.Cancel(context.Background(), f.cancelRaw(op, n)); code != CodeCancelInvalid {
		t.Fatalf("повтор nonce: %s", code)
	}
	// Подтверждение после отмены — сохранённый итог ROLLED_BACK, файл не трогается.
	if r, code := f.confirm(op); code != "" || r.GetOutcome() != agentv1.OperationOutcome_OPERATION_OUTCOME_ROLLED_BACK || readFile(t, p) != "old\n" {
		t.Fatalf("подтверждение после отмены: %+v %s", r, code)
	}
	// Ещё одна отмена (новый nonce) после отката — тот же итог, без повторного отката.
	if raw, code := f.e.Cancel(context.Background(), f.cancelRaw(op, newNonce())); code != "" || len(raw) == 0 {
		t.Fatalf("отмена после отката: %s", code)
	}
}

// Отмена после подтверждения — CANCEL_TOO_LATE, итог SUCCEEDED и файл не меняются.
func TestCancelAfterConfirm(t *testing.T) {
	f := newFixture(t)
	p := f.target("old\n")
	w := f.configWrite(p, "new\n", false, 30)
	f.exec(sealed(w))
	if r, code := f.confirm(w.GetOperationId()); code != "" || r.GetOutcome() != agentv1.OperationOutcome_OPERATION_OUTCOME_SUCCEEDED {
		t.Fatalf("подтверждение: %+v %s", r, code)
	}
	if _, code := f.e.Cancel(context.Background(), f.cancelRaw(w.GetOperationId(), newNonce())); code != CodeCancelTooLate {
		t.Fatalf("после подтверждения: %s", code)
	}
	if st := f.state(w.GetOperationId()); st.Outcome != int32(agentv1.OperationOutcome_OPERATION_OUTCOME_SUCCEEDED) || readFile(t, p) != "new\n" {
		t.Fatalf("итог изменён: %+v %q", st, readFile(t, p))
	}
}

// Гонка подтверждения и отмены: побеждает ровно одно, итог и файл согласованы.
func TestCancelConfirmRace(t *testing.T) {
	for i := 0; i < 20; i++ {
		f := newFixture(t)
		p := f.target("old\n")
		w := f.configWrite(p, "new\n", false, 30)
		f.exec(sealed(w))
		op := w.GetOperationId()
		var wg sync.WaitGroup
		var cancelCode, confirmCode string
		var confirmed *agentv1.OperationResult
		wg.Add(2)
		go func() { defer wg.Done(); _, cancelCode = f.e.Cancel(context.Background(), f.cancelRaw(op, newNonce())) }()
		go func() { defer wg.Done(); confirmed, confirmCode = f.confirm(op) }()
		wg.Wait()
		st := f.state(op)
		switch {
		case cancelCode == "":
			// Отмена первой: файл старый, подтверждение вернуло итог отката.
			if readFile(t, p) != "old\n" || st.Outcome != int32(agentv1.OperationOutcome_OPERATION_OUTCOME_ROLLED_BACK) ||
				confirmCode != "" || confirmed.GetOutcome() != agentv1.OperationOutcome_OPERATION_OUTCOME_ROLLED_BACK {
				t.Fatalf("отмена первой: %q %+v %s %+v", readFile(t, p), st, confirmCode, confirmed)
			}
		case cancelCode == CodeCancelTooLate:
			if readFile(t, p) != "new\n" || st.Outcome != int32(agentv1.OperationOutcome_OPERATION_OUTCOME_SUCCEEDED) || confirmCode != "" {
				t.Fatalf("подтверждение первым: %q %+v %s", readFile(t, p), st, confirmCode)
			}
		default:
			t.Fatalf("код отмены %s", cancelCode)
		}
	}
}
