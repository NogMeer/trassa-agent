// SPDX-License-Identifier: AGPL-3.0-only

package helper

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/config"
	"github.com/NogMeer/trassa-agent/internal/fsutil"
	"github.com/NogMeer/trassa-agent/internal/helperrpc"
	"github.com/NogMeer/trassa-agent/internal/ops"
	"github.com/NogMeer/trassa-agent/internal/verify"
)

const (
	oldGW = "wss://gw.old.example/agent/v1/connect"
	newGW = "wss://gw.new.example/agent/v1/connect"
)

var newPanelPriv = ed25519.NewKeyFromSeed(must(hex.DecodeString("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7")))

func (f *fixture) writeEnrollment() {
	f.t.Helper()
	if err := os.MkdirAll(f.paths.EtcDir, 0o750); err != nil {
		f.t.Fatal(err)
	}
	en := config.Enrollment{ServerID: serverID, GatewayURL: oldGW, ProtocolVersion: config.ProtocolVersion,
		PanelKeys: []config.PanelKey{{KeyID: keyID, PublicKey: base64.StdEncoding.EncodeToString(panelPriv.Public().(ed25519.PublicKey))}}}
	if err := config.SaveEnrollment(f.paths.Enrollment, en, fsutil.Keep); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) rebindBody() *agentv1.OperationBody {
	b := f.body(ops.TypeAgentRebind, &agentv1.OperationParams{Params: &agentv1.OperationParams_AgentRebind{AgentRebind: &agentv1.AgentRebindParams{
		GatewayUrl: newGW, PanelKeys: []*agentv1.RebindPanelKey{{KeyId: "new-1", PublicKey: newPanelPriv.Public().(ed25519.PublicKey)}}}}})
	b.Rollback, b.ConfirmWithinSec = agentv1.RollbackKind_ROLLBACK_KIND_CONFIG, 300
	return b
}

func (f *fixture) confirmWith(op string, priv ed25519.PrivateKey, kid string) (*agentv1.OperationResult, string) {
	raw, _ := proto.Marshal(&agentv1.ConfirmBody{OperationId: op, ServerId: serverID, Nonce: newNonce(), NotAfterMs: f.clock.Now().Add(time.Minute).UnixMilli()})
	sc, _ := proto.Marshal(&agentv1.SignedConfirm{Body: raw, KeyId: kid, Signature: ed25519.Sign(priv, verify.Input(verify.ContextConfirm, raw))})
	out, code := f.e.Confirm(context.Background(), sc)
	if code != "" {
		return nil, code
	}
	var res agentv1.OperationResult
	_ = proto.Unmarshal(out, &res)
	return &res, ""
}

func (f *fixture) gateway() string {
	en, _, err := config.LoadEnrollment(f.paths.Enrollment)
	if err != nil {
		f.t.Fatal(err)
	}
	return en.GatewayURL
}

func (f *fixture) rebindState() *RebindState {
	var st *RebindState
	f.e.Serve(context.Background(), helperrpc.Request{Method: helperrpc.MethodRebindState}, func(r helperrpc.Response) error {
		if len(r.Result) > 0 {
			st = &RebindState{}
			_ = json.Unmarshal(r.Result, st)
		}
		return nil
	})
	return st
}

func TestRebindConfirmedByNewPanel(t *testing.T) {
	f := newFixture(t)
	f.writeEnrollment()
	if !slices.Contains(caps(t, f.e), ops.TypeAgentRebind) {
		t.Fatal("нет agent.rebind в capabilities")
	}
	// Предпросмотр: адреса и отпечаток ключа, запись не меняется.
	b := f.rebindBody()
	b.DryRun = true
	if o := f.exec(sealed(b)); o.result.GetPreview().GetSummary() == "" || f.gateway() != oldGW {
		t.Fatalf("предпросмотр: %+v", o.result)
	}
	// Итог операции прежней панели, который она не успела квитировать: после подтверждения новой он не уйдёт.
	oldOp := f.exec(sealed(f.body(ops.TypeSystemInfo, infoParams())))
	oldID := oldOp.result.GetOperationId()
	b = f.rebindBody()
	o := f.exec(sealed(b))
	op := b.GetOperationId()
	if o.result.GetOutcome() != agentv1.OperationOutcome_OPERATION_OUTCOME_AWAITING_CONFIRM || f.gateway() != newGW {
		t.Fatalf("применение: %+v", o.result)
	}
	if st := f.rebindState(); st == nil || st.OperationID != op || st.GatewayURL != newGW || st.PrevGatewayURL != oldGW {
		t.Fatalf("состояние: %+v", st)
	}
	// Второй перевод, пока первый не завершён, — отказ (новая панель подписывает тем же путём).
	b2 := f.rebindBody()
	raw, _ := proto.Marshal(b2)
	if o := f.exec(sealRaw(raw, newPanelPriv, "new-1", verify.ContextOperation)); o.result.GetErrorCode() != CodeRebindInProgress {
		t.Fatalf("второй перевод: %+v %+v", o, o.result)
	}
	// Подтверждение ключом прежней панели не принимается: проверка — ключами новой.
	if _, code := f.confirmWith(op, panelPriv, keyID); code != ops.CodeSignatureInvalid {
		t.Fatalf("ключ A: %q", code)
	}
	res, code := f.confirmWith(op, newPanelPriv, "new-1")
	if code != "" || res.GetOutcome() != agentv1.OperationOutcome_OPERATION_OUTCOME_SUCCEEDED {
		t.Fatalf("ключ B: %q %+v", code, res)
	}
	if f.rebindState() != nil || f.gateway() != newGW {
		t.Fatal("после подтверждения перевод не завершён")
	}
	if st, _ := f.e.States.Get(oldID); st == nil || !st.Reported {
		t.Fatalf("итог прежней панели остался к отправке: %+v", st)
	}
	if st, _ := f.e.States.Get(op); st == nil || st.Reported {
		t.Fatal("итог перевода отмечен доставленным")
	}
	// Копия прежней записи удалена: вернуть прежнюю панель операцией нельзя.
	if _, err := f.e.Rollback.Load(op); err == nil {
		t.Fatal("точка отката перевода осталась")
	}
	// Операции прежней панели больше не принимаются, новой — принимаются.
	expectReject(t, f, sealed(f.body(ops.TypeSystemInfo, infoParams())), ops.CodeSignatureInvalid)
	raw, _ = proto.Marshal(f.body(ops.TypeSystemInfo, infoParams()))
	if o := f.exec(sealRaw(raw, newPanelPriv, "new-1", verify.ContextOperation)); !o.accepted {
		t.Fatalf("операция новой панели: %+v", o)
	}
}

func TestRebindReturnsToOldPanel(t *testing.T) {
	for _, tc := range []struct {
		name    string
		fail    func(f *fixture, op string)
		failure agentv1.RebindFailure
	}{
		{name: "сертификат", failure: agentv1.RebindFailure_REBIND_FAILURE_TLS_UNTRUSTED, fail: func(f *fixture, op string) {
			f.rebindFail(op, agentv1.RebindFailure_REBIND_FAILURE_TLS_UNTRUSTED, "x509: certificate signed by unknown authority", true)
		}},
		{name: "недоступна, затем срок", failure: agentv1.RebindFailure_REBIND_FAILURE_UNREACHABLE, fail: func(f *fixture, op string) {
			f.rebindFail(op, agentv1.RebindFailure_REBIND_FAILURE_UNREACHABLE, "dial tcp: connection refused token=abcdefghijklmnop", false)
			if f.gateway() != newGW {
				f.t.Fatal("без now возврата быть не должно")
			}
			if err := f.e.AutoRollback(context.Background(), op); err != nil {
				f.t.Fatal(err)
			}
		}},
		{name: "нет подтверждения", failure: agentv1.RebindFailure_REBIND_FAILURE_NO_CONFIRM, fail: func(f *fixture, op string) {
			if err := f.e.AutoRollback(context.Background(), op); err != nil {
				f.t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			f.writeEnrollment()
			b := f.rebindBody()
			if o := f.exec(sealed(b)); o.result.GetOutcome() != agentv1.OperationOutcome_OPERATION_OUTCOME_AWAITING_CONFIRM {
				t.Fatalf("%+v", o.result)
			}
			op := b.GetOperationId()
			tc.fail(f, op)
			if f.gateway() != oldGW || f.rebindState() != nil {
				t.Fatalf("запись не вернулась: %s", f.gateway())
			}
			st, _ := f.e.States.Get(op)
			var res agentv1.OperationResult
			_ = proto.Unmarshal(st.Result, &res)
			if res.GetOutcome() != agentv1.OperationOutcome_OPERATION_OUTCOME_ROLLED_BACK || res.GetErrorCode() != CodeRebindRolledBack ||
				res.GetAgentRebind().GetFailure() != tc.failure || len(res.GetAgentRebind().GetDetail()) > 300 {
				t.Fatalf("итог: %+v", &res)
			}
			if d := res.GetAgentRebind().GetDetail(); tc.failure == agentv1.RebindFailure_REBIND_FAILURE_UNREACHABLE && (d == "" || strings.Contains(d, "abcdefghijklmnop")) {
				t.Fatalf("описание: %q", d)
			}
			// Ключи — снова прежней панели; подтверждение новой опоздало.
			if o := f.exec(sealed(f.body(ops.TypeSystemInfo, infoParams()))); !o.accepted {
				t.Fatalf("прежняя панель: %+v", o)
			}
			if _, code := f.confirmWith(op, newPanelPriv, "new-1"); code == "" {
				t.Fatal("подтверждение после возврата принято")
			}
		})
	}
}

func (f *fixture) rebindFail(op string, failure agentv1.RebindFailure, detail string, now bool) {
	f.t.Helper()
	var got helperrpc.Response
	f.e.Serve(context.Background(), helperrpc.Request{Method: helperrpc.MethodRebindFail, OperationID: op, Reason: int32(failure), Detail: detail, Now: now},
		func(r helperrpc.Response) error { got = r; return nil })
	if got.Kind != helperrpc.KindOK {
		f.t.Fatalf("rebind.fail: %+v", got)
	}
}

// rebind.fail без перевода и с неизвестной причиной — отказ; агент не может «подтвердить» перевод этим вызовом.
func TestRebindFailRejects(t *testing.T) {
	f := newFixture(t)
	f.writeEnrollment()
	for _, req := range []helperrpc.Request{
		{Method: helperrpc.MethodRebindFail, OperationID: newUUID(), Reason: 1, Now: true},
		{Method: helperrpc.MethodRebindFail, OperationID: newUUID(), Reason: int32(agentv1.RebindFailure_REBIND_FAILURE_NO_CONFIRM)},
		{Method: helperrpc.MethodRebindFail, OperationID: newUUID(), Reason: 99},
	} {
		var got helperrpc.Response
		f.e.Serve(context.Background(), req, func(r helperrpc.Response) error { got = r; return nil })
		if got.Kind != helperrpc.KindError {
			t.Fatalf("%+v → %+v", req, got)
		}
	}
	if f.gateway() != oldGW {
		t.Fatal("запись изменилась")
	}
}
