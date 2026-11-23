// SPDX-License-Identifier: AGPL-3.0-only

package channel

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/ops"
	"github.com/NogMeer/trassa-agent/internal/verify"
)

var panelBPriv = ed25519.NewKeyFromSeed(mustHex("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7"))

func panelBKeys() []verify.PanelKey {
	return []verify.PanelKey{{ID: "b1", PublicKey: panelBPriv.Public().(ed25519.PublicKey)}}
}

// rebindHelper — помощник с записью о регистрации в памяти: agent.rebind переводит на b, подтверждение — только
// ключом b, rebind.fail с now возвращает на a с итогом ROLLED_BACK.
type rebindHelper struct {
	*fakeHelper
	mu       sync.Mutex
	a, b     string
	cur      string
	pending  string
	failures []agentv1.RebindFailure
	results  map[string]*agentv1.OperationResult
}

func (h *rebindHelper) reload() (string, []verify.PanelKey, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.cur == h.b {
		return h.cur, panelBKeys(), nil
	}
	return h.cur, panelKeys(), nil
}

func (h *rebindHelper) Execute(ctx context.Context, signed []byte, onAck func(bool, string), onProgress func([]byte)) ([]byte, error) {
	var so agentv1.SignedOperation
	_ = proto.Unmarshal(signed, &so)
	var b agentv1.OperationBody
	_ = proto.Unmarshal(so.GetBody(), &b)
	if b.GetType() != ops.TypeAgentRebind {
		return h.fakeHelper.Execute(ctx, signed, onAck, onProgress)
	}
	onAck(true, "")
	h.mu.Lock()
	h.cur, h.pending = h.b, b.GetOperationId()
	h.mu.Unlock()
	return proto.Marshal(&agentv1.OperationResult{OperationId: b.GetOperationId(), Outcome: agentv1.OperationOutcome_OPERATION_OUTCOME_AWAITING_CONFIRM, FinishedAtMs: 1})
}

func (h *rebindHelper) Confirm(_ context.Context, raw []byte) ([]byte, error) {
	var sc agentv1.SignedConfirm
	_ = proto.Unmarshal(raw, &sc)
	h.mu.Lock()
	defer h.mu.Unlock()
	keys := panelKeys()
	if h.cur == h.b {
		keys = panelBKeys()
	}
	if verify.Signature(keys, sc.GetKeyId(), verify.ContextConfirm, sc.GetBody(), sc.GetSignature()) != nil {
		return nil, errors.New("SIGNATURE_INVALID")
	}
	var cb agentv1.ConfirmBody
	_ = proto.Unmarshal(sc.GetBody(), &cb)
	if cb.GetOperationId() != h.pending {
		return nil, errors.New("CONFIRM_UNKNOWN")
	}
	h.pending = ""
	return proto.Marshal(&agentv1.OperationResult{OperationId: cb.GetOperationId(), Outcome: agentv1.OperationOutcome_OPERATION_OUTCOME_SUCCEEDED, FinishedAtMs: 2})
}

func (h *rebindHelper) Reports(ctx context.Context) ([][]byte, error) {
	h.mu.Lock()
	var out [][]byte
	for _, r := range h.results {
		raw, _ := proto.Marshal(r)
		out = append(out, raw)
	}
	h.mu.Unlock()
	return out, nil
}

func (h *rebindHelper) Reported(_ context.Context, op string, outcome int32) error {
	h.mu.Lock()
	if r := h.results[op]; r != nil && int32(r.GetOutcome()) == outcome {
		delete(h.results, op)
	}
	h.mu.Unlock()
	return nil
}

func (h *rebindHelper) RebindState(context.Context) ([]byte, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.pending == "" {
		return nil, nil
	}
	return json.Marshal(map[string]string{"operation_id": h.pending, "gateway_url": h.b})
}

func (h *rebindHelper) RebindFail(_ context.Context, op string, failure int32, _ string, now bool) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if op != h.pending {
		return errors.New("CONFIRM_UNKNOWN")
	}
	h.failures = append(h.failures, agentv1.RebindFailure(failure))
	if now {
		h.cur, h.pending = h.a, ""
		h.results[op] = &agentv1.OperationResult{OperationId: op, Outcome: agentv1.OperationOutcome_OPERATION_OUTCOME_ROLLED_BACK,
			ErrorCode: "REBIND_ROLLED_BACK", FinishedAtMs: 3,
			Data: &agentv1.OperationResult_AgentRebind{AgentRebind: &agentv1.AgentRebindResult{Failure: agentv1.RebindFailure(failure)}}}
	}
	return nil
}

// expire — срок вышел у помощника: прежняя запись, итог NO_CONFIRM (агента помощник не будит).
func (h *rebindHelper) expire() {
	h.mu.Lock()
	defer h.mu.Unlock()
	op := h.pending
	h.cur, h.pending = h.a, ""
	h.results[op] = &agentv1.OperationResult{OperationId: op, Outcome: agentv1.OperationOutcome_OPERATION_OUTCOME_ROLLED_BACK,
		ErrorCode: "REBIND_ROLLED_BACK", FinishedAtMs: 3,
		Data: &agentv1.OperationResult_AgentRebind{AgentRebind: &agentv1.AgentRebindResult{Failure: agentv1.RebindFailure_REBIND_FAILURE_NO_CONFIRM}}}
}

func (h *rebindHelper) state() (cur, pending string, failures []agentv1.RebindFailure) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.cur, h.pending, append([]agentv1.RebindFailure(nil), h.failures...)
}

func rebindOp(t *testing.T, op, url string) *agentv1.SignedOperation {
	now := time.Now()
	n := make([]byte, 16)
	_, _ = rand.Read(n)
	body, _ := proto.Marshal(&agentv1.OperationBody{
		OperationId: op, ServerId: serverID, Type: ops.TypeAgentRebind, Nonce: n,
		Params: &agentv1.OperationParams{Params: &agentv1.OperationParams_AgentRebind{AgentRebind: &agentv1.AgentRebindParams{
			GatewayUrl: url, PanelKeys: []*agentv1.RebindPanelKey{{KeyId: "b1", PublicKey: panelBPriv.Public().(ed25519.PublicKey)}}}}},
		NotAfterMs: now.Add(5 * time.Minute).UnixMilli(), IssuedAtMs: now.UnixMilli(), Rollback: agentv1.RollbackKind_ROLLBACK_KIND_CONFIG,
		ConfirmWithinSec: 300,
	})
	return &agentv1.SignedOperation{Body: body, KeyId: "k1", Signature: ed25519.Sign(panelPriv, verify.Input(verify.ContextOperation, body))}
}

func signedConfirm(op string, priv ed25519.PrivateKey, kid string) *agentv1.SignedConfirm {
	n := make([]byte, 16)
	_, _ = rand.Read(n)
	body, _ := proto.Marshal(&agentv1.ConfirmBody{OperationId: op, ServerId: serverID, Nonce: n, NotAfterMs: time.Now().Add(time.Minute).UnixMilli()})
	return &agentv1.SignedConfirm{Body: body, KeyId: kid, Signature: ed25519.Sign(priv, verify.Input(verify.ContextConfirm, body))}
}

// ackAll — шлюз квитирует каждый итог и складывает их.
func ackAll(ctx context.Context, c *gwConn, results chan<- *agentv1.OperationResult) {
	for {
		m, err := c.read(ctx)
		if err != nil {
			return
		}
		if r := m.GetOperationResult(); r != nil {
			_ = c.send(ctx, &agentv1.GatewayMessage{Payload: &agentv1.GatewayMessage_InboundAck{InboundAck: &agentv1.InboundAck{Seq: m.GetSeq()}}})
			results <- r
		}
	}
}

// selfSigned — сервер с сертификатом, которого нет в корнях клиента.
func selfSigned(t *testing.T, h http.Handler) *httptest.Server {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "evil"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, DNSNames: []string{"localhost"}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	s := httptest.NewUnstartedServer(h)
	s.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: k}}}
	s.StartTLS()
	t.Cleanup(s.Close)
	return s
}

func TestRebindTwoPanels(t *testing.T) {
	for _, tc := range []struct {
		name    string
		setupB  func(t *testing.T, gb *testGateway)
		confirm func(op string) *agentv1.SignedConfirm // что присылает B; nil — ничего
		onB     bool
		failure agentv1.RebindFailure
		// expire — B на связи, но молчит: срок выходит у помощника во время сеанса с B.
		expire bool
	}{
		{name: "подтверждено ключом B", confirm: func(op string) *agentv1.SignedConfirm { return signedConfirm(op, panelBPriv, "b1") }, onB: true},
		{name: "B отклоняет рукопожатие", setupB: func(_ *testing.T, gb *testGateway) { gb.reason = agentv1.CloseReason_CLOSE_REASON_REVOKED },
			failure: agentv1.RebindFailure_REBIND_FAILURE_HANDSHAKE_REJECTED},
		{name: "самоподписанный сертификат B", setupB: func(t *testing.T, gb *testGateway) {
			gb.srv.Close()
			gb.srv = selfSigned(t, http.HandlerFunc(gb.handle))
		}, failure: agentv1.RebindFailure_REBIND_FAILURE_TLS_UNTRUSTED},
		{name: "B на связи, но не подтверждает", expire: true, failure: agentv1.RebindFailure_REBIND_FAILURE_NO_CONFIRM},
		{name: "B недоступен", setupB: func(_ *testing.T, gb *testGateway) { gb.srv.Close() },
			failure: agentv1.RebindFailure_REBIND_FAILURE_UNREACHABLE},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id := newIdentity(t)
			resultsA := make(chan *agentv1.OperationResult, 16)
			var helloB *agentv1.Hello
			var mu sync.Mutex
			var gbURL string
			// Операция уходит только при первом подключении, как у панели: повтор после возврата (новый nonce)
			// снова переключил бы запись на B, и проверка «запись у A» падала бы через раз.
			var sendRebind sync.Once
			ga := newGateway(t, id.PublicKey(), func(ctx context.Context, c *gwConn) {
				sendRebind.Do(func() {
					_ = c.send(ctx, &agentv1.GatewayMessage{Payload: &agentv1.GatewayMessage_Operation{Operation: rebindOp(t, opID(1), gbURL)}})
				})
				ackAll(ctx, c, resultsA)
			})
			resultsB := make(chan *agentv1.OperationResult, 16)
			var h *rebindHelper
			hExpire := func() { h.expire() }
			gb := newGateway(t, id.PublicKey(), func(ctx context.Context, c *gwConn) {
				mu.Lock()
				helloB = c.hello
				mu.Unlock()
				if tc.expire {
					go func() { time.Sleep(200 * time.Millisecond); hExpire() }()
				}
				// Подтверждение ключом A новая сторона не примет; ключом B — примет.
				_ = c.send(ctx, &agentv1.GatewayMessage{Payload: &agentv1.GatewayMessage_Confirm{Confirm: signedConfirm(c.hello.GetRebindOperationId(), panelPriv, "k1")}})
				if tc.confirm != nil && !tc.expire {
					_ = c.send(ctx, &agentv1.GatewayMessage{Payload: &agentv1.GatewayMessage_Confirm{Confirm: tc.confirm(c.hello.GetRebindOperationId())}})
				}
				ackAll(ctx, c, resultsB)
			})
			if tc.setupB != nil {
				tc.setupB(t, gb)
			}
			gbURL = gb.url()
			h = &rebindHelper{fakeHelper: newFakeHelper(), a: ga.url(), b: gbURL, cur: ga.url(), results: map[string]*agentv1.OperationResult{}}
			a := New(Config{
				GatewayURL: ga.url(), ServerID: serverID, Identity: id, PanelKeys: panelKeys(), Helper: h, Version: "1.0.0",
				OS: "debian", OSVersion: "12", Arch: "amd64", HTTPClient: ga.srv.Client(), // корни — только тестовый CA
				Backoff: Backoff{Base: time.Millisecond, Max: 10 * time.Millisecond},
				Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
				Reload:  h.reload, Rebind: h,
			})
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- a.Run(ctx) }()
			defer func() {
				cancel()
				<-done
			}()
			// Прежняя панель получает AWAITING_CONFIRM.
			select {
			case r := <-resultsA:
				if r.GetOutcome() != agentv1.OperationOutcome_OPERATION_OUTCOME_AWAITING_CONFIRM {
					t.Fatalf("A: %+v", r)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("A не получила итог")
			}
			if tc.onB {
				select {
				case r := <-resultsB:
					if r.GetOutcome() != agentv1.OperationOutcome_OPERATION_OUTCOME_SUCCEEDED {
						t.Fatalf("B: %+v", r)
					}
				case <-time.After(10 * time.Second):
					t.Fatal("B не подтвердила")
				}
				mu.Lock()
				if helloB.GetRebindOperationId() != opID(1) {
					t.Fatalf("Hello B: %q", helloB.GetRebindOperationId())
				}
				mu.Unlock()
				if cur, pending, _ := h.state(); cur != gbURL || pending != "" {
					t.Fatalf("после подтверждения: %s %q", cur, pending)
				}
				return
			}
			// Возврат: агент снова у A, A получает ROLLED_BACK с причиной.
			select {
			case r := <-resultsA:
				if r.GetOutcome() != agentv1.OperationOutcome_OPERATION_OUTCOME_ROLLED_BACK || r.GetAgentRebind().GetFailure() != tc.failure {
					t.Fatalf("A после возврата: %+v", r)
				}
			case <-time.After(60 * time.Second):
				_, _, f := h.state()
				t.Fatalf("возврата не было, причины: %v", f)
			}
			if cur, _, _ := h.state(); cur != ga.url() {
				t.Fatalf("запись: %s", cur)
			}
		})
	}
}
