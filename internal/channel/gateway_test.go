// SPDX-License-Identifier: AGPL-3.0-only

package channel

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"google.golang.org/protobuf/proto"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/fsutil"
	"github.com/NogMeer/trassa-agent/internal/identity"
	"github.com/NogMeer/trassa-agent/internal/verify"
)

const serverID = "01a1f4b6-f327-7a5d-ac23-e95c272c0fe8"

var panelPriv = ed25519.NewKeyFromSeed(mustHex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"))

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func panelKeys() []verify.PanelKey {
	return []verify.PanelKey{{ID: "k1", PublicKey: panelPriv.Public().(ed25519.PublicKey)}}
}

// gwConn — соединение на стороне тестового шлюза.
type gwConn struct {
	ws    *websocket.Conn
	seq   uint64
	hello *agentv1.Hello
	mu    sync.Mutex
}

func (c *gwConn) send(ctx context.Context, m *agentv1.GatewayMessage) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.seq++
	m.Seq = c.seq
	raw, _ := proto.Marshal(m)
	return c.ws.Write(ctx, websocket.MessageBinary, raw)
}

func (c *gwConn) read(ctx context.Context) (*agentv1.AgentMessage, error) {
	_, raw, err := c.ws.Read(ctx)
	if err != nil {
		return nil, err
	}
	var m agentv1.AgentMessage
	if err := proto.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// testGateway — шлюз внутри теста: рукопожатие как в разделе 5 E05, дальше сценарий script.
type testGateway struct {
	t        *testing.T
	srv      *httptest.Server
	agentPub ed25519.PublicKey
	accepts  atomic.Int32
	// status — код ответа на обновление (0 — принять).
	status int
	// welcome — отвечать ли Welcome; reason — вместо Welcome прислать Close.
	reason agentv1.CloseReason
	script func(ctx context.Context, c *gwConn)
}

func newGateway(t *testing.T, pub ed25519.PublicKey, script func(ctx context.Context, c *gwConn)) *testGateway {
	g := &testGateway{t: t, agentPub: pub, script: script}
	g.srv = httptest.NewTLSServer(http.HandlerFunc(g.handle))
	t.Cleanup(g.srv.Close)
	return g
}

func (g *testGateway) url() string {
	return "wss" + strings.TrimPrefix(g.srv.URL, "https") + "/agent/v1/connect"
}

func (g *testGateway) handle(w http.ResponseWriter, r *http.Request) {
	if g.status != 0 {
		w.WriteHeader(g.status)
		return
	}
	ws, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	defer ws.CloseNow()
	ws.SetReadLimit(1 << 20)
	ctx := r.Context()
	c := &gwConn{ws: ws}
	nonce := make([]byte, 32)
	_, _ = rand.Read(nonce)
	if err := c.send(ctx, &agentv1.GatewayMessage{Payload: &agentv1.GatewayMessage_Challenge{Challenge: &agentv1.Challenge{
		Nonce: nonce, GatewayTimeMs: time.Now().UnixMilli(), ProtocolVersions: []agentv1.ProtocolVersion{agentv1.ProtocolVersion_PROTOCOL_VERSION_1},
	}}}); err != nil {
		return
	}
	hctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	m, err := c.read(hctx)
	cancel()
	if err != nil || m.GetHello() == nil {
		return
	}
	h := m.GetHello()
	if !ed25519.Verify(g.agentPub, identity.AuthInput(nonce, h.GetServerId()), h.GetSignature()) || h.GetServerId() != serverID {
		_ = c.send(ctx, &agentv1.GatewayMessage{Payload: &agentv1.GatewayMessage_Close{Close: &agentv1.Close{Reason: agentv1.CloseReason_CLOSE_REASON_AUTH_FAILED}}})
		return
	}
	if g.reason != agentv1.CloseReason_CLOSE_REASON_UNSPECIFIED {
		_ = c.send(ctx, &agentv1.GatewayMessage{Payload: &agentv1.GatewayMessage_Close{Close: &agentv1.Close{Reason: g.reason}}})
		return
	}
	c.hello = h
	if err := c.send(ctx, &agentv1.GatewayMessage{Payload: &agentv1.GatewayMessage_Welcome{Welcome: &agentv1.Welcome{
		ProtocolVersion: agentv1.ProtocolVersion_PROTOCOL_VERSION_1, GatewayTimeMs: time.Now().UnixMilli(), HeartbeatSec: 1,
	}}}); err != nil {
		return
	}
	g.accepts.Add(1)
	if g.script != nil {
		g.script(ctx, c)
	}
}

// fakeHelper — помощник без системы: принимает всё с верной подписью, итог SUCCEEDED.
type fakeHelper struct {
	mu       sync.Mutex
	results  map[string][]byte // итоги, не подтверждённые шлюзом
	reported map[string]int32
	executed map[string]int
	delay    time.Duration
}

func newFakeHelper() *fakeHelper {
	return &fakeHelper{results: map[string][]byte{}, reported: map[string]int32{}, executed: map[string]int{}}
}

func (h *fakeHelper) Hello(context.Context) (string, []string, error) {
	return "1.0.0", []string{"system.info"}, nil
}

func (h *fakeHelper) Execute(ctx context.Context, signed []byte, onAck func(bool, string), onProgress func([]byte)) ([]byte, error) {
	var so agentv1.SignedOperation
	_ = proto.Unmarshal(signed, &so)
	var b agentv1.OperationBody
	_ = proto.Unmarshal(so.GetBody(), &b)
	onAck(true, "")
	p, _ := proto.Marshal(&agentv1.OperationProgress{OperationId: b.GetOperationId(), Seq: 1, Chunk: "работаю"})
	onProgress(p)
	if h.delay > 0 {
		time.Sleep(h.delay)
	}
	raw, _ := proto.Marshal(&agentv1.OperationResult{OperationId: b.GetOperationId(), Outcome: agentv1.OperationOutcome_OPERATION_OUTCOME_SUCCEEDED, FinishedAtMs: 1})
	h.mu.Lock()
	h.executed[b.GetOperationId()]++
	if _, done := h.reported[b.GetOperationId()]; !done {
		h.results[b.GetOperationId()] = raw
	}
	h.mu.Unlock()
	return raw, nil
}

func (h *fakeHelper) Confirm(context.Context, []byte) ([]byte, error) {
	return nil, errors.New("нет")
}

func (h *fakeHelper) Reports(context.Context) ([][]byte, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out [][]byte
	for _, r := range h.results {
		out = append(out, r)
	}
	return out, nil
}

func (h *fakeHelper) Reported(_ context.Context, op string, outcome int32) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.reported[op] = outcome
	delete(h.results, op)
	return nil
}

func (h *fakeHelper) Running(context.Context) ([]string, error) { return nil, nil }

func (h *fakeHelper) reportedCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.reported)
}

func newIdentity(t *testing.T) *identity.Identity {
	id, err := identity.Generate(filepath.Join(t.TempDir(), "agent.key"), fsutil.Keep)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func newAgent(t *testing.T, id *identity.Identity, g *testGateway, h Helper) *Agent {
	return New(Config{
		GatewayURL: g.url(), ServerID: serverID, Identity: id, PanelKeys: panelKeys(), Helper: h, Version: "1.0.0",
		OS: "debian", OSVersion: "12", Arch: "amd64", HTTPClient: g.srv.Client(),
		Backoff: Backoff{Base: time.Millisecond, Max: 10 * time.Millisecond},
		Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
}

func signedOp(t *testing.T, op string) *agentv1.SignedOperation {
	now := time.Now()
	n := make([]byte, 16)
	_, _ = rand.Read(n)
	body, _ := proto.Marshal(&agentv1.OperationBody{
		OperationId: op, ServerId: serverID, Type: "system.info", Nonce: n,
		Params:     &agentv1.OperationParams{Params: &agentv1.OperationParams_SystemInfo{SystemInfo: &agentv1.SystemInfoParams{}}},
		NotAfterMs: now.Add(5 * time.Minute).UnixMilli(), IssuedAtMs: now.UnixMilli(), Rollback: agentv1.RollbackKind_ROLLBACK_KIND_NONE,
	})
	return &agentv1.SignedOperation{Body: body, KeyId: "k1", Signature: ed25519.Sign(panelPriv, verify.Input(verify.ContextOperation, body))}
}

func opID(i int) string { return fmt.Sprintf("01a1f4b6-f2f2-7e66-85b4-%012d", i) }

func waitFor(t *testing.T, d time.Duration, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("не дождались: %s", what)
}
