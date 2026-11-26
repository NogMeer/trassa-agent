// SPDX-License-Identifier: AGPL-3.0-only

package channel

import (
	"context"
	"crypto/ed25519"
	"errors"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/events"
	"github.com/NogMeer/trassa-agent/internal/logs"
	"github.com/NogMeer/trassa-agent/internal/metrics"
	"github.com/NogMeer/trassa-agent/internal/nonce"
	"github.com/NogMeer/trassa-agent/internal/opcheck"
	"github.com/NogMeer/trassa-agent/internal/ops"
	"github.com/NogMeer/trassa-agent/internal/verify"
)

func TestBackoff(t *testing.T) {
	b := DefaultBackoff()
	for _, r := range []float64{0, 0.5, 0.999999} {
		b.Rand = func() float64 { return r }
		prev := time.Duration(0)
		for i := 0; i < 100; i++ {
			d := b.Delay(i)
			if d > 60*time.Second || d < 500*time.Millisecond {
				t.Fatalf("попытка %d: %v", i, d)
			}
			if r == 0 && d < prev {
				t.Fatalf("окно уменьшилось: %v < %v", d, prev)
			}
			prev = d
		}
		if d := b.Delay(1000); d < 30*time.Second {
			t.Fatalf("после многих попыток окно не 60 с: %v", d)
		}
	}
	// Разброс: у тысячи агентов задержки различаются.
	b.Rand = rand.Float64
	seen := map[time.Duration]bool{}
	for i := 0; i < 1000; i++ {
		seen[b.Delay(10)] = true
	}
	if len(seen) < 900 {
		t.Fatalf("разброс мал: %d различных", len(seen))
	}
}

// Рукопожатие: подпись ключом агента по nonce и server_id, Hello несёт версию и список типов помощника.
func TestHandshakeAndOperation(t *testing.T) {
	id := newIdentity(t)
	h := newFakeHelper()
	got := make(chan *agentv1.AgentMessage, 16)
	var hello *agentv1.Hello
	g := newGateway(t, id.PublicKey(), func(ctx context.Context, c *gwConn) {
		hello = c.hello
		_ = c.send(ctx, &agentv1.GatewayMessage{Payload: &agentv1.GatewayMessage_Operation{Operation: signedOp(t, opID(1))}})
		for {
			m, err := c.read(ctx)
			if err != nil {
				return
			}
			got <- m
			if r := m.GetOperationResult(); r != nil {
				_ = c.send(ctx, &agentv1.GatewayMessage{Payload: &agentv1.GatewayMessage_InboundAck{InboundAck: &agentv1.InboundAck{Seq: m.GetSeq()}}})
			}
		}
	})
	a := newAgent(t, id, g, h)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error)
	go func() { done <- a.Run(ctx) }()
	var ack, prog, res bool
	timeout := time.After(5 * time.Second)
	for !(ack && prog && res) {
		select {
		case m := <-got:
			ack = ack || m.GetOperationAck().GetAccepted()
			prog = prog || m.GetOperationProgress() != nil
			res = res || m.GetOperationResult().GetOperationId() == opID(1)
		case <-timeout:
			t.Fatalf("ack=%v progress=%v result=%v", ack, prog, res)
		}
	}
	waitFor(t, 2*time.Second, func() bool { return h.reportedCount() == 1 }, "отметка доставки у помощника")
	if hello.GetAgentVersion() != "1.0.0" || hello.GetHelperVersion() != "1.0.0" || len(hello.GetCapabilities()) != 1 || hello.GetOs() != "debian" {
		t.Fatalf("Hello: %+v", hello)
	}
	// Пульс раз в heartbeat_sec из Welcome.
	waitFor(t, 3*time.Second, func() bool {
		for {
			select {
			case m := <-got:
				if m.GetHeartbeat() != nil {
					return true
				}
			default:
				return false
			}
		}
	}, "пульс")
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// Операция с неверной подписью не доходит до помощника, шлюз получает отказ SIGNATURE_INVALID.
func TestAgentRejectsBadSignature(t *testing.T) {
	id := newIdentity(t)
	h := newFakeHelper()
	got := make(chan *agentv1.OperationAck, 1)
	g := newGateway(t, id.PublicKey(), func(ctx context.Context, c *gwConn) {
		op := signedOp(t, opID(2))
		_, other, _ := ed25519.GenerateKey(nil)
		op.Signature = ed25519.Sign(other, op.Body)
		_ = c.send(ctx, &agentv1.GatewayMessage{Payload: &agentv1.GatewayMessage_Operation{Operation: op}})
		for {
			m, err := c.read(ctx)
			if err != nil {
				return
			}
			if a := m.GetOperationAck(); a != nil {
				got <- a
			}
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = newAgent(t, id, g, h).Run(ctx) }()
	select {
	case a := <-got:
		if a.GetAccepted() || a.GetRejectCode() != "SIGNATURE_INVALID" || a.GetOperationId() != opID(2) {
			t.Fatalf("%+v", a)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("нет отказа")
	}
	if len(h.executed) != 0 {
		t.Fatal("помощник получил операцию с неверной подписью")
	}
}

// Итог без InboundAck досылается после переподключения.
func TestResultResentAfterReconnect(t *testing.T) {
	id := newIdentity(t)
	h := newFakeHelper()
	var conns atomic.Int32
	g := newGateway(t, id.PublicKey(), func(ctx context.Context, c *gwConn) {
		n := conns.Add(1)
		if n == 1 {
			_ = c.send(ctx, &agentv1.GatewayMessage{Payload: &agentv1.GatewayMessage_Operation{Operation: signedOp(t, opID(3))}})
			for {
				m, err := c.read(ctx)
				if err != nil || m.GetOperationResult() != nil {
					return // рвём связь, не подтвердив итог
				}
			}
		}
		for {
			m, err := c.read(ctx)
			if err != nil {
				return
			}
			if r := m.GetOperationResult(); r != nil && r.GetOperationId() == opID(3) {
				_ = c.send(ctx, &agentv1.GatewayMessage{Payload: &agentv1.GatewayMessage_InboundAck{InboundAck: &agentv1.InboundAck{Seq: m.GetSeq()}}})
			}
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = newAgent(t, id, g, h).Run(ctx) }()
	waitFor(t, 5*time.Second, func() bool { return h.reportedCount() == 1 }, "итог доставлен со второй попытки")
	if conns.Load() < 2 {
		t.Fatal("переподключения не было")
	}
	if h.executed[opID(3)] != 1 {
		t.Fatal("операция выполнена повторно")
	}
}

// Отзыв: Close REVOKED или 403 — агент больше не подключается.
func TestRevoked(t *testing.T) {
	for name, set := range map[string]func(*testGateway){
		"close": func(g *testGateway) { g.reason = agentv1.CloseReason_CLOSE_REASON_REVOKED },
		"403":   func(g *testGateway) { g.status = http.StatusForbidden },
	} {
		t.Run(name, func(t *testing.T) {
			id := newIdentity(t)
			g := newGateway(t, id.PublicKey(), nil)
			set(g)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := newAgent(t, id, g, newFakeHelper()).Run(ctx); !errors.Is(err, ErrRevoked) {
				t.Fatalf("ждали ErrRevoked, получили %v", err)
			}
		})
	}
}

// Чужой ключ агента: шлюз отказывает, агент продолжает попытки с задержкой.
func TestWrongKeyRetries(t *testing.T) {
	id := newIdentity(t)
	g := newGateway(t, newIdentity(t).PublicKey(), nil)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	a := newAgent(t, id, g, newFakeHelper())
	if err := a.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if g.accepts.Load() != 0 || a.Sessions() != 0 {
		t.Fatal("чужой ключ принят")
	}
}

// Шумная сеть: шлюз рвёт соединения в случайные моменты, отказывает в рукопожатии, теряет квитанции. Время
// сжато (задержки 1–10 мс), за прогон — сотни обрывов, что соответствует часу обрывов с настоящими задержками.
// Агент каждый раз возвращается, каждая операция выполняется ровно один раз и её итог доставляется.
func TestNoisyNetwork(t *testing.T) {
	id := newIdentity(t)
	h := newFakeHelper()
	h.delay = time.Millisecond
	var next atomic.Int32
	var calm atomic.Bool
	g := newGateway(t, id.PublicKey(), func(ctx context.Context, c *gwConn) {
		if !calm.Load() {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, time.Duration(rand.IntN(40))*time.Millisecond)
			defer cancel()
			if rand.IntN(3) == 0 {
				_ = c.send(ctx, &agentv1.GatewayMessage{Payload: &agentv1.GatewayMessage_Operation{Operation: signedOp(t, opID(int(next.Add(1))))}})
			}
		}
		for {
			m, err := c.read(ctx)
			if err != nil {
				return
			}
			// Пока сеть шумит, половина квитанций теряется.
			if m.GetOperationResult() != nil && (calm.Load() || rand.IntN(2) == 0) {
				_ = c.send(ctx, &agentv1.GatewayMessage{Payload: &agentv1.GatewayMessage_InboundAck{InboundAck: &agentv1.InboundAck{Seq: m.GetSeq()}}})
			}
		}
	})
	var hits atomic.Int32
	inner := g.srv.Config.Handler
	g.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !calm.Load() && hits.Add(1)%4 == 0 {
			w.WriteHeader(http.StatusBadGateway) // шлюз недоступен
			return
		}
		inner.ServeHTTP(w, r)
	})
	ctx, cancel := context.WithCancel(context.Background())
	a := newAgent(t, id, g, h)
	done := make(chan error)
	go func() { done <- a.Run(ctx) }()
	// Шумим, пока не наберётся 30 сессий: счёт по событиям, а не по секундам — под нагрузкой CI сессий в секунду
	// меньше, и порог по времени давал ложные провалы.
	waitFor(t, 60*time.Second, func() bool { return a.Sessions() >= 30 }, "30 сессий в шумной сети")
	calm.Store(true)
	waitFor(t, 10*time.Second, func() bool {
		h.mu.Lock()
		defer h.mu.Unlock()
		return len(h.results) == 0 && len(h.reported) == len(h.executed)
	}, "доставка всех итогов после успокоения сети")
	cancel()
	<-done
	h.mu.Lock()
	defer h.mu.Unlock()
	for op, n := range h.executed {
		if n != 1 {
			t.Fatalf("%s выполнена %d раз", op, n)
		}
	}
	t.Logf("сессий %d, операций отправлено %d, выполнено %d", a.Sessions(), next.Load(), len(h.executed))
}

// agent.update: выпуск скачивает агент в свой каталог до передачи операции помощнику.
func TestUpdateStagedByAgent(t *testing.T) {
	id := newIdentity(t)
	staged := make(chan []string, 1)
	h := &stagingHelper{fakeHelper: newFakeHelper(), staged: staged}
	op := opID(77)
	g := newGateway(t, id.PublicKey(), func(ctx context.Context, c *gwConn) {
		_ = c.send(ctx, &agentv1.GatewayMessage{Payload: &agentv1.GatewayMessage_Operation{Operation: updateOp(t, op, "https://"+c.host+"/rel")}})
		for {
			if _, err := c.read(ctx); err != nil {
				return
			}
		}
	})
	g.files = map[string][]byte{"SHA256SUMS.minisig": []byte("sig"), "SHA256SUMS": []byte("sums"), "trassa-agent-linux-amd64": []byte("a"), "trassa-helper-linux-amd64": []byte("h")}
	a := newAgent(t, id, g, h)
	a.cfg.Arch = "amd64"
	a.cfg.UpdateDir = filepath.Join(t.TempDir(), "update")
	h.dir = filepath.Join(a.cfg.UpdateDir, op)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = a.Run(ctx) }()
	select {
	case names := <-staged:
		if len(names) != 4 {
			t.Fatalf("скачано %v", names)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("помощник не получил операцию")
	}
}

type stagingHelper struct {
	*fakeHelper
	dir    string
	staged chan []string
}

func (s *stagingHelper) Execute(ctx context.Context, signed []byte, onAck func(bool, string), onProgress func([]byte)) ([]byte, error) {
	ents, _ := os.ReadDir(s.dir)
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	s.staged <- names
	return s.fakeHelper.Execute(ctx, signed, onAck, onProgress)
}

func updateOp(t *testing.T, op, base string) *agentv1.SignedOperation {
	now := time.Now()
	n := make([]byte, 16)
	params := &agentv1.AgentUpdateParams{Version: "1.1.0", SignatureUrl: base + "/SHA256SUMS.minisig"}
	for _, b := range []string{"trassa-agent", "trassa-helper"} {
		params.Artifacts = append(params.Artifacts, &agentv1.ReleaseArtifact{Os: "linux", Arch: "amd64", Url: base + "/" + b + "-linux-amd64", Sha256: strings.Repeat("a", 64)})
	}
	body, _ := proto.Marshal(&agentv1.OperationBody{
		OperationId: op, ServerId: serverID, Type: "agent.update", Nonce: n,
		Params:     &agentv1.OperationParams{Params: &agentv1.OperationParams_AgentUpdate{AgentUpdate: params}},
		NotAfterMs: now.Add(5 * time.Minute).UnixMilli(), IssuedAtMs: now.UnixMilli(), Rollback: agentv1.RollbackKind_ROLLBACK_KIND_NONE,
	})
	return &agentv1.SignedOperation{Body: body, KeyId: "k1", Signature: ed25519.Sign(panelPriv, verify.Input(verify.ContextOperation, body))}
}

// Метрики (E08): накопленные без связи пачки уходят после рукопожатия во времени шлюза; подтверждённая пачка
// больше не шлётся, неподтверждённая уходит снова в следующем соединении, и ровно один раз.
func TestMetricsDelivery(t *testing.T) {
	id := newIdentity(t)
	agentNow := func() time.Time { return time.Now().Add(-time.Hour) } // часы агента отстают от шлюза на час
	buf := metrics.NewBuffer(agentNow)
	base := agentNow()
	buf.Add(&agentv1.MetricsBatch{CollectedAtMs: base.UnixMilli(), Metrics: []*agentv1.Metric{{Name: "load1", Value: 1}}})
	buf.Add(&agentv1.MetricsBatch{CollectedAtMs: base.Add(15 * time.Second).UnixMilli(), Metrics: []*agentv1.Metric{{Name: "load1", Value: 2}}})

	var mu sync.Mutex
	got := map[int][]*agentv1.MetricsBatch{}
	var conns atomic.Int32
	g := newGateway(t, id.PublicKey(), func(ctx context.Context, c *gwConn) {
		n := int(conns.Add(1))
		for {
			m, err := c.read(ctx)
			if err != nil {
				return
			}
			b := m.GetMetrics()
			if b == nil {
				continue
			}
			mu.Lock()
			got[n] = append(got[n], b)
			count := len(got[n])
			mu.Unlock()
			// Первое соединение подтверждает только первую пачку и рвётся после второй.
			if n > 1 || b.GetMetrics()[0].GetValue() == 1 {
				_ = c.send(ctx, &agentv1.GatewayMessage{Payload: &agentv1.GatewayMessage_InboundAck{InboundAck: &agentv1.InboundAck{Seq: m.GetSeq()}}})
			}
			if n == 1 && count == 2 {
				return
			}
		}
	})
	a := newAgent(t, id, g, newFakeHelper())
	a.cfg.Metrics = buf
	a.cfg.Now = agentNow
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = a.Run(ctx) }()
	waitFor(t, 5*time.Second, func() bool { return buf.Len() == 0 }, "все пачки подтверждены")

	mu.Lock()
	first, second := append([]*agentv1.MetricsBatch(nil), got[1]...), append([]*agentv1.MetricsBatch(nil), got[2]...)
	mu.Unlock()
	if len(first) != 2 {
		t.Fatalf("первое соединение: %d пачек", len(first))
	}
	if len(second) != 1 || second[0].GetMetrics()[0].GetValue() != 2 {
		t.Fatalf("второе соединение: %+v", second)
	}
	// Время пачки — в часах шлюза: агент добавил поправку из Welcome (около часа).
	skew := first[0].GetCollectedAtMs() - base.UnixMilli()
	if skew < (time.Hour-5*time.Second).Milliseconds() || skew > (time.Hour+5*time.Second).Milliseconds() {
		t.Fatalf("поправка часов %d мс", skew)
	}

	// Новая пачка во время соединения уходит сразу и один раз.
	buf.Add(&agentv1.MetricsBatch{CollectedAtMs: agentNow().UnixMilli(), Metrics: []*agentv1.Metric{{Name: "load1", Value: 3}}})
	waitFor(t, 5*time.Second, func() bool { return buf.Len() == 0 }, "новая пачка подтверждена")
	mu.Lock()
	defer mu.Unlock()
	threes := 0
	for _, bs := range got {
		for _, b := range bs {
			if b.GetMetrics()[0].GetValue() == 3 {
				threes++
			}
		}
	}
	if threes != 1 {
		t.Fatalf("новая пачка ушла %d раз", threes)
	}
}

// События (E08-T12) идут той же доставкой с квитанцией, время — в часах шлюза.
func TestEventsDelivery(t *testing.T) {
	id := newIdentity(t)
	agentNow := func() time.Time { return time.Now().Add(-time.Hour) }
	q := events.NewQueue(agentNow)
	at := agentNow().UnixMilli()
	q.Add(&agentv1.Event{Kind: events.CodeServiceDown, AtMs: at, Attributes: map[string]string{"subject": "nginx.service", "state": "firing"}})
	got := make(chan *agentv1.Event, 4)
	g := newGateway(t, id.PublicKey(), func(ctx context.Context, c *gwConn) {
		for {
			m, err := c.read(ctx)
			if err != nil {
				return
			}
			if e := m.GetEvent(); e != nil {
				got <- e
				_ = c.send(ctx, &agentv1.GatewayMessage{Payload: &agentv1.GatewayMessage_InboundAck{InboundAck: &agentv1.InboundAck{Seq: m.GetSeq()}}})
			}
		}
	})
	a := newAgent(t, id, g, newFakeHelper())
	a.cfg.Events = q
	a.cfg.Now = agentNow
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = a.Run(ctx) }()
	select {
	case e := <-got:
		if e.GetKind() != events.CodeServiceDown || e.GetAttributes()["subject"] != "nginx.service" {
			t.Fatalf("%+v", e)
		}
		if d := e.GetAtMs() - at; d < (time.Hour-5*time.Second).Milliseconds() || d > (time.Hour+5*time.Second).Milliseconds() {
			t.Fatalf("поправка часов %d мс", d)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("событие не пришло")
	}
	waitFor(t, 5*time.Second, func() bool { return q.Len() == 0 }, "событие подтверждено")
}

// Журналы (E08-T15): пачки с диска уходят до квитанции и удаляются после неё.
func TestLogsDelivery(t *testing.T) {
	id := newIdentity(t)
	spool, err := logs.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := spool.Append("op1", []*agentv1.LogRecord{{Message: "m", TimeMs: 1000}}, nil); err != nil {
			t.Fatal(err)
		}
	}
	got := make(chan *agentv1.LogChunk, 4)
	g := newGateway(t, id.PublicKey(), func(ctx context.Context, c *gwConn) {
		for {
			m, err := c.read(ctx)
			if err != nil {
				return
			}
			if ch := m.GetLogChunk(); ch != nil {
				got <- ch
				_ = c.send(ctx, &agentv1.GatewayMessage{Payload: &agentv1.GatewayMessage_InboundAck{InboundAck: &agentv1.InboundAck{Seq: m.GetSeq()}}})
			}
		}
	})
	a := newAgent(t, id, g, newFakeHelper())
	a.cfg.Logs = spool
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = a.Run(ctx) }()
	waitFor(t, 5*time.Second, func() bool { return len(spool.Pending()) == 0 }, "пачки подтверждены")
	if len(got) != 2 {
		t.Fatalf("пришло %d пачек", len(got))
	}
	ch := <-got
	if ch.GetSubscriptionId() != "op1" || ch.GetSeq() != 1 || len(ch.GetRecords()) != 1 {
		t.Fatalf("%+v", ch)
	}
}

// net.check (E07): исполняет сам агент — проверки 1–6, своё окно nonce, итог без помощника.
func TestNetCheckLocal(t *testing.T) {
	// Адрес интерфейса машины: loopback проверка связи не трогает (FORBIDDEN_TARGET).
	var ip string
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil && !n.IP.IsLoopback() && !n.IP.IsLinkLocalUnicast() {
				ip = n.IP.String()
				break
			}
		}
	}
	if ip == "" {
		t.Skip("нет адреса IPv4 кроме loopback")
	}
	l, err := net.Listen("tcp", net.JoinHostPort(ip, "0"))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	port := uint32(l.Addr().(*net.TCPAddr).Port)
	sign := func(op string, n []byte, p *agentv1.NetCheckParams) *agentv1.SignedOperation {
		now := time.Now()
		body, _ := proto.Marshal(&agentv1.OperationBody{
			OperationId: op, ServerId: serverID, Type: ops.TypeNetCheck, Nonce: n,
			Params:     &agentv1.OperationParams{Params: &agentv1.OperationParams_NetCheck{NetCheck: p}},
			NotAfterMs: now.Add(time.Minute).UnixMilli(), IssuedAtMs: now.UnixMilli(), Rollback: agentv1.RollbackKind_ROLLBACK_KIND_NONE,
		})
		return &agentv1.SignedOperation{Body: body, KeyId: "k1", Signature: ed25519.Sign(panelPriv, verify.Input(verify.ContextOperation, body))}
	}
	n := []byte("fedcba9876543210")
	got := make(chan *agentv1.AgentMessage, 16)
	id := newIdentity(t)
	g := newGateway(t, id.PublicKey(), func(ctx context.Context, c *gwConn) {
		for _, so := range []*agentv1.SignedOperation{
			sign(opID(1), n, &agentv1.NetCheckParams{Host: ip, Port: port, TimeoutMs: 1000}),
			sign(opID(2), n, &agentv1.NetCheckParams{Host: ip, Port: port}), // тот же nonce — повтор
			sign(opID(3), []byte("0123456789abcdef"), &agentv1.NetCheckParams{Host: "a b", Port: port}),
		} {
			_ = c.send(ctx, &agentv1.GatewayMessage{Payload: &agentv1.GatewayMessage_Operation{Operation: so}})
		}
		for {
			m, err := c.read(ctx)
			if err != nil {
				return
			}
			got <- m
			if m.GetOperationResult() != nil {
				_ = c.send(ctx, &agentv1.GatewayMessage{Payload: &agentv1.GatewayMessage_InboundAck{InboundAck: &agentv1.InboundAck{Seq: m.GetSeq()}}})
			}
		}
	})
	h := newFakeHelper()
	a := newAgent(t, id, g, h)
	ns, err := nonce.Open(filepath.Join(t.TempDir(), "nonces.log"), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	defer ns.Close()
	a.cfg.Local = &Local{Checker: &opcheck.Checker{Keys: panelKeys(), ServerID: serverID, Catalog: ops.Agent(), Nonces: ns}, Nonces: ns}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = a.Run(ctx) }()
	acks := map[string]string{}
	var res *agentv1.OperationResult
	timeout := time.After(5 * time.Second)
	for len(acks) < 3 || res == nil {
		select {
		case m := <-got:
			if ak := m.GetOperationAck(); ak != nil {
				acks[ak.GetOperationId()] = ak.GetRejectCode()
			}
			if r := m.GetOperationResult(); r != nil {
				res = r
			}
		case <-timeout:
			t.Fatalf("acks %v, итог %v", acks, res)
		}
	}
	// Операции идут параллельно: номер достаётся той, что пришла первой, другая получает REPLAY.
	winner, loser := opID(1), opID(2)
	if acks[winner] != "" {
		winner, loser = loser, winner
	}
	if acks[winner] != "" || acks[loser] != ops.CodeReplay || acks[opID(3)] != ops.CodeParamsInvalid {
		t.Fatalf("%v", acks)
	}
	if res.GetOperationId() != winner || !res.GetNetCheck().GetReachable() {
		t.Fatalf("%+v", res)
	}
	time.Sleep(100 * time.Millisecond)
	if h.reportedCount() != 0 || len(h.executed) != 0 {
		t.Fatal("net.check ушла помощнику")
	}
}

type encHelper struct{ *fakeHelper }

func (encHelper) EncryptionKey() ([]byte, string) { return bytes32(7), "kid-7" }

func bytes32(b byte) []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = b
	}
	return out
}

// Ключ шифрования секретов помощника (E13) уходит шлюзу в Hello.
func TestHelloEncryptionKey(t *testing.T) {
	id := newIdentity(t)
	hello := make(chan *agentv1.Hello, 1)
	g := newGateway(t, id.PublicKey(), func(ctx context.Context, c *gwConn) { hello <- c.hello; <-ctx.Done() })
	a := newAgent(t, id, g, encHelper{newFakeHelper()})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = a.Run(ctx) }()
	select {
	case h := <-hello:
		if len(h.GetEncryptionPublicKey()) != 32 || h.GetEncryptionKeyId() != "kid-7" {
			t.Fatalf("%+v", h)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("нет Hello")
	}
}

// Полуоткрытый канал (прод, ams1, 2026-11-26): после рукопожатия шлюз перестаёт читать — ни кадров, ни pong на ping,
// а запись агента уходит в буфер ядра без ошибки. Агент сам рвёт такой канал через keepaliveMisses пульсов без
// ответа и переподключается, а не держит его часами.
func TestReconnectWhenGatewayStopsAnswering(t *testing.T) {
	id := newIdentity(t)
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	var conns atomic.Int32
	g := newGateway(t, id.PublicKey(), func(ctx context.Context, c *gwConn) {
		if conns.Add(1) == 1 {
			<-stop // молчим: не читаем — pong не уходит, квитанций нет
			return
		}
		for {
			if _, err := c.read(ctx); err != nil {
				return
			}
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = newAgent(t, id, g, newFakeHelper()).Run(ctx) }()
	// Пульс 1 с (Welcome тестового шлюза): обрыв не позже keepaliveMisses+1 секунд.
	waitFor(t, time.Duration(keepaliveMisses+2)*time.Second, func() bool { return conns.Load() >= 2 }, "агент переподключился к молчащему шлюзу")
}
