// SPDX-License-Identifier: AGPL-3.0-only

package channel

import (
	"context"
	"crypto/ed25519"
	"errors"
	"math/rand/v2"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
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
	time.Sleep(3 * time.Second)
	calm.Store(true)
	waitFor(t, 10*time.Second, func() bool {
		h.mu.Lock()
		defer h.mu.Unlock()
		return len(h.results) == 0 && len(h.reported) == len(h.executed)
	}, "доставка всех итогов после успокоения сети")
	cancel()
	<-done
	if a.Sessions() < 30 {
		t.Fatalf("сессий всего %d", a.Sessions())
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for op, n := range h.executed {
		if n != 1 {
			t.Fatalf("%s выполнена %d раз", op, n)
		}
	}
	t.Logf("сессий %d, операций отправлено %d, выполнено %d", a.Sessions(), next.Load(), len(h.executed))
}
