// SPDX-License-Identifier: AGPL-3.0-only

package metrics

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
)

func TestBuffer(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	b := NewBuffer(func() time.Time { return now })
	for i := 0; i < 3; i++ {
		b.Add(&agentv1.MetricsBatch{CollectedAtMs: now.Add(time.Duration(i) * Interval).UnixMilli()})
	}
	select {
	case <-b.Notify():
	default:
		t.Fatal("нет сигнала о пачке")
	}
	p := b.Pending()
	if len(p) != 3 || p[0].ID != 1 || p[2].ID != 3 {
		t.Fatalf("%+v", p)
	}
	b.Ack(2)
	b.Ack(99) // чужой номер — без последствий
	if p := b.Pending(); len(p) != 2 || p[1].ID != 3 {
		t.Fatalf("после Ack: %+v", p)
	}
	// Без связи дольше 10 минут: старые пачки вытесняются.
	now = now.Add(MaxAge + 2*Interval + time.Second) // старше 10 минут все три прежние
	b.Add(&agentv1.MetricsBatch{CollectedAtMs: now.UnixMilli()})
	if p := b.Pending(); len(p) != 1 || p[0].ID != 4 {
		t.Fatalf("после 10 минут: %+v", p)
	}
}

// Без связи пачки копятся не больше чем за 10 минут: 40 пачек по 15 с.
func TestRunBuffersOffline(t *testing.T) {
	proc := writeTree(t, map[string]string{
		"stat": stat1, "meminfo": meminfo, "loadavg": loadavg, "uptime": uptime,
		"net/tcp": tcp, "net/dev": netdev1, "self/mountinfo": mountinfo,
	})
	c := &Collector{Proc: proc, Sys: t.TempDir(), Statfs: fakeStatfs}
	clock := time.Unix(1_700_000_000, 0)
	b := NewBuffer(func() time.Time { return clock })
	for i := 0; i < 100; i++ {
		batch, _ := c.Collect(clock)
		b.Add(batch)
		clock = clock.Add(Interval)
	}
	if n := b.Len(); n < 40 || n > 41 {
		t.Fatalf("в буфере %d пачек, ждали ~40", n)
	}
	// Run снимает первую пачку сразу и останавливается по ctx.
	ctx, cancel := context.WithCancel(context.Background())
	rb := NewBuffer(nil)
	done := make(chan struct{})
	go func() {
		Run(ctx, c, time.Hour, nil, slog.New(slog.NewTextHandler(io.Discard, nil)), func(b *agentv1.MetricsBatch) { rb.Add(b) })
		close(done)
	}()
	<-rb.Notify()
	cancel()
	<-done
	if rb.Len() != 1 {
		t.Fatalf("Run: %d пачек", rb.Len())
	}
}
