// SPDX-License-Identifier: AGPL-3.0-only

package metrics

import (
	"context"
	"log/slog"
	"sync"
	"time"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
)

// Период сбора и сколько копить без связи (E08, раздел 6).
const (
	Interval = 15 * time.Second
	MaxAge   = 10 * time.Minute
)

// Item — пачка в буфере. ID растёт с каждой пачкой; по нему канал отмечает доставку.
type Item struct {
	ID    uint64
	Batch *agentv1.MetricsBatch
}

// Buffer — пачки, которые шлюз ещё не подтвердил (InboundAck). Хранит не дольше MaxAge: без связи старые
// пачки вытесняются новыми.
type Buffer struct {
	mu     sync.Mutex
	items  []Item
	next   uint64
	notify chan struct{}
	now    func() time.Time
}

// NewBuffer — пустой буфер; now — часы для срока хранения (nil — time.Now).
func NewBuffer(now func() time.Time) *Buffer {
	if now == nil {
		now = time.Now
	}
	return &Buffer{notify: make(chan struct{}, 1), now: now}
}

// Add кладёт пачку и будит отправителя.
func (b *Buffer) Add(batch *agentv1.MetricsBatch) {
	b.mu.Lock()
	b.next++
	b.items = append(b.items, Item{ID: b.next, Batch: batch})
	b.pruneLocked()
	b.mu.Unlock()
	select {
	case b.notify <- struct{}{}:
	default:
	}
}

// Pending — неподтверждённые пачки по порядку, без просроченных.
func (b *Buffer) Pending() []Item {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.pruneLocked()
	return append([]Item(nil), b.items...)
}

// Ack убирает доставленную пачку.
func (b *Buffer) Ack(id uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for i, it := range b.items {
		if it.ID == id {
			b.items = append(b.items[:i], b.items[i+1:]...)
			return
		}
	}
}

// Notify — сигнал «появилась пачка».
func (b *Buffer) Notify() <-chan struct{} { return b.notify }

// Len — сколько пачек ждёт доставки.
func (b *Buffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.items)
}

func (b *Buffer) pruneLocked() {
	cut := b.now().Add(-MaxAge).UnixMilli()
	i := 0
	for i < len(b.items) && b.items[i].Batch.GetCollectedAtMs() < cut {
		i++
	}
	if i > 0 {
		b.items = append([]Item(nil), b.items[i:]...)
	}
}

// Run снимает пачку раз в every и кладёт в буфер — независимо от связи со шлюзом. Ошибка источника не
// останавливает сбор: она пишется в журнал один раз, пока источник не восстановится.
func Run(ctx context.Context, c *Collector, b *Buffer, every time.Duration, now func() time.Time, log *slog.Logger) {
	if now == nil {
		now = time.Now
	}
	failing := map[string]bool{}
	tick := time.NewTicker(every)
	defer tick.Stop()
	for {
		batch, errs := c.Collect(now())
		cur := map[string]bool{}
		for _, err := range errs {
			cur[err.Error()] = true
			if !failing[err.Error()] {
				log.Warn("метрики: источник не прочитан", "err", err)
			}
		}
		failing = cur
		if len(batch.GetMetrics()) > 0 {
			b.Add(batch)
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
