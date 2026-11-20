// SPDX-License-Identifier: AGPL-3.0-only

package metrics

import (
	"context"
	"log/slog"
	"time"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/queue"
)

// Период сбора и сколько копить без связи (E08, раздел 6).
const (
	Interval = 15 * time.Second
	MaxAge   = 10 * time.Minute
)

// Buffer — пачки, которые шлюз ещё не подтвердил (InboundAck). Хранит не дольше MaxAge: без связи старые
// пачки вытесняются новыми.
type Buffer = queue.Queue[*agentv1.MetricsBatch]

// NewBuffer — пустой буфер; now — часы для срока хранения (nil — time.Now).
func NewBuffer(now func() time.Time) *Buffer {
	if now == nil {
		now = time.Now
	}
	return queue.New(int(MaxAge/Interval)+1, func(b *agentv1.MetricsBatch) bool {
		return b.GetCollectedAtMs() >= now().Add(-MaxAge).UnixMilli()
	})
}

// Run снимает пачку раз в every и отдаёт её каждому sink (буфер отправки, пороги событий) — независимо от связи
// со шлюзом. Ошибка источника не останавливает сбор: она пишется в журнал один раз, пока источник не
// восстановится. Пустая пачка не отдаётся.
func Run(ctx context.Context, c *Collector, every time.Duration, now func() time.Time, log *slog.Logger, sinks ...func(*agentv1.MetricsBatch)) {
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
			for _, sink := range sinks {
				sink(batch)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
