// SPDX-License-Identifier: AGPL-3.0-only

package events

import (
	"context"
	"log/slog"
	"strconv"
	"time"

	"google.golang.org/protobuf/proto"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/queue"
)

// Связь в приватной сети (E14-T14): порог — 180 с без рукопожатия (REJECT_AFTER_TIME ядра, решение продукта;
// decisions E14, п. 8).
const (
	CodeLinkStale    = "wireguard.link_stale"
	CodeLinkRestored = "wireguard.link_restored"
	LinkStaleAfter   = 180 * time.Second
)

// WgStatsSource — метрики пиров от помощника (helperrpc.Client.WgStats).
type WgStatsSource interface {
	WgStats(ctx context.Context) ([]byte, error)
}

// LinkWatcher — состояние связей: устарела ли и с какого момента пир виден без рукопожатия.
type LinkWatcher struct {
	stale     map[string]bool
	firstSeen map[string]time.Time
}

// NewLinkWatcher — без сработавших порогов.
func NewLinkWatcher() *LinkWatcher {
	return &LinkWatcher{stale: map[string]bool{}, firstSeen: map[string]time.Time{}}
}

// Observe — события по пачке wg.stats. Пир без рукопожатия (возраст −1) устаревшим считается через
// LinkStaleAfter после первого появления.
func (w *LinkWatcher) Observe(now time.Time, b *agentv1.MetricsBatch) []*agentv1.Event {
	var out []*agentv1.Event
	seen := map[string]bool{}
	for _, m := range b.GetMetrics() {
		if m.GetName() != "wg_peer_handshake_age_seconds" {
			continue
		}
		iface, peer := m.GetLabels()["iface"], m.GetLabels()["peer"]
		k := iface + "\x00" + peer
		seen[k] = true
		if _, ok := w.firstSeen[k]; !ok {
			w.firstSeen[k] = now
		}
		age := m.GetValue()
		stale := age > LinkStaleAfter.Seconds() || (age < 0 && now.Sub(w.firstSeen[k]) >= LinkStaleAfter)
		if stale == w.stale[k] {
			continue
		}
		w.stale[k] = stale
		code, state, sev := CodeLinkRestored, "resolved", agentv1.EventSeverity_EVENT_SEVERITY_INFO
		if stale {
			code, state, sev = CodeLinkStale, "firing", agentv1.EventSeverity_EVENT_SEVERITY_WARN
		}
		out = append(out, &agentv1.Event{Kind: code, Severity: sev, AtMs: now.UnixMilli(), Message: code + " " + iface + " " + peer,
			Attributes: map[string]string{"iface": iface, "peer": peer, "state": state, "handshake_age": strconv.FormatFloat(age, 'f', 0, 64)}})
	}
	for k := range w.firstSeen {
		if !seen[k] {
			delete(w.firstSeen, k)
			delete(w.stale, k)
		}
	}
	return out
}

// PollWg — раз в every: метрики пиров в буфер метрик, события связей в очередь событий.
func PollWg(ctx context.Context, src WgStatsSource, metrics func(*agentv1.MetricsBatch), q *queue.Queue[*agentv1.Event], every time.Duration, now func() time.Time, log *slog.Logger) {
	w := NewLinkWatcher()
	failing := ""
	for {
		raw, err := src.WgStats(ctx)
		switch {
		case err != nil && err.Error() != failing:
			log.Debug("приватная сеть: wg.stats", "err", err)
			failing = err.Error()
		case err == nil:
			failing = ""
			var b agentv1.MetricsBatch
			if proto.Unmarshal(raw, &b) == nil && len(b.GetMetrics()) > 0 {
				b.CollectedAtMs = now().UnixMilli()
				metrics(&b)
				for _, e := range w.Observe(now(), &b) {
					q.Add(e)
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		}
	}
}
