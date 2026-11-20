// SPDX-License-Identifier: AGPL-3.0-only

package events

import (
	"testing"
	"time"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
)

func wgBatch(age float64) *agentv1.MetricsBatch {
	return &agentv1.MetricsBatch{Metrics: []*agentv1.Metric{{Name: "wg_peer_handshake_age_seconds", Value: age,
		Labels: map[string]string{"iface": "wg0", "peer": "PEERKEY="}}}}
}

func TestLinkWatcher(t *testing.T) {
	w := NewLinkWatcher()
	t0 := time.Unix(1_800_000_000, 0)
	if ev := w.Observe(t0, wgBatch(30)); len(ev) != 0 {
		t.Fatal(ev)
	}
	ev := w.Observe(t0.Add(time.Minute), wgBatch(200))
	if len(ev) != 1 || ev[0].GetKind() != CodeLinkStale || ev[0].GetAttributes()["peer"] != "PEERKEY=" || ev[0].GetAttributes()["state"] != "firing" {
		t.Fatalf("%v", ev)
	}
	if ev := w.Observe(t0.Add(2*time.Minute), wgBatch(260)); len(ev) != 0 {
		t.Fatal("повтор устаревания")
	}
	if ev := w.Observe(t0.Add(3*time.Minute), wgBatch(5)); len(ev) != 1 || ev[0].GetKind() != CodeLinkRestored {
		t.Fatalf("%v", ev)
	}
	// Пир без рукопожатия: событие только через 180 с после первого появления.
	w = NewLinkWatcher()
	if ev := w.Observe(t0, wgBatch(-1)); len(ev) != 0 {
		t.Fatal("сразу устарел")
	}
	if ev := w.Observe(t0.Add(LinkStaleAfter), wgBatch(-1)); len(ev) != 1 || ev[0].GetKind() != CodeLinkStale {
		t.Fatalf("%v", ev)
	}
}
