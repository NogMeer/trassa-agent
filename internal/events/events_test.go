// SPDX-License-Identifier: AGPL-3.0-only

package events

import (
	"testing"
	"time"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/sysinfo"
)

func batch(mem float64, disks map[string]float64) *agentv1.MetricsBatch {
	b := &agentv1.MetricsBatch{}
	if mem >= 0 {
		b.Metrics = append(b.Metrics, &agentv1.Metric{Name: "mem_used_percent", Value: mem})
	}
	for m, v := range disks {
		b.Metrics = append(b.Metrics, &agentv1.Metric{Name: "disk_used_percent", Value: v, Labels: map[string]string{"mount": m}})
	}
	return b
}

func summary(evs []*agentv1.Event) []string {
	var out []string
	for _, e := range evs {
		out = append(out, e.GetKind()+" "+e.GetAttributes()["subject"]+" "+e.GetAttributes()["state"])
	}
	return out
}

func expect(t *testing.T, step string, got []*agentv1.Event, want ...string) {
	t.Helper()
	s := summary(got)
	if len(s) != len(want) {
		t.Fatalf("%s: %v, ждали %v", step, s, want)
	}
	for i := range want {
		if s[i] != want[i] {
			t.Fatalf("%s: %v, ждали %v", step, s, want)
		}
	}
}

func TestDisk(t *testing.T) {
	d := NewDetector()
	t0 := time.Unix(1_700_000_000, 0)
	expect(t, "ниже порога", d.Observe(t0, batch(-1, map[string]float64{"/": 89.9}), nil))
	evs := d.Observe(t0, batch(-1, map[string]float64{"/": 90}), nil)
	expect(t, "порог", evs, "disk.full / firing")
	if a := evs[0].GetAttributes(); a["value"] != "90.0" || a["threshold"] != "90" || evs[0].GetAtMs() != t0.UnixMilli() {
		t.Fatalf("атрибуты: %v", a)
	}
	expect(t, "держится", d.Observe(t0, batch(-1, map[string]float64{"/": 95}), nil))
	expect(t, "у границы не снимается", d.Observe(t0, batch(-1, map[string]float64{"/": 89}), nil))
	expect(t, "раздел пропал из пачки — не снимается", d.Observe(t0, batch(-1, nil), nil))
	expect(t, "снятие", d.Observe(t0, batch(-1, map[string]float64{"/": 80}), nil), "disk.full / resolved")
}

func TestMemForAMinute(t *testing.T) {
	d := NewDetector()
	t0 := time.Unix(1_700_000_000, 0)
	expect(t, "первый замер", d.Observe(t0, batch(96, nil), nil))
	expect(t, "через 45 с", d.Observe(t0.Add(45*time.Second), batch(97, nil), nil))
	expect(t, "через минуту", d.Observe(t0.Add(60*time.Second), batch(97, nil), nil), "mem.high  firing")
	// Короткий провал между возвратом и порогом не снимает событие.
	expect(t, "94%", d.Observe(t0.Add(75*time.Second), batch(94, nil), nil))
	expect(t, "снятие", d.Observe(t0.Add(90*time.Second), batch(90, nil), nil), "mem.high  resolved")
	// Всплеск короче минуты события не даёт.
	d.Observe(t0.Add(100*time.Second), batch(99, nil), nil)
	d.Observe(t0.Add(130*time.Second), batch(94, nil), nil)
	expect(t, "всплеск", d.Observe(t0.Add(165*time.Second), batch(99, nil), nil))
}

func TestServices(t *testing.T) {
	d := NewDetector()
	t0 := time.Unix(1_700_000_000, 0)
	units := []sysinfo.Unit{
		{Name: "nginx.service", ActiveState: "failed"},
		{Name: "cron.service", ActiveState: "active"},
		{Name: "backup.timer", ActiveState: "failed"}, // не служба
		{Name: "a.service", ActiveState: "failed"},
	}
	expect(t, "упали", d.Observe(t0, batch(-1, nil), units), "service.down a.service firing", "service.down nginx.service firing")
	expect(t, "D-Bus недоступен — без изменений", d.Observe(t0, batch(-1, nil), nil))
	units[0].ActiveState = "active"
	expect(t, "nginx поднялся", d.Observe(t0, batch(-1, nil), units), "service.down nginx.service resolved")
	expect(t, "a.service пропал из списка", d.Observe(t0, batch(-1, nil), units[1:3]), "service.down a.service resolved")
}

func TestServiceLimit(t *testing.T) {
	d := NewDetector()
	var units []sysinfo.Unit
	for i := 0; i < 300; i++ {
		units = append(units, sysinfo.Unit{Name: "s" + string(rune('a'+i%26)) + string(rune('a'+i/26)) + ".service", ActiveState: "failed"})
	}
	if n := len(d.Observe(time.Now(), batch(-1, nil), units)); n != MaxServices {
		t.Fatalf("%d событий", n)
	}
}

func TestQueueAge(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	q := NewQueue(func() time.Time { return now })
	q.Add(&agentv1.Event{Kind: CodeDiskFull, AtMs: now.UnixMilli()})
	now = now.Add(MaxAge + time.Second)
	if q.Len() != 1 || len(q.Pending()) != 0 {
		t.Fatal("событие старше часа не вытеснено")
	}
}
