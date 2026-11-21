// SPDX-License-Identifier: AGPL-3.0-only

package deploy

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/NogMeer/trassa-agent/internal/dockerapi"
)

type statsDocker struct {
	mu    sync.Mutex
	conts []map[string]any
	stats map[string]map[string]any
}

func startStatsDocker(t *testing.T) (*statsDocker, *dockerapi.Client) {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "trs")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "d.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	d := &statsDocker{stats: map[string]map[string]any{}}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d.mu.Lock()
		defer d.mu.Unlock()
		p := r.URL.Path
		if i := strings.Index(p[1:], "/"); strings.HasPrefix(p, "/v1.") && i > 0 {
			p = p[i+1:]
		}
		switch {
		case p == "/_ping" || p == "/version":
			_, _ = w.Write([]byte(`{"ApiVersion":"1.44","Version":"27.0.0"}`))
		case p == "/containers/json":
			_ = json.NewEncoder(w).Encode(d.conts)
		case strings.HasSuffix(p, "/stats"):
			id := strings.Split(p, "/")[2]
			if r.URL.Query().Get("stream") != "false" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(d.stats[id])
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
	return d, &dockerapi.Client{Socket: sock}
}

func stat(total, system, usage, inactive uint64) map[string]any {
	return map[string]any{
		"cpu_stats":    map[string]any{"cpu_usage": map[string]any{"total_usage": total}, "system_cpu_usage": system},
		"memory_stats": map[string]any{"usage": usage, "stats": map[string]any{"inactive_file": inactive}},
	}
}

func TestAppStats(t *testing.T) {
	d, cl := startStatsDocker(t)
	const a1, a2 = "01a1f4b6-f327-7a5d-ac23-e95c272c0fe8", "01a1f4b6-f327-7a5d-ac23-e95c272c0fe9"
	d.conts = []map[string]any{
		{"Id": "c1", "State": "running", "Labels": map[string]string{LabelApp: a1}},
		{"Id": "c2", "State": "running", "Labels": map[string]string{LabelApp: a1}},
		{"Id": "c3", "State": "exited", "Labels": map[string]string{LabelApp: a2}},
		{"Id": "c4", "State": "running", "Labels": map[string]string{LabelApp: "not-a-uuid"}},
	}
	d.stats["c1"] = stat(1000, 100000, 300<<20, 100<<20)
	d.stats["c2"] = stat(2000, 100000, 50<<20, 0)
	clock := time.Unix(1_800_000_000, 0)
	s := &AppStats{Env: &Env{Docker: cl}, Now: func() time.Time { return clock }}
	ms, err := s.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// Первая пачка: память есть, CPU нет (нет прошлого замера); остановленные и чужие метки не считаются.
	if len(ms) != 1 || ms[0].GetName() != "app_mem_used_bytes" || ms[0].GetValue() != float64(250<<20) || ms[0].GetLabels()["app_id"] != a1 {
		t.Fatalf("%+v", ms)
	}
	// Повторный вызов раньше MinInterval — тот же итог из кэша.
	if again, _ := s.Collect(context.Background()); len(again) != 1 {
		t.Fatalf("кэш: %+v", again)
	}
	clock = clock.Add(MinInterval)
	d.mu.Lock()
	d.stats["c1"] = stat(11000, 200000, 300<<20, 100<<20) // +10 000 из +100 000 — 10 %
	d.stats["c2"] = stat(7000, 200000, 50<<20, 0)         // +5 000 — 5 %
	d.mu.Unlock()
	ms, err = s.Collect(context.Background())
	if err != nil || len(ms) != 2 || ms[1].GetName() != "app_cpu_usage_percent" || ms[1].GetValue() != 15 {
		t.Fatalf("%+v %v", ms, err)
	}
	// Новый контейнер приложения: CPU этого приложения в пачке нет, пока нет его прошлого замера.
	d.mu.Lock()
	d.conts = append(d.conts, map[string]any{"Id": "c5", "State": "running", "Labels": map[string]string{LabelApp: a1}})
	d.stats["c5"] = stat(10, 300000, 1<<20, 0)
	d.stats["c1"] = stat(12000, 300000, 300<<20, 100<<20)
	d.stats["c2"] = stat(8000, 300000, 50<<20, 0)
	d.mu.Unlock()
	clock = clock.Add(MinInterval)
	if ms, _ = s.Collect(context.Background()); len(ms) != 1 {
		t.Fatalf("новый контейнер: %+v", ms)
	}
	// Без Docker — ошибка, не пустая «нулевая» метрика.
	if _, err := (&AppStats{Env: &Env{}}).Collect(context.Background()); err == nil {
		t.Fatal("без Docker")
	}
}
