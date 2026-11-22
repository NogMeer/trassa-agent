// SPDX-License-Identifier: AGPL-3.0-only

package remedy

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
)

type appHealthCases struct {
	States []struct {
		Name       string         `json:"name"`
		Containers []AppContainer `json:"containers"`
		State      string         `json:"state"`
		Reason     string         `json:"reason"`
	} `json:"states"`
	Sequences []struct {
		Name         string      `json:"name"`
		Observations [][2]string `json:"observations"`
		Events       []struct {
			At     int    `json:"at"`
			State  string `json:"state"`
			Reason string `json:"reason"`
		} `json:"events"`
	} `json:"sequences"`
}

// Общий набор с панелью: состояние по контейнерам и гашение дребезга.
func TestAppHealthShared(t *testing.T) {
	raw, err := os.ReadFile("../../proto/testdata/app-health.json")
	if err != nil {
		t.Fatal(err)
	}
	var c appHealthCases
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	if len(c.States) < 15 || len(c.Sequences) < 8 {
		t.Fatalf("набор мал: %d, %d", len(c.States), len(c.Sequences))
	}
	for _, s := range c.States {
		if st, r := AppState(s.Containers); st != s.State || r != s.Reason {
			t.Errorf("%s: %s %s, ждали %s %s", s.Name, st, r, s.State, s.Reason)
		}
	}
	for _, s := range c.Sequences {
		w := &appWatch{}
		var got []string
		for i, o := range s.Observations {
			if ev, r := w.step(o[0], o[1]); ev != "" {
				got = append(got, jsonEv(i, ev, r))
			}
		}
		var want []string
		for _, e := range s.Events {
			want = append(want, jsonEv(e.At, e.State, e.Reason))
		}
		if len(got) != len(want) {
			t.Errorf("%s: %v, ждали %v", s.Name, got, want)
			continue
		}
		for i := range got {
			if got[i] != want[i] {
				t.Errorf("%s: %v, ждали %v", s.Name, got, want)
			}
		}
	}
}

func jsonEv(at int, state, reason string) string {
	b, _ := json.Marshal([]any{at, state, reason})
	return string(b)
}

const healthApp = "01a1f4b6-f327-7a5d-ac23-e95c272c0fe8"

// Наблюдатель: контейнеры приложения по метке, здоровье из inspect, события после дребезга, пропавшее приложение.
func TestWatcherApps(t *testing.T) {
	e, c := newEnv(t)
	d, cl := startDocker(t, c)
	e.Docker = cl
	d.list = []map[string]any{
		{"Id": "a1", "Names": []string{"/web"}, "State": "running", "Labels": map[string]string{labelApp: healthApp}},
		{"Id": "a2", "Names": []string{"/migrate"}, "State": "exited", "Labels": map[string]string{labelApp: healthApp}},
		{"Id": "x1", "Names": []string{"/other"}, "State": "restarting", "Labels": map[string]string{}},
		{"Id": "x2", "Names": []string{"/bad"}, "State": "restarting", "Labels": map[string]string{labelApp: "not-uuid"}},
	}
	health := func(s string) {
		d.mu.Lock()
		d.cont["a1"] = map[string]any{"Id": "a1", "State": map[string]any{"Status": "running", "Health": map[string]any{"Status": s}}}
		d.mu.Unlock()
	}
	w := &Watcher{Env: e}
	health("unhealthy")
	for i := 0; i < UnhealthyTicks-1; i++ {
		if evs := w.Apps(context.Background()); len(evs) != 0 {
			t.Fatalf("дребезг %d: %+v", i, evs)
		}
	}
	evs := w.Apps(context.Background())
	if len(evs) != 1 || evs[0].GetKind() != EventAppUnhealthy || evs[0].GetSeverity() != agentv1.EventSeverity_EVENT_SEVERITY_CRIT ||
		evs[0].GetAttributes()["app_id"] != healthApp || evs[0].GetAttributes()["state"] != "firing" || evs[0].GetAttributes()["reason"] != ReasonCheck {
		t.Fatalf("firing: %+v", evs)
	}
	health("healthy")
	if evs := w.Apps(context.Background()); len(evs) != 0 {
		t.Fatalf("один здоровый: %+v", evs)
	}
	if evs := w.Apps(context.Background()); len(evs) != 1 || evs[0].GetAttributes()["state"] != "resolved" {
		t.Fatalf("resolved: %+v", evs)
	}
	// Контейнеры удалены не через Trassa: MISSING после дребезга, затем приложение забыто.
	d.mu.Lock()
	d.list = d.list[2:]
	d.mu.Unlock()
	var last []*agentv1.Event
	for i := 0; i < UnhealthyTicks; i++ {
		last = w.Apps(context.Background())
	}
	if len(last) != 1 || last[0].GetAttributes()["reason"] != ReasonMissing || len(w.apps) != 0 {
		t.Fatalf("missing: %+v %d", last, len(w.apps))
	}
	// Без Docker — событий нет и счётчики не трогаются.
	e.Docker = nil
	if evs := w.Apps(context.Background()); evs != nil {
		t.Fatalf("без docker: %+v", evs)
	}
}
