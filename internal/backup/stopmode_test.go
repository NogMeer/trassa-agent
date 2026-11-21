// SPDX-License-Identifier: AGPL-3.0-only

package backup

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

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/dockerapi"
)

// stopDocker — Engine API: один том, контейнер web с ним; start может падать.
type stopDocker struct {
	mu        sync.Mutex
	state     map[string]string // id → running|exited
	calls     []string
	failStart int // сколько первых start отвечают 500
	filters   string
}

func startStopDocker(t *testing.T, mount string) (*stopDocker, *dockerapi.Client) {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "trb")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	l, err := net.Listen("unix", filepath.Join(dir, "d.sock"))
	if err != nil {
		t.Skipf("unix-сокет: %v", err)
	}
	d := &stopDocker{state: map[string]string{"c1": "running"}}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d.mu.Lock()
		defer d.mu.Unlock()
		w.Header().Set("Api-Version", "1.44")
		p := strings.TrimPrefix(r.URL.Path, "/v1.44")
		switch {
		case p == "/_ping":
		case p == "/volumes/data":
			_ = json.NewEncoder(w).Encode(map[string]string{"Name": "data", "Driver": "local", "Mountpoint": mount})
		case p == "/containers/json":
			d.filters = r.URL.Query().Get("filters")
			var out []map[string]any
			for id, st := range d.state {
				if st == "running" {
					out = append(out, map[string]any{"Id": id, "Names": []string{"/web"}})
				}
			}
			_ = json.NewEncoder(w).Encode(out)
		case strings.HasSuffix(p, "/stop"):
			d.calls = append(d.calls, "stop")
			d.state["c1"] = "exited"
			w.WriteHeader(http.StatusNoContent)
		case strings.HasSuffix(p, "/start"):
			d.calls = append(d.calls, "start")
			if d.failStart > 0 {
				d.failStart--
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			d.state["c1"] = "running"
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
	return d, &dockerapi.Client{Socket: filepath.Join(dir, "d.sock")}
}

func (d *stopDocker) running() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.state["c1"] == "running"
}

func TestRunPlanVolumeStop(t *testing.T) {
	restartDelay = time.Millisecond
	mount := tmp(t)
	f := newFake(t)
	r := f.restic("rest:https://bk.example/p", nil)
	d, cl := startStopDocker(t, mount)
	e := &Env{Docker: cl, WorkDir: filepath.Join(tmp(t), "work")}
	src := []*agentv1.BackupSource{{Name: "vol", Source: &agentv1.BackupSource_DockerVolume{DockerVolume: "data"}, VolumeMode: agentv1.VolumeMode_VOLUME_MODE_STOP}}
	run := func() (*agentv1.BackupRunResult, string, []*agentv1.Event) {
		var evs []*agentv1.Event
		res, code, err := e.RunPlan(context.Background(), r, RunJob{Params: &agentv1.BackupRunParams{PlanId: planID, Sources: src},
			Deadline: time.Now().Add(time.Minute), Event: func(ev *agentv1.Event) { evs = append(evs, ev) }})
		if err != nil {
			t.Fatal(err)
		}
		return res, code, evs
	}

	// Успех: остановлен, скопирован, запущен; список на диске убран.
	f.on("backup", `{"message_type":"summary","snapshot_id":"dddddddd44"}`+"\n", 0)
	res, code, evs := run()
	if code != "" || !res.Sources[0].GetOk() || strings.Join(res.Sources[0].GetStoppedContainers(), ",") != "web" || !d.running() || len(evs) != 0 {
		t.Fatalf("успех: %q %+v %v", code, res.Sources[0], d.calls)
	}
	if !strings.Contains(d.filters, `"volume":["data"]`) || !strings.Contains(d.filters, `"running"`) {
		t.Fatalf("фильтр: %s", d.filters)
	}
	if _, err := os.Stat(e.stoppedPath()); !os.IsNotExist(err) {
		t.Fatal("список остановленных остался")
	}

	// Копия упала — контейнер всё равно запущен.
	f.on("backup", "", 1, "", `{"message_type":"exit_error","code":1,"message":"boom"}`)
	res, code, _ = run()
	if code != CodeSourceFailed || res.Sources[0].GetOk() || !d.running() {
		t.Fatalf("сбой копии: %q %+v", code, res.Sources[0])
	}

	// Три неудачных запуска — код, событие CRIT, список остаётся для запуска при старте помощника.
	f.on("backup", `{"message_type":"summary","snapshot_id":"dddddddd45"}`+"\n", 0)
	d.failStart = 3
	res, code, evs = run()
	if code != CodeContainerNotRestarted || strings.Join(res.Sources[0].GetNotRestarted(), ",") != "web" || d.running() ||
		len(evs) != 1 || evs[0].GetKind() != EventContainerNotRestarted || evs[0].GetSeverity() != agentv1.EventSeverity_EVENT_SEVERITY_CRIT {
		t.Fatalf("не запущен: %q %+v %v", code, res.Sources[0], evs)
	}
	if err := e.RestartStopped(context.Background()); err != nil || !d.running() {
		t.Fatalf("запуск при старте: %v", err)
	}
	if _, err := os.Stat(e.stoppedPath()); !os.IsNotExist(err) {
		t.Fatal("список остался после запуска")
	}

	// Проверка: режим только у тома и только из перечня.
	if err := checkSource(src[0]); err != nil {
		t.Fatal(err)
	}
	if checkSource(&agentv1.BackupSource{Name: "p", Source: &agentv1.BackupSource_Path{Path: &agentv1.PathSource{Path: "/srv"}},
		VolumeMode: agentv1.VolumeMode_VOLUME_MODE_STOP}) == nil {
		t.Fatal("volume_mode у пути принят")
	}
	if checkSource(&agentv1.BackupSource{Name: "v", Source: &agentv1.BackupSource_DockerVolume{DockerVolume: "data"}, VolumeMode: 9}) == nil {
		t.Fatal("неизвестный volume_mode принят")
	}
}
