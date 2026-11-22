// SPDX-License-Identifier: AGPL-3.0-only

package remedy

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
)

func composeLabels(service string) map[string]string {
	return map[string]string{labelComposeProject: "trassa", labelComposeService: service}
}

func listedC(id, name, state string, created int64, labels map[string]string) map[string]any {
	return map[string]any{"Id": id, "Names": []string{"/" + name}, "State": state, "Created": created, "Labels": labels}
}

func inspectedC(id string, code int, policy string) map[string]any {
	return map[string]any{"Id": id, "State": map[string]any{"ExitCode": code}, "HostConfig": map[string]any{"RestartPolicy": map[string]any{"Name": policy}}}
}

func collect(w *Watcher, n int, step func(i int)) []*agentv1.Event {
	var out []*agentv1.Event
	for i := 0; i < n; i++ {
		if step != nil {
			step(i)
		}
		out = append(out, w.Containers(context.Background())...)
	}
	return out
}

// Прод, 2026-11-22: compose остановил trassa-api-10 (unless-stopped, код 1) на 16 минут, поднял trassa-api-11 и
// удалил -10; pgbackup-1 пересоздан с тем же именем. Ни одного события.
func TestWatcherComposeReplacement(t *testing.T) {
	e, c := newEnv(t)
	d, cl := startDocker(t, c)
	e.Docker = cl
	w := &Watcher{Env: e}
	d.list = []map[string]any{
		listedC("a10", "trassa-api-10", "exited", 100, composeLabels("api")),
		listedC("p1", "trassa-pgbackup-1", "exited", 100, composeLabels("pgbackup")),
	}
	d.cont["a10"] = inspectedC("a10", 1, "unless-stopped")
	d.cont["p1"] = inspectedC("p1", 137, "unless-stopped")
	evs := collect(w, 16, func(int) { c.t = c.t.Add(time.Minute) })
	d.list = []map[string]any{
		listedC("a10", "trassa-api-10", "exited", 100, composeLabels("api")),
		listedC("a11", "trassa-api-11", "running", 200, composeLabels("api")),
		listedC("p2", "trassa-pgbackup-1", "running", 300, composeLabels("pgbackup")),
	}
	evs = append(evs, collect(w, 2, nil)...)
	d.list = d.list[1:]
	evs = append(evs, collect(w, 2, nil)...)
	if len(evs) != 0 {
		t.Fatalf("ложные события: %v", evs)
	}
}

// 1) Удалённый контейнер — не «остановился»: служба без контейнеров снимает сработавшее и не срабатывает сама.
func TestWatcherRemovedIsNotDown(t *testing.T) {
	e, c := newEnv(t)
	d, cl := startDocker(t, c)
	e.Docker = cl
	w := &Watcher{Env: e}
	// Контейнер упал (on-failure, код 1) и через полминуты удалён — до срока DownFor: события нет.
	d.list = []map[string]any{listedC("j1", "job", "exited", 100, nil)}
	d.cont["j1"] = inspectedC("j1", 1, "on-failure")
	_ = w.Containers(context.Background())
	d.list = nil
	if evs := collect(w, 3, func(int) { c.t = c.t.Add(time.Minute) }); len(evs) != 0 {
		t.Fatalf("удалён до срока: %v", evs)
	}
	// Упал и лежит дольше срока — firing; затем удалён — resolved с тем же subject.
	d.list = []map[string]any{listedC("j2", "job", "exited", 200, nil)}
	d.cont["j2"] = inspectedC("j2", 1, "on-failure")
	evs := collect(w, 3, func(int) { c.t = c.t.Add(time.Minute) })
	if len(evs) != 1 || evs[0].GetAttributes()["state"] != "firing" || evs[0].GetAttributes()["subject"] != "job" {
		t.Fatalf("упал: %v", evs)
	}
	d.list = nil
	evs = collect(w, 1, nil)
	if len(evs) != 1 || evs[0].GetAttributes()["state"] != "resolved" || evs[0].GetAttributes()["subject"] != "job" {
		t.Fatalf("удалён: %v", evs)
	}
}

// 2) Служба compose: копия упала, но другая копия той же службы работает — не инцидент; сработавшее снимается,
// когда поднялась новая копия, с прежним subject (отпечаток инцидента).
func TestWatcherComposeService(t *testing.T) {
	e, c := newEnv(t)
	d, cl := startDocker(t, c)
	e.Docker = cl
	w := &Watcher{Env: e}
	d.list = []map[string]any{
		listedC("w1", "app-worker-1", "exited", 100, composeLabels("worker")),
		listedC("w2", "app-worker-2", "running", 110, composeLabels("worker")),
	}
	d.cont["w1"] = inspectedC("w1", 1, "on-failure")
	if evs := collect(w, 5, func(int) { c.t = c.t.Add(time.Minute) }); len(evs) != 0 {
		t.Fatalf("есть здоровая копия: %v", evs)
	}
	// Обе лежат — служба упала; сработало по самой новой копии.
	d.list[1]["State"] = "exited"
	d.cont["w2"] = inspectedC("w2", 2, "on-failure")
	evs := collect(w, 3, func(int) { c.t = c.t.Add(time.Minute) })
	if len(evs) != 1 || evs[0].GetAttributes()["subject"] != "app-worker-2" || evs[0].GetAttributes()["compose_service"] != "worker" {
		t.Fatalf("служба упала: %v", evs)
	}
	// Новая копия app-worker-3 поднялась — снятие с subject app-worker-2.
	d.list = append(d.list, listedC("w3", "app-worker-3", "running", 300, composeLabels("worker")))
	evs = collect(w, 1, nil)
	if len(evs) != 1 || evs[0].GetAttributes()["state"] != "resolved" || evs[0].GetAttributes()["subject"] != "app-worker-2" {
		t.Fatalf("новая копия: %v", evs)
	}
}

// 3) Пересоздание с тем же именем: новая копия запустилась — снятие; запуска не было — состояние прежнее.
func TestWatcherRecreatedSameName(t *testing.T) {
	e, c := newEnv(t)
	d, cl := startDocker(t, c)
	e.Docker = cl
	w := &Watcher{Env: e}
	d.list = []map[string]any{listedC("b1", "backup", "exited", 100, nil)}
	d.cont["b1"] = inspectedC("b1", 3, "on-failure")
	if evs := collect(w, 3, func(int) { c.t = c.t.Add(time.Minute) }); len(evs) != 1 {
		t.Fatalf("упал: %v", evs)
	}
	// Пересоздан (новый id, то же имя), ещё не запущен — ни снятия, ни повтора.
	d.list = []map[string]any{listedC("b2", "backup", "created", 200, nil)}
	if evs := collect(w, 1, nil); len(evs) != 0 {
		t.Fatalf("создан: %v", evs)
	}
	d.list[0]["State"] = "running"
	if evs := collect(w, 1, nil); len(evs) != 1 || evs[0].GetAttributes()["state"] != "resolved" || evs[0].GetAttributes()["subject"] != "backup" {
		t.Fatalf("запущен: %v", evs)
	}
}

// Сработавшее переживает перезапуск помощника: новый наблюдатель с тем же файлом снимает его, когда условия нет.
func TestWatcherStatePersists(t *testing.T) {
	e, c := newEnv(t)
	d, cl := startDocker(t, c)
	e.Docker = cl
	path := filepath.Join(t.TempDir(), "watch.json")
	w := &Watcher{Env: e, StatePath: path}
	d.list = []map[string]any{listedC("r1", "redis", "restarting", 100, composeLabels("redis"))}
	d.cont["r1"] = inspectedC("r1", 1, "always")
	if evs := collect(w, RestartingTicks, nil); len(evs) != 1 {
		t.Fatalf("цикл: %v", evs)
	}
	// Перезапуск помощника: контейнер уже работает — снятие уходит с прежним subject.
	d.list[0]["State"] = "running"
	w2 := &Watcher{Env: e, StatePath: path}
	if evs := collect(w2, 1, nil); len(evs) != 1 || evs[0].GetAttributes()["state"] != "resolved" || evs[0].GetAttributes()["subject"] != "redis" {
		t.Fatalf("после перезапуска: %v", evs)
	}
	// Снято — в файле ничего: третий наблюдатель ничего не шлёт.
	w3 := &Watcher{Env: e, StatePath: path}
	if evs := collect(w3, 1, nil); len(evs) != 0 {
		t.Fatalf("повтор снятия: %v", evs)
	}
	// Перезапуск, а служба удалена целиком — тоже снятие.
	d.list[0]["State"] = "restarting"
	_ = collect(w3, RestartingTicks, nil)
	d.list = nil
	w4 := &Watcher{Env: e, StatePath: path}
	if evs := collect(w4, 1, nil); len(evs) != 1 || evs[0].GetAttributes()["state"] != "resolved" {
		t.Fatalf("удалена после перезапуска: %v", evs)
	}
}
