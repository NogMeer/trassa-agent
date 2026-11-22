// SPDX-License-Identifier: AGPL-3.0-only

package remedy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/fsutil"
	"github.com/NogMeer/trassa-agent/internal/sysinfo"
)

// Коды событий E18 (справочник E09: container.down, cert.expiring).
const (
	EventContainerDown = "container.down"
	EventCertExpiring  = "cert.expiring"
	// RestartingTicks — сколько опросов подряд в restarting считается падением (цикл перезапусков).
	RestartingTicks = 3
	// DownFor — сколько контейнер должен лежать до события.
	DownFor = 60 * time.Second
	// MaxWatched — предел отслеживаемых контейнеров.
	MaxWatched = 500
)

// CertThresholds — пороги cert.expiring, дней (план E18, CERT_EXPIRING: 30, 14, 7).
var CertThresholds = []int{30, 14, 7}

type downState struct {
	since      time.Time
	restarting int
	firing     bool
	// subject — имя контейнера в сработавшем событии: снятие уходит с тем же subject (отпечаток инцидента).
	subject string
}

// Watcher — наблюдение помощника (решения E18 пп. 6, 7). Сработавшие container.down хранятся в StatePath: после
// перезапуска помощника снятие всё равно уйдёт. Остальное состояние (сроки, счётчики) — в памяти.
type Watcher struct {
	Env *Env
	// StatePath — файл сработавших container.down (helper/watch.json); пусто — только в памяти.
	StatePath  string
	containers map[string]*downState
	certs      map[string]int // имя → сработавший порог
	apps       map[string]*appWatch
	loaded     bool
}

type listed struct {
	ID      string            `json:"Id"`
	Names   []string          `json:"Names"`
	State   string            `json:"State"`
	Created int64             `json:"Created"`
	Labels  map[string]string `json:"Labels"`
}

type inspected struct {
	State struct {
		ExitCode  int  `json:"ExitCode"`
		OOMKilled bool `json:"OOMKilled"`
	} `json:"State"`
	HostConfig struct {
		RestartPolicy struct {
			Name string `json:"Name"`
		} `json:"RestartPolicy"`
	} `json:"HostConfig"`
}

func event(kind string, sev agentv1.EventSeverity, now time.Time, msg string, attrs map[string]string) *agentv1.Event {
	return &agentv1.Event{Kind: kind, Severity: sev, AtMs: now.UnixMilli(), Message: msg, Attributes: attrs}
}

// Метки compose: служба опознаётся по проекту и имени службы, а не по имени контейнера с номером копии.
const (
	labelComposeProject = "com.docker.compose.project"
	labelComposeService = "com.docker.compose.service"
)

// containerKey — служба контейнера: compose — «проект/служба» (замена копии trassa-api-10 → trassa-api-11 — та
// же служба), иначе имя контейнера (пересоздание с тем же именем — тот же контейнер).
func containerKey(c listed, name string) string {
	if p, s := c.Labels[labelComposeProject], c.Labels[labelComposeService]; p != "" && s != "" {
		return "compose:" + p + "/" + s
	}
	return "name:" + name
}

// crashedAfterStop — контейнер остался в exited после падения, а не после остановки. С политикой always и
// unless-stopped упавший контейнер Docker запускает сам (цикл виден как restarting), поэтому такой контейнер в
// exited остановили (docker stop, compose при замене копии) — это не «упал». Падение в exited бывает только у
// on-failure (попытки кончились) с ненулевым кодом или OOM. Без политики остановка — норма.
func crashedAfterStop(i *inspected) bool {
	if i.HostConfig.RestartPolicy.Name != "on-failure" {
		return false
	}
	return i.State.OOMKilled || i.State.ExitCode != 0
}

type member struct {
	c    listed
	name string
}

// Containers — события container.down и снятие (resolved) по службам контейнеров. Служба на связи, если хоть одна
// её копия running: замена копии и пересоздание с тем же именем — не падение. Удалённый контейнер просто выпадает
// из службы — это не «остановился»; служба без единого контейнера снимает сработавшее событие.
func (w *Watcher) Containers(ctx context.Context) []*agentv1.Event {
	if w.containers == nil {
		w.containers = map[string]*downState{}
	}
	w.load()
	var cs []listed
	if _, err := w.Env.docker(ctx, http.MethodGet, "/containers/json?all=1", &cs); err != nil {
		return nil // нет Docker или ответа — состояние не меняется
	}
	now := w.Env.now()
	groups := map[string][]member{}
	sort.Slice(cs, func(i, j int) bool { return cs[i].ID < cs[j].ID })
	for i, c := range cs {
		if i >= MaxWatched {
			break
		}
		if len(c.Names) == 0 {
			continue
		}
		name := strings.TrimPrefix(c.Names[0], "/")
		if c.Labels[labelRole] != "" || strings.HasPrefix(name, builderPrefix) {
			continue
		}
		k := containerKey(c, name)
		groups[k] = append(groups[k], member{c: c, name: name})
	}
	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []*agentv1.Event
	changed := false
	for _, k := range keys {
		ms := groups[k]
		st := w.containers[k]
		running := false
		for _, m := range ms {
			running = running || m.c.State == "running"
		}
		if running {
			if st != nil && st.firing {
				out = append(out, w.resolved(now, st.subject, ms[0].c, "служба снова работает"))
				changed = true
			}
			delete(w.containers, k)
			continue
		}
		// Ни одной работающей копии: решает самая новая (её состояние и политика).
		sort.Slice(ms, func(i, j int) bool { return ms[i].c.Created > ms[j].c.Created })
		cur := ms[0]
		if cur.c.State != "exited" && cur.c.State != "dead" && cur.c.State != "restarting" {
			continue // created, paused, removing — ни падения, ни снятия
		}
		var info inspected
		if _, err := w.Env.docker(ctx, http.MethodGet, "/containers/"+url.PathEscape(cur.c.ID)+"/json", &info); err != nil {
			continue
		}
		if info.HostConfig.RestartPolicy.Name == "" || info.HostConfig.RestartPolicy.Name == "no" {
			continue // без политики перезапуска остановка — норма
		}
		// Только контейнер, который должен работать (E06, тот же признак, что в инвентаре и панели).
		if !sysinfo.ContainerExpected(info.HostConfig.RestartPolicy.Name, cur.c.State, int32(info.State.ExitCode), cur.c.Labels[labelComposeService]) {
			continue
		}
		if st == nil {
			st = &downState{since: now}
			w.containers[k] = st
		}
		down := false
		if cur.c.State == "restarting" || cur.c.State == "dead" {
			st.restarting++
			down = st.restarting >= RestartingTicks
		} else {
			st.restarting = 0
			down = crashedAfterStop(&info) && now.Sub(st.since) >= DownFor
		}
		if down && !st.firing {
			st.firing, st.subject = true, cur.name
			attrs := w.attrs(cur.name, cur.c)
			attrs["state"], attrs["exit_code"] = "firing", strconv.Itoa(info.State.ExitCode)
			attrs["oom"] = strconv.FormatBool(info.State.OOMKilled)
			out = append(out, event(EventContainerDown, agentv1.EventSeverity_EVENT_SEVERITY_CRIT, now, "контейнер не работает", attrs))
			changed = true
		}
	}
	for k, st := range w.containers {
		if _, ok := groups[k]; ok {
			continue
		}
		// Служба удалена целиком: сработавшее снимается, «остановился» не бывает.
		if st.firing {
			out = append(out, event(EventContainerDown, agentv1.EventSeverity_EVENT_SEVERITY_INFO, now, "контейнер удалён",
				map[string]string{"subject": st.subject, "state": "resolved"}))
			changed = true
		}
		delete(w.containers, k)
	}
	if changed {
		w.save()
	}
	return out
}

func (w *Watcher) attrs(subject string, c listed) map[string]string {
	a := map[string]string{"subject": subject}
	if v := c.Labels[labelApp]; v != "" {
		a["app_id"] = v
	}
	if p, s := c.Labels[labelComposeProject], c.Labels[labelComposeService]; p != "" && s != "" {
		a["compose_project"], a["compose_service"] = p, s
	}
	return a
}

func (w *Watcher) resolved(now time.Time, subject string, c listed, msg string) *agentv1.Event {
	a := w.attrs(subject, c)
	a["state"] = "resolved"
	return event(EventContainerDown, agentv1.EventSeverity_EVENT_SEVERITY_INFO, now, msg, a)
}

// fired — запись файла состояния: служба → subject сработавшего события.
type fired map[string]string

func (w *Watcher) load() {
	if w.loaded || w.StatePath == "" {
		w.loaded = true
		return
	}
	w.loaded = true
	raw, err := os.ReadFile(w.StatePath)
	if err != nil {
		return
	}
	var f fired
	if json.Unmarshal(raw, &f) != nil {
		return
	}
	now := w.Env.now()
	for k, subj := range f {
		if _, ok := w.containers[k]; !ok && subj != "" {
			w.containers[k] = &downState{since: now, firing: true, subject: subj}
		}
	}
}

func (w *Watcher) save() {
	if w.StatePath == "" {
		return
	}
	f := fired{}
	for k, st := range w.containers {
		if st.firing {
			f[k] = st.subject
		}
	}
	raw, _ := json.Marshal(f)
	_ = fsutil.WriteFileAtomic(w.StatePath, raw, 0o600, fsutil.Keep)
}

// threshold — наименьший порог, до которого дошёл срок (0 — дальше всех порогов).
func threshold(days int) int {
	t := 0
	for _, p := range CertThresholds {
		if days <= p {
			t = p
		}
	}
	return t
}

// Certs — события cert.expiring: при переходе через порог и снятие после продления.
func (w *Watcher) Certs() []*agentv1.Event {
	if w.certs == nil {
		w.certs = map[string]int{}
	}
	now := w.Env.now()
	var out []*agentv1.Event
	have := w.Env.Certs()
	names := make([]string, 0, len(have))
	for n := range have {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		na := have[name]
		days := int(na.Sub(now).Hours() / 24)
		t := threshold(days)
		attrs := map[string]string{"subject": name, "value": strconv.Itoa(days), "not_after_ms": strconv.FormatInt(na.UnixMilli(), 10)}
		prev := w.certs[name]
		switch {
		case t == 0 && prev != 0:
			attrs["state"], attrs["threshold"] = "resolved", strconv.Itoa(prev)
			out = append(out, event(EventCertExpiring, agentv1.EventSeverity_EVENT_SEVERITY_INFO, now, "сертификат продлён", attrs))
			delete(w.certs, name)
		case t != 0 && (prev == 0 || t < prev):
			sev := agentv1.EventSeverity_EVENT_SEVERITY_WARN
			if t <= 7 {
				sev = agentv1.EventSeverity_EVENT_SEVERITY_CRIT
			}
			attrs["state"], attrs["threshold"] = "firing", strconv.Itoa(t)
			out = append(out, event(EventCertExpiring, sev, now, "срок сертификата подходит к концу", attrs))
			w.certs[name] = t
		}
	}
	for name, prev := range w.certs {
		if _, ok := have[name]; !ok {
			out = append(out, event(EventCertExpiring, agentv1.EventSeverity_EVENT_SEVERITY_INFO, now, "сертификата больше нет",
				map[string]string{"subject": name, "state": "resolved", "threshold": strconv.Itoa(prev)}))
			delete(w.certs, name)
		}
	}
	return out
}

// Run — опрос: контейнеры раз в every, сертификаты раз в certEvery; события — в push.
func (w *Watcher) Run(ctx context.Context, every, certEvery time.Duration, push func(*agentv1.Event)) {
	t := time.NewTicker(every)
	defer t.Stop()
	var lastCerts time.Time
	for {
		for _, ev := range w.Containers(ctx) {
			push(ev)
		}
		for _, ev := range w.Apps(ctx) {
			push(ev)
		}
		if time.Since(lastCerts) >= certEvery {
			lastCerts = time.Now()
			for _, ev := range w.Certs() {
				push(ev)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
