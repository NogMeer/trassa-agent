// SPDX-License-Identifier: AGPL-3.0-only

package remedy

import (
	"context"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
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
}

// Watcher — наблюдение помощника (решения E18 пп. 6, 7). Состояние в памяти: после перезапуска действующее
// условие сработает снова (E09 склеивает по fingerprint).
type Watcher struct {
	Env        *Env
	containers map[string]*downState
	certs      map[string]int // имя → сработавший порог
	apps       map[string]*appWatch
}

type listed struct {
	ID     string            `json:"Id"`
	Names  []string          `json:"Names"`
	State  string            `json:"State"`
	Labels map[string]string `json:"Labels"`
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

// crashed — остановка не похожа на ручную: docker stop даёт 0 (обработал SIGTERM) или 143 (SIGTERM). Признак
// эвристический (Engine API не отдаёт «остановлен вручную»): падение с кодом 0 события не даст.
func crashed(i *inspected) bool {
	return i.State.OOMKilled || (i.State.ExitCode != 0 && i.State.ExitCode != 143)
}

// Containers — события container.down и снятие (resolved) по списку контейнеров.
func (w *Watcher) Containers(ctx context.Context) []*agentv1.Event {
	if w.containers == nil {
		w.containers = map[string]*downState{}
	}
	var cs []listed
	if _, err := w.Env.docker(ctx, http.MethodGet, "/containers/json?all=1", &cs); err != nil {
		return nil // нет Docker или ответа — состояние не меняется
	}
	now := w.Env.now()
	seen := map[string]bool{}
	var out []*agentv1.Event
	sort.Slice(cs, func(i, j int) bool { return cs[i].ID < cs[j].ID })
	for i, c := range cs {
		if i >= MaxWatched || len(c.Names) == 0 {
			break
		}
		name := strings.TrimPrefix(c.Names[0], "/")
		if c.Labels[labelRole] != "" || strings.HasPrefix(name, builderPrefix) {
			continue
		}
		seen[name] = true
		st := w.containers[name]
		attrs := map[string]string{"subject": name}
		if a := c.Labels[labelApp]; a != "" {
			attrs["app_id"] = a
		}
		if c.State == "running" {
			if st != nil && st.firing {
				attrs["state"] = "resolved"
				out = append(out, event(EventContainerDown, agentv1.EventSeverity_EVENT_SEVERITY_INFO, now, "контейнер снова работает", attrs))
			}
			delete(w.containers, name)
			continue
		}
		if c.State != "exited" && c.State != "dead" && c.State != "restarting" {
			continue
		}
		var info inspected
		if _, err := w.Env.docker(ctx, http.MethodGet, "/containers/"+url.PathEscape(c.ID)+"/json", &info); err != nil {
			continue
		}
		switch info.HostConfig.RestartPolicy.Name {
		case "always", "unless-stopped", "on-failure":
		default:
			continue // без политики перезапуска остановка — норма
		}
		if st == nil {
			st = &downState{since: now}
			w.containers[name] = st
		}
		down := false
		if c.State == "restarting" {
			st.restarting++
			down = st.restarting >= RestartingTicks
		} else {
			st.restarting = 0
			down = crashed(&info) && now.Sub(st.since) >= DownFor
		}
		if down && !st.firing {
			st.firing = true
			attrs["state"], attrs["exit_code"] = "firing", strconv.Itoa(info.State.ExitCode)
			attrs["oom"] = strconv.FormatBool(info.State.OOMKilled)
			out = append(out, event(EventContainerDown, agentv1.EventSeverity_EVENT_SEVERITY_CRIT, now, "контейнер не работает", attrs))
		}
	}
	for name, st := range w.containers {
		if !seen[name] {
			// Контейнер удалён: событие снимается, если было.
			if st.firing {
				out = append(out, event(EventContainerDown, agentv1.EventSeverity_EVENT_SEVERITY_INFO, now, "контейнер удалён",
					map[string]string{"subject": name, "state": "resolved"}))
			}
			delete(w.containers, name)
		}
	}
	return out
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
