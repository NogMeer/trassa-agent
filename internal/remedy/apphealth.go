// SPDX-License-Identifier: AGPL-3.0-only

package remedy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"sort"
	"strings"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/config"
)

// Здоровье приложений Trassa (E17-T26-R1): событие app.unhealthy (атрибуты app_id, state firing|resolved, reason).
// Состояние приложения — те же правила, что runtimeState панели (apps/api/src/modules/deploy/app-health.ts),
// общий набор — proto/testdata/app-health.json.
const (
	EventAppUnhealthy = "app.unhealthy"
	// UnhealthyTicks — сколько опросов подряд приложение должно быть нездоровым до firing (дребезг: проверка
	// здоровья Docker после перезапуска, короткий цикл restarting).
	UnhealthyTicks = 3
	// HealthyTicks — сколько опросов подряд здоровым до resolved.
	HealthyTicks = 2
	// MaxApps — предел отслеживаемых приложений.
	MaxApps = 200
)

// Состояния и причины (как RuntimeState и AppHealthReason панели).
const (
	AppHealthy    = "HEALTHY"
	AppStopped    = "STOPPED"
	AppUnhealthy  = "UNHEALTHY"
	ReasonCheck   = "HEALTHCHECK"
	ReasonRestart = "RESTARTING"
	ReasonMissing = "MISSING"
)

// AppContainer — что о контейнере приложения нужно для решения: State из Docker (running, restarting, exited…) и
// State.Health.Status (healthy, unhealthy, starting или пусто без проверки).
type AppContainer struct {
	State  string `json:"state"`
	Health string `json:"health"`
}

// AppState — состояние приложения по его контейнерам. Контейнеров нет — нездорово (MISSING). Есть restarting или
// dead — нездорово (RESTARTING): у контейнера в цикле перезапусков тоже нет running. Все не running — STOPPED
// (остановили руками; события нет). Есть unhealthy — HEALTHCHECK. Завершившийся одноразовый сервис compose
// (миграции) рядом с работающими здоровья не портит.
func AppState(cs []AppContainer) (state, reason string) {
	if len(cs) == 0 {
		return AppUnhealthy, ReasonMissing
	}
	allDown := true
	unhealthy := false
	for _, c := range cs {
		if c.State == "restarting" || c.State == "dead" {
			return AppUnhealthy, ReasonRestart
		}
		if c.State == "running" {
			allDown = false
		}
		if c.Health == "unhealthy" {
			unhealthy = true
		}
	}
	if allDown {
		return AppStopped, ""
	}
	if unhealthy {
		return AppUnhealthy, ReasonCheck
	}
	return AppHealthy, ""
}

type appWatch struct {
	firing    bool
	bad, good int
	reason    string
}

// step — дребезг для одного приложения: наблюдение state/reason → событие (или nil). firing — после
// UnhealthyTicks нездоровых подряд, resolved — после HealthyTicks здоровых подряд у сработавшего. STOPPED
// счётчики сбрасывает и событий не даёт: остановку ведёт панель (deploy.control), сработавшее снимается там же.
func (w *appWatch) step(state, reason string) (ev string, evReason string) {
	switch state {
	case AppUnhealthy:
		w.good = 0
		w.bad++
		w.reason = reason
		if !w.firing && w.bad >= UnhealthyTicks {
			w.firing = true
			return "firing", reason
		}
	case AppHealthy:
		w.bad = 0
		w.good++
		if w.firing && w.good >= HealthyTicks {
			w.firing = false
			return "resolved", w.reason
		}
	default:
		w.bad, w.good = 0, 0
	}
	return "", ""
}

type appListed struct {
	ID     string            `json:"Id"`
	State  string            `json:"State"`
	Labels map[string]string `json:"Labels"`
}

type appInspected struct {
	State struct {
		Health *struct {
			Status string `json:"Status"`
		} `json:"Health"`
	} `json:"State"`
}

// Apps — события app.unhealthy по контейнерам с меткой trassa.app_id. Приложение, которого Docker больше не
// показывает, но которое агент видел, — MISSING (контейнеры удалены не через Trassa); снятое приложение панель
// не применяет (решения E17, часть 12, п. 2).
func (w *Watcher) Apps(ctx context.Context) []*agentv1.Event {
	if w.apps == nil {
		w.apps = map[string]*appWatch{}
	}
	f, _ := json.Marshal(map[string][]string{"label": {labelApp}})
	var cs []appListed
	if _, err := w.Env.docker(ctx, http.MethodGet, "/containers/json?all=1&filters="+url.QueryEscape(string(f)), &cs); err != nil {
		return nil // нет Docker или ответа — наблюдение пропускается, счётчики не меняются
	}
	byApp := map[string][]AppContainer{}
	for _, c := range cs {
		app := c.Labels[labelApp]
		if !config.IsUUID(app) {
			continue
		}
		app = strings.ToLower(app)
		ac := AppContainer{State: c.State}
		if c.State == "running" {
			var info appInspected
			if _, err := w.Env.docker(ctx, http.MethodGet, "/containers/"+url.PathEscape(c.ID)+"/json", &info); err != nil {
				return nil // неполная картина хуже пропуска: здоровье по половине контейнеров не решается
			}
			if info.State.Health != nil {
				ac.Health = info.State.Health.Status
			}
		}
		byApp[app] = append(byApp[app], ac)
	}
	ids := make([]string, 0, len(byApp)+len(w.apps))
	for id := range byApp {
		ids = append(ids, id)
	}
	for id := range w.apps {
		if _, ok := byApp[id]; !ok {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	now := w.Env.now()
	var out []*agentv1.Event
	for _, id := range ids {
		st := w.apps[id]
		if st == nil {
			if len(w.apps) >= MaxApps {
				continue
			}
			st = &appWatch{}
			w.apps[id] = st
		}
		state, reason := AppState(byApp[id])
		ev, why := st.step(state, reason)
		switch ev {
		case "firing":
			out = append(out, event(EventAppUnhealthy, agentv1.EventSeverity_EVENT_SEVERITY_CRIT, now, "приложение нездорово",
				map[string]string{"app_id": id, "state": "firing", "reason": why}))
		case "resolved":
			out = append(out, event(EventAppUnhealthy, agentv1.EventSeverity_EVENT_SEVERITY_INFO, now, "приложение снова здорово",
				map[string]string{"app_id": id, "state": "resolved", "reason": why}))
		}
		// Пропавшее приложение после события больше не отслеживается (удалённое через Trassa даст одно событие
		// MISSING, панель его не применит).
		if _, ok := byApp[id]; !ok && st.firing {
			delete(w.apps, id)
		}
	}
	return out
}
