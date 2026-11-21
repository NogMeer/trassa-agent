// SPDX-License-Identifier: AGPL-3.0-only

package deploy

import (
	"context"
	"math"
	"net/http"
	"net/url"
	"sort"
	"sync"
	"time"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
)

// MaxStatApps — сколько приложений попадает в пачку метрик (лимит меток E08).
const MaxStatApps = 100

// AppStats — память и CPU приложений Trassa (E17-T24-R1): app_mem_used_bytes и app_cpu_usage_percent с меткой
// app_id. Помощник читает статистику Docker по работающим контейнерам с меткой trassa.app_id и складывает по
// приложению. CPU — доля всего сервера (0–100, как cpu_usage_percent), по разности счётчиков с прошлого вызова:
// первая пачка после старта или нового контейнера CPU приложения не содержит.
type AppStats struct {
	Env *Env
	// Now — часы (тесты); nil — time.Now.
	Now func() time.Time

	mu   sync.Mutex
	prev map[string]cpuSample
	// Итог кэшируется на MinInterval: частые вызовы агента не нагружают Docker и не сбивают базу CPU.
	at   time.Time
	last []*agentv1.Metric
}

// MinInterval — не чаще одного сбора.
const MinInterval = 30 * time.Second

type cpuSample struct{ total, system uint64 }

type dockerStats struct {
	CPU struct {
		Usage struct {
			Total uint64 `json:"total_usage"`
		} `json:"cpu_usage"`
		System uint64 `json:"system_cpu_usage"`
	} `json:"cpu_stats"`
	Memory struct {
		Usage uint64            `json:"usage"`
		Stats map[string]uint64 `json:"stats"`
	} `json:"memory_stats"`
}

// memUsed — как docker stats: usage без неактивного файлового кэша (cgroup v2 inactive_file, v1 total_inactive_file).
func (s dockerStats) memUsed() uint64 {
	inactive, ok := s.Memory.Stats["inactive_file"]
	if !ok {
		inactive = s.Memory.Stats["total_inactive_file"]
	}
	if inactive > s.Memory.Usage {
		return s.Memory.Usage
	}
	return s.Memory.Usage - inactive
}

// Collect — метрики приложений; без Docker — ошибка, без приложений — пусто.
func (a *AppStats) Collect(ctx context.Context) ([]*agentv1.Metric, error) {
	now := time.Now
	if a.Now != nil {
		now = a.Now
	}
	a.mu.Lock()
	if !a.at.IsZero() && now().Sub(a.at) < MinInterval {
		out := a.last
		a.mu.Unlock()
		return out, nil
	}
	a.mu.Unlock()
	cs, err := a.Env.appContainers(ctx, "")
	if err != nil {
		return nil, err
	}
	type acc struct {
		mem      uint64
		cpu      float64
		cpuKnown bool
	}
	apps := map[string]*acc{}
	next := map[string]cpuSample{}
	a.mu.Lock()
	prev := a.prev
	a.mu.Unlock()
	for _, c := range cs {
		app := c.Labels[LabelApp]
		if c.State != "running" || checkApp(app) != nil {
			continue
		}
		var st dockerStats
		// one-shot: без ожидания второго замера (API 1.41+); разность считаем сами.
		q := url.Values{"stream": {"false"}, "one-shot": {"true"}}
		if err := a.Env.dockerJSON(ctx, http.MethodGet, "/containers/"+url.PathEscape(c.ID)+"/stats?"+q.Encode(), nil, &st); err != nil {
			continue
		}
		x := apps[app]
		if x == nil {
			if len(apps) >= MaxStatApps {
				continue
			}
			x = &acc{cpuKnown: true}
			apps[app] = x
		}
		x.mem += st.memUsed()
		cur := cpuSample{total: st.CPU.Usage.Total, system: st.CPU.System}
		next[c.ID] = cur
		p, ok := prev[c.ID]
		if !ok || cur.system <= p.system || cur.total < p.total {
			x.cpuKnown = false
			continue
		}
		x.cpu += 100 * float64(cur.total-p.total) / float64(cur.system-p.system)
	}
	var out []*agentv1.Metric
	ids := make([]string, 0, len(apps))
	for id := range apps {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		x := apps[id]
		l := map[string]string{"app_id": id}
		out = append(out, &agentv1.Metric{Name: "app_mem_used_bytes", Value: float64(x.mem), Labels: l})
		if x.cpuKnown {
			out = append(out, &agentv1.Metric{Name: "app_cpu_usage_percent", Value: math.Min(math.Max(x.cpu, 0), 100),
				Labels: map[string]string{"app_id": id}})
		}
	}
	a.mu.Lock()
	a.prev, a.at, a.last = next, now(), out
	a.mu.Unlock()
	return out, nil
}
