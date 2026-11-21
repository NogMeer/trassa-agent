// SPDX-License-Identifier: AGPL-3.0-only

package logsrc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/dockerapi"
	"github.com/NogMeer/trassa-agent/internal/redact"
)

// Метки контейнеров приложения Trassa (deploy.LabelApp и соседние; тест сверяет).
const (
	labelApp     = "trassa.app_id"
	labelRelease = "trassa.release_id"
	labelService = "trassa.service"
	// MaxAppContainers — сколько последних контейнеров приложения читается (релизы, службы compose).
	MaxAppContainers = 20
)

type appContainer struct {
	ID      string            `json:"Id"`
	Names   []string          `json:"Names"`
	State   string            `json:"State"`
	Created int64             `json:"Created"`
	Labels  map[string]string `json:"Labels"`
}

func (c appContainer) name() string {
	if len(c.Names) > 0 {
		return strings.TrimPrefix(c.Names[0], "/")
	}
	return c.ID
}

// appContainers — контейнеры с меткой trassa.app_id=<app> (и остановленные: журнал упавшего релиза нужен),
// не больше MaxAppContainers самых новых, от старых к новым. Отбор по метке делает Docker: контейнеры вне
// приложений Trassa сюда не попадают.
func (r *Reader) appContainers(ctx context.Context, app string) ([]appContainer, error) {
	if r.Docker == nil {
		return nil, errUnsupported
	}
	f, _ := json.Marshal(map[string][]string{"label": {labelApp + "=" + app}})
	resp, err := r.Docker.Get(ctx, "/containers/json?all=1&filters="+url.QueryEscape(string(f)))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("docker api: HTTP %d", resp.StatusCode)
	}
	var cs []appContainer
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&cs); err != nil {
		return nil, fmt.Errorf("docker api: список контейнеров: %w", err)
	}
	// Метку сверяем и сами: ответ Docker — данные, а не гарантия.
	out := cs[:0]
	for _, c := range cs {
		if c.ID != "" && c.Labels[labelApp] == app {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Created != out[j].Created {
			return out[i].Created < out[j].Created
		}
		return out[i].ID < out[j].ID
	})
	if len(out) > MaxAppContainers {
		out = out[len(out)-MaxAppContainers:]
	}
	return out, nil
}

func (r *Reader) appRecord(src *agentv1.LogSource, c appContainer, l dockerLine) *agentv1.LogRecord {
	f := map[string]string{"container": field(c.name()), "stream": l.stream}
	if v := c.Labels[labelService]; v != "" {
		f["service"] = field(v)
	}
	if v := c.Labels[labelRelease]; v != "" {
		f["release"] = field(v)
	}
	return &agentv1.LogRecord{TimeMs: l.ts.UnixMilli(), Level: fileLevel(l.text), Source: src, Message: clean(l.text),
		Fields: f, Cursor: dockerPos(c.ID, l.ts)}
}

// readApp — logs.read по приложению: последние строки всех его контейнеров вместе, по времени.
func (r *Reader) readApp(ctx context.Context, src *agentv1.LogSource, lines int, grep string) ([]*agentv1.LogRecord, error) {
	dctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cs, err := r.appContainers(dctx, src.GetName())
	if err != nil {
		return nil, err
	}
	var all []*agentv1.LogRecord
	var errs []error
	for _, c := range cs {
		_, tty, _, err := r.inspect(dctx, c.ID)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		recs, err := r.readContainer(dctx, c.ID, tty, lines, grep, func(l dockerLine) *agentv1.LogRecord { return r.appRecord(src, c, l) })
		if err != nil {
			errs = append(errs, err)
			continue
		}
		all = append(all, recs...)
	}
	if len(all) == 0 && len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	sort.SliceStable(all, func(i, j int) bool { return all[i].GetTimeMs() < all[j].GetTimeMs() })
	if len(all) > lines {
		all = all[len(all)-lines:]
	}
	return all, nil
}

// appPos — позиции контейнеров приложения: «id@время» через «,».
func appPos(pos string) map[string]string {
	m := map[string]string{}
	for _, p := range strings.Split(pos, ",") {
		if id, _, ok := strings.Cut(p, "@"); ok && id != "" {
			m[id] = p
		}
	}
	return m
}

// pollApp — новые строки всех контейнеров приложения. Контейнер нового релиза читается с момента подписки;
// остановленный — ещё один раз после того, как был виден работающим (последние строки), затем выпадает из
// позиции. Позиция каждого контейнера своя, поэтому строки соседних контейнеров с тем же временем не теряются.
func (r *Reader) pollApp(ctx context.Context, src *agentv1.LogSource, pos string, sinceMs int64, min agentv1.LogLevel, maxRec, maxBytes int) ([]*agentv1.LogRecord, string, bool, error) {
	dctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cs, err := r.appContainers(dctx, src.GetName())
	if err != nil {
		return nil, pos, false, err
	}
	prev := appPos(pos)
	next := map[string]string{}
	var out []*agentv1.LogRecord
	size, more := 0, false
	for _, c := range cs {
		p, seen := prev[c.ID]
		if c.State != "running" && !seen {
			continue
		}
		if len(out) >= maxRec || size >= maxBytes {
			more = true
			if seen {
				next[c.ID] = p
			}
			continue
		}
		_, tty, _, err := r.inspect(dctx, c.ID)
		if errors.Is(err, dockerapi.ErrNoDocker) {
			return nil, pos, false, err
		}
		if err != nil {
			if seen {
				next[c.ID] = p
			}
			continue
		}
		recs, np, m, err := r.pollContainer(dctx, c.ID, tty, p, sinceMs, min, maxRec-len(out), maxBytes-size,
			func(l dockerLine) *agentv1.LogRecord { return r.appRecord(src, c, l) })
		if err != nil {
			if seen {
				next[c.ID] = p
			}
			continue
		}
		for _, x := range recs {
			size += recSize(x)
		}
		out = append(out, recs...)
		more = more || m
		// Остановленный и дочитанный контейнер больше не опрашивается.
		if c.State == "running" || m {
			next[c.ID] = np
		}
	}
	ids := make([]string, 0, len(next))
	for id := range next {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	parts := make([]string, 0, len(ids))
	for _, id := range ids {
		parts = append(parts, next[id])
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].GetTimeMs() < out[j].GetTimeMs() })
	return out, strings.Join(parts, ","), more, nil
}

// field — значение из ответа Docker в поле записи: через фильтр секретов и в пределе.
func field(v string) string { return clip(redact.String(strings.ToValidUTF8(v, "\uFFFD")), maxField) }
