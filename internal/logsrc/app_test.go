// SPDX-License-Identifier: AGPL-3.0-only

package logsrc

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/deploy"
	"github.com/NogMeer/trassa-agent/internal/ops"
)

const testApp = "01a1f4b6-f327-7a5d-ac23-e95c272c0fe8"

// fakeAppDocker — контейнеры приложения (с меткой) и чужой контейнер; журналы по id с учётом since.
type fakeAppDocker struct {
	containers []appContainer
	logs       map[string][]string // id → «время сообщение»
	filters    []string
}

func (f *fakeAppDocker) Get(_ context.Context, path string) (*http.Response, error) {
	resp := func(code int, body []byte) (*http.Response, error) {
		return &http.Response{StatusCode: code, Body: io.NopCloser(bytes.NewReader(body))}, nil
	}
	u, _ := url.Parse(path)
	switch {
	case u.Path == "/containers/json":
		f.filters = append(f.filters, u.Query().Get("filters"))
		b, _ := json.Marshal(f.containers)
		return resp(200, b)
	case strings.HasSuffix(u.Path, "/json"):
		return resp(200, []byte(`{"Id":"`+strings.Split(u.Path, "/")[2]+`","Config":{"Tty":true}}`))
	case strings.HasSuffix(u.Path, "/logs"):
		id := strings.Split(u.Path, "/")[2]
		var since time.Time
		if s := u.Query().Get("since"); s != "" {
			sec, _, _ := strings.Cut(s, ".")
			var a int64
			for _, c := range sec {
				a = a*10 + int64(c-'0')
			}
			since = time.Unix(a, 0)
		}
		var out bytes.Buffer
		for _, l := range f.logs[id] {
			ts, _, _ := strings.Cut(l, " ")
			t, _ := time.Parse(time.RFC3339Nano, ts)
			if !t.Before(since) {
				out.WriteString(l + "\n")
			}
		}
		return resp(200, out.Bytes())
	}
	return resp(404, nil)
}

func appLabels(release, service string) map[string]string {
	return map[string]string{labelApp: testApp, labelRelease: release, labelService: service}
}

func TestAppLabelsMatchDeploy(t *testing.T) {
	if labelApp != deploy.LabelApp || labelRelease != deploy.LabelRelease || labelService != deploy.LabelService {
		t.Fatal("метки logsrc и deploy разошлись")
	}
}

func TestValidAppSource(t *testing.T) {
	if err := ops.ValidLogSource(&agentv1.LogSource{Kind: agentv1.LogSourceKind_LOG_SOURCE_KIND_APP, Name: testApp}); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"", "web", strings.ToUpper(testApp), testApp + `","x`, "trassa.app_id=x"} {
		if ops.ValidLogSource(&agentv1.LogSource{Kind: agentv1.LogSourceKind_LOG_SOURCE_KIND_APP, Name: n}) == nil {
			t.Errorf("%q принят", n)
		}
	}
}

func TestAppReadAndPoll(t *testing.T) {
	d := &fakeAppDocker{
		containers: []appContainer{
			{ID: "old", Names: []string{"/app-old"}, State: "exited", Created: 100, Labels: appLabels("r1", "web")},
			{ID: "new", Names: []string{"/app-new"}, State: "running", Created: 200, Labels: appLabels("r2", "web")},
			{ID: "wrk", Names: []string{"/app-worker"}, State: "running", Created: 201, Labels: appLabels("r2", "worker")},
			// Ответ Docker с чужим контейнером: агент сверяет метку сам.
			{ID: "foreign", Names: []string{"/db"}, State: "running", Created: 300, Labels: map[string]string{"x": "y"}},
		},
		logs: map[string][]string{
			"old":     {"2026-11-22T10:00:00Z old release line"},
			"new":     {"2026-11-22T10:00:02Z started password=hunter2hunter2", "2026-11-22T10:00:04Z GET / 200"},
			"wrk":     {"2026-11-22T10:00:03Z job done"},
			"foreign": {"2026-11-22T10:00:05Z db secret line"},
		},
	}
	r := &Reader{Docker: d, Now: time.Now}
	src := &agentv1.LogSource{Kind: agentv1.LogSourceKind_LOG_SOURCE_KIND_APP, Name: testApp}
	res, err := r.Read(context.Background(), src, 3, "")
	if err != nil {
		t.Fatal(err)
	}
	var msgs []string
	for _, x := range res.GetRecords() {
		msgs = append(msgs, x.GetMessage())
		if x.GetSource().GetKind() != agentv1.LogSourceKind_LOG_SOURCE_KIND_APP || x.GetFields()["service"] == "" || x.GetFields()["release"] == "" {
			t.Fatalf("поля: %+v", x)
		}
	}
	got := strings.Join(msgs, "|")
	if got != "started password=[REDACTED]|job done|GET / 200" || strings.Contains(got, "db secret") {
		t.Fatalf("read: %q", got)
	}
	if !strings.Contains(d.filters[0], `trassa.app_id=`+testApp) {
		t.Fatalf("фильтр: %q", d.filters[0])
	}
	// Опрос: с момента подписки, остановленный и невиданный контейнер не читается; позиции по контейнерам.
	sub := time.Date(2026, 11, 22, 10, 0, 1, 0, time.UTC).UnixMilli()
	recs, pos, more, err := r.pollApp(context.Background(), src, "", sub, agentv1.LogLevel_LOG_LEVEL_DEBUG, 100, 1<<20)
	if err != nil || more || len(recs) != 3 || strings.Contains(pos, "old@") || !strings.Contains(pos, "new@") || !strings.Contains(pos, "wrk@") {
		t.Fatalf("poll: %v %q %v %d", err, pos, more, len(recs))
	}
	// Новая строка у одного контейнера — только она; позиция другого не сдвигается.
	d.logs["wrk"] = append(d.logs["wrk"], "2026-11-22T10:00:06Z job 2")
	recs, pos2, _, err := r.pollApp(context.Background(), src, pos, sub, agentv1.LogLevel_LOG_LEVEL_DEBUG, 100, 1<<20)
	if err != nil || len(recs) != 1 || recs[0].GetMessage() != "job 2" {
		t.Fatalf("poll 2: %v %+v", err, recs)
	}
	// Контейнер остановился: читается ещё раз и выпадает из позиции.
	d.containers[2].State = "exited"
	d.logs["wrk"] = append(d.logs["wrk"], "2026-11-22T10:00:07Z bye")
	recs, pos3, _, err := r.pollApp(context.Background(), src, pos2, sub, agentv1.LogLevel_LOG_LEVEL_DEBUG, 100, 1<<20)
	if err != nil || len(recs) != 1 || recs[0].GetMessage() != "bye" || strings.Contains(pos3, "wrk@") {
		t.Fatalf("poll 3: %v %+v %q", err, recs, pos3)
	}
	// Предел записей: остаток — в следующий раз (more).
	d.containers[2].State = "running"
	d.logs["new"] = append(d.logs["new"], "2026-11-22T10:00:08Z a", "2026-11-22T10:00:09Z b")
	recs, _, more, err = r.pollApp(context.Background(), src, pos3, sub, agentv1.LogLevel_LOG_LEVEL_DEBUG, 1, 1<<20)
	if err != nil || len(recs) != 1 || !more {
		t.Fatalf("предел: %v %d %v", err, len(recs), more)
	}
	// Подписка: источник открыт и без контейнеров; без Docker — SOURCE_UNSUPPORTED.
	st, ok, _ := r.Open([]*agentv1.LogSource{src})
	if len(ok) != 1 || !st[0].GetOpened() {
		t.Fatalf("open: %+v", st)
	}
	st, _, _ = (&Reader{}).Open([]*agentv1.LogSource{src})
	if st[0].GetOpened() || st[0].GetReason() != ReasonUnsupported {
		t.Fatalf("без docker: %+v", st)
	}
}
