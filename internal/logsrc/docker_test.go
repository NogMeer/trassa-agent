// SPDX-License-Identifier: AGPL-3.0-only

package logsrc

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/dockerapi"
)

func frame(stream byte, s string) []byte {
	b := make([]byte, 8, 8+len(s))
	b[0] = stream
	binary.BigEndian.PutUint32(b[4:], uint32(len(s)))
	return append(b, s...)
}

// fakeDocker — контейнер web (без TTY) и tty (с TTY); журнал отдаётся с учётом since и tail.
type fakeDocker struct {
	id    string
	lines []string // «время сообщение»
	paths []string
}

func (f *fakeDocker) Get(_ context.Context, path string) (*http.Response, error) {
	f.paths = append(f.paths, path)
	resp := func(code int, body []byte) (*http.Response, error) {
		return &http.Response{StatusCode: code, Body: io.NopCloser(bytes.NewReader(body))}, nil
	}
	switch {
	case path == "/containers/web/json":
		return resp(200, []byte(`{"Id":"`+f.id+`","Config":{"Tty":false}}`))
	case path == "/containers/tty/json":
		return resp(200, []byte(`{"Id":"t1","Config":{"Tty":true}}`))
	case strings.HasSuffix(path, "/json"):
		return resp(404, []byte(`{"message":"No such container"}`))
	}
	u, _ := url.Parse(path)
	q := u.Query()
	var since time.Time
	if s := q.Get("since"); s != "" {
		sec, nsec, _ := strings.Cut(s, ".")
		var a, b int64
		for _, c := range sec {
			a = a*10 + int64(c-'0')
		}
		for _, c := range nsec {
			b = b*10 + int64(c-'0')
		}
		since = time.Unix(a, b)
	}
	var out bytes.Buffer
	tty := strings.Contains(path, "/t1/")
	for i, l := range f.lines {
		ts, _, _ := strings.Cut(l, " ")
		t, _ := time.Parse(time.RFC3339Nano, ts)
		if t.Before(since) {
			continue
		}
		if tty {
			out.WriteString(l + "\n")
			continue
		}
		st := byte(dockerapi.StreamStdout)
		if i%2 == 1 {
			st = dockerapi.StreamStderr
		}
		out.Write(frame(st, l+"\n"))
	}
	return resp(200, out.Bytes())
}

func dockerSrc(name string) *agentv1.LogSource {
	return &agentv1.LogSource{Kind: agentv1.LogSourceKind_LOG_SOURCE_KIND_DOCKER, Name: name}
}

func TestDockerPoll(t *testing.T) {
	d := &fakeDocker{id: "c1", lines: []string{
		"2026-11-20T10:00:00.000000001Z before subscribe",
		"2026-11-20T10:00:05.000000000Z GET / 200",
		"2026-11-20T10:00:06.000000000Z ERROR boom secret=hunter2hunter2",
	}}
	r := &Reader{Docker: d, Now: time.Now}
	sub := &Subscription{CreatedAtMs: time.Date(2026, 11, 20, 10, 0, 1, 0, time.UTC).UnixMilli(), Sources: []*agentv1.LogSource{dockerSrc("web")}}
	k := Key(sub.Sources[0])

	recs, pos, _, errs := r.Poll(context.Background(), sub, nil)
	if len(errs) != 0 || len(recs) != 2 {
		t.Fatalf("с момента подписки: %v %v", recs, errs)
	}
	// Поддельный Docker чередует потоки по номеру строки: вторая строка журнала — stderr.
	if recs[0].GetFields()["stream"] != "stderr" || recs[1].GetFields()["stream"] != "stdout" ||
		recs[1].GetLevel() != agentv1.LogLevel_LOG_LEVEL_ERROR || strings.Contains(recs[1].GetMessage(), "hunter2hunter2") {
		t.Fatalf("записи: %+v", recs)
	}
	// Повторный опрос с позиции: строки с тем же временем не повторяются.
	again, pos2, _, _ := r.Poll(context.Background(), sub, pos)
	if len(again) != 0 || pos2[k] != pos[k] {
		t.Fatalf("повтор: %v", again)
	}
	d.lines = append(d.lines, "2026-11-20T10:00:07.5Z new line")
	recs, _, _, _ = r.Poll(context.Background(), sub, pos2)
	if len(recs) != 1 || recs[0].GetMessage() != "new line" {
		t.Fatalf("новая строка: %+v", recs)
	}
	// Контейнер пересоздан (другой id): позиция старого не годится, чтение с момента подписки.
	d.id = "c2"
	recs, pos3, _, _ := r.Poll(context.Background(), sub, pos2)
	if len(recs) != 3 || !strings.HasPrefix(pos3[k], "c2@") {
		t.Fatalf("пересоздан: %d %v", len(recs), pos3)
	}
}

func TestDockerOpenAndRead(t *testing.T) {
	d := &fakeDocker{id: "c1", lines: []string{"2026-11-20T10:00:00Z a1", "2026-11-20T10:00:01Z b", "2026-11-20T10:00:02Z a2"}}
	r := &Reader{Docker: d, Now: time.Now}
	st, ok, _ := r.Open([]*agentv1.LogSource{dockerSrc("web"), dockerSrc("missing")})
	if !st[0].GetOpened() || st[1].GetReason() != ReasonNotFound || len(ok) != 1 {
		t.Fatalf("%+v", st)
	}
	res, err := r.Read(context.Background(), dockerSrc("web"), 1, "a")
	if err != nil || len(res.GetRecords()) != 1 || res.GetRecords()[0].GetMessage() != "a2" {
		t.Fatalf("%v %+v", err, res)
	}
	res, err = r.Read(context.Background(), dockerSrc("tty"), 5, "")
	if err != nil || len(res.GetRecords()) != 3 || res.GetRecords()[0].GetFields()["stream"] != "tty" {
		t.Fatalf("TTY: %v %+v", err, res)
	}
	if !strings.Contains(d.paths[len(d.paths)-1], "tail=5") {
		t.Fatalf("tail: %v", d.paths)
	}
	if st, _, _ := (&Reader{Now: time.Now}).Open([]*agentv1.LogSource{dockerSrc("web")}); st[0].GetReason() != ReasonUnsupported {
		t.Fatalf("без Docker: %+v", st)
	}
}

func TestReadFrame(t *testing.T) {
	var b bytes.Buffer
	b.Write(frame(1, "x"))
	b.Write([]byte{3, 0, 0, 0, 0, 0, 0, 1, 'y'})
	if st, p, err := dockerapi.ReadFrame(&b); err != nil || st != 1 || string(p) != "x" {
		t.Fatal(st, p, err)
	}
	if _, _, err := dockerapi.ReadFrame(&b); err == nil {
		t.Fatal("тип потока 3 принят")
	}
	big := []byte{1, 0, 0, 0, 0xff, 0xff, 0xff, 0xff}
	if _, _, err := dockerapi.ReadFrame(bytes.NewReader(big)); err == nil {
		t.Fatal("кадр 4 ГиБ принят")
	}
	if _, _, err := dockerapi.ReadFrame(bytes.NewReader(frame(1, "abc")[:9])); err == nil {
		t.Fatal("оборванный кадр принят")
	}
	if _, _, err := dockerapi.ReadFrame(bytes.NewReader(nil)); err != io.EOF {
		t.Fatalf("конец потока: %v", err)
	}
}
