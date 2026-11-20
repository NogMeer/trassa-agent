// SPDX-License-Identifier: AGPL-3.0-only

package logsrc

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
)

func root(t *testing.T) string {
	t.Helper()
	r := t.TempDir()
	must(t, os.MkdirAll(filepath.Join(r, "var/log/app"), 0o755))
	must(t, os.MkdirAll(filepath.Join(r, "etc"), 0o755))
	must(t, os.WriteFile(filepath.Join(r, "etc/shadow"), []byte("root:secret\n"), 0o600))
	must(t, os.WriteFile(filepath.Join(r, "var/log/app/app.log"), []byte("old line\n"), 0o644))
	// Ссылки наружу: на файл и на каталог.
	must(t, os.Symlink(filepath.Join(r, "etc/shadow"), filepath.Join(r, "var/log/shadow.log")))
	must(t, os.Symlink(filepath.Join(r, "etc"), filepath.Join(r, "var/log/etc")))
	must(t, os.MkdirAll(filepath.Join(r, "var/log/dir.log"), 0o755))
	return r
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func file(name string) *agentv1.LogSource {
	return &agentv1.LogSource{Kind: agentv1.LogSourceKind_LOG_SOURCE_KIND_FILE, Name: name}
}

func TestOpenFile(t *testing.T) {
	r := &Reader{Root: root(t), Now: time.Now}
	cases := map[string]string{
		"/var/log/app/app.log":    "",
		"/var/log/shadow.log":     ReasonPathForbidden, // ссылка на файл вне /var/log
		"/var/log/etc/shadow":     ReasonPathForbidden, // ссылка на каталог по пути
		"/var/log/../etc/shadow":  ReasonPathForbidden,
		"/var/log/app/../app.log": ReasonPathForbidden,
		"/etc/shadow":             ReasonPathForbidden,
		"/var/log/nope.log":       ReasonNotFound,
		"/var/log/dir.log":        ReasonNotRegular,
		"var/log/app/app.log":     ReasonPathForbidden,
	}
	for p, want := range cases {
		f, reason, err := r.OpenFile(p)
		if f != nil {
			f.Close()
		}
		if reason != want || (want == "") != (err == nil) {
			t.Errorf("%s: причина %q (%v), ждали %q", p, reason, err, want)
		}
	}
	st, ok := r.Open([]*agentv1.LogSource{
		file("/var/log/app/app.log"), file("/var/log/app/app.log"), file("/var/log/shadow.log"),
		{Kind: agentv1.LogSourceKind_LOG_SOURCE_KIND_DOCKER, Name: "web"},
		{Kind: agentv1.LogSourceKind_LOG_SOURCE_KIND_SYSTEM},
	})
	var reasons []string
	for _, s := range st {
		reasons = append(reasons, s.GetReason())
	}
	if strings.Join(reasons, ",") != ",DUPLICATE,PATH_FORBIDDEN,SOURCE_UNSUPPORTED," || len(ok) != 2 {
		t.Fatalf("причины %v, открыто %d", reasons, len(ok))
	}
}

func TestPollFile(t *testing.T) {
	rt := root(t)
	r := &Reader{Root: rt, Now: time.Now}
	p := filepath.Join(rt, "var/log/app/app.log")
	sub := &Subscription{ID: "s", Sources: []*agentv1.LogSource{file("/var/log/app/app.log")}}
	key := Key(sub.Sources[0])

	// Первый опрос: позиция — конец файла, старые строки не уходят.
	recs, pos, _, errs := r.Poll(context.Background(), sub, nil)
	if len(recs) != 0 || len(errs) != 0 || pos[key] == "" {
		t.Fatalf("первый опрос: %v %v %v", recs, pos, errs)
	}
	appendTo(t, p, "GET / 200\nERROR db down password=hunter2hunter2\nhalf a li")
	recs, pos2, more, _ := r.Poll(context.Background(), sub, pos)
	if len(recs) != 2 || more {
		t.Fatalf("новые строки: %d %v", len(recs), more)
	}
	if recs[1].GetLevel() != agentv1.LogLevel_LOG_LEVEL_ERROR || strings.Contains(recs[1].GetMessage(), "hunter2") {
		t.Fatalf("уровень или секрет: %+v", recs[1])
	}
	// Неполная строка дочитывается, когда допишется.
	appendTo(t, p, "ne\n")
	recs, pos3, _, _ := r.Poll(context.Background(), sub, pos2)
	if len(recs) != 1 || recs[0].GetMessage() != "half a line" {
		t.Fatalf("дописанная строка: %+v", recs)
	}
	// Тот же опрос с той же позицией даёт то же (повтор пачки после сбоя — не потеря).
	again, _, _, _ := r.Poll(context.Background(), sub, pos2)
	if len(again) != 1 || again[0].GetCursor() != recs[0].GetCursor() {
		t.Fatal("повторный опрос с той же позиции")
	}
	// Ротация: новый файл читается с начала.
	must(t, os.Rename(p, p+".1"))
	must(t, os.WriteFile(p, []byte("fresh\n"), 0o644))
	recs, _, _, _ = r.Poll(context.Background(), sub, pos3)
	if len(recs) != 1 || recs[0].GetMessage() != "fresh" {
		t.Fatalf("после ротации: %+v", recs)
	}

	// Уровень: при WARN строки INFO не уходят.
	sub.MinLevel = agentv1.LogLevel_LOG_LEVEL_WARN
	_, pos4, _, _ := r.Poll(context.Background(), sub, nil)
	appendTo(t, p, "info line\nwarning: disk\n")
	recs, _, _, _ = r.Poll(context.Background(), sub, pos4)
	if len(recs) != 1 || recs[0].GetLevel() != agentv1.LogLevel_LOG_LEVEL_WARN {
		t.Fatalf("уровень WARN: %+v", recs)
	}
}

func TestPollLimits(t *testing.T) {
	rt := root(t)
	r := &Reader{Root: rt, Now: time.Now}
	p := filepath.Join(rt, "var/log/app/app.log")
	sub := &Subscription{Sources: []*agentv1.LogSource{file("/var/log/app/app.log")}}
	_, pos, _, _ := r.Poll(context.Background(), sub, nil)
	appendTo(t, p, strings.Repeat("line\n", 700)+strings.Repeat("x", 20<<10)+"\n")
	recs, pos, more, _ := r.Poll(context.Background(), sub, pos)
	if len(recs) != MaxRecords || !more {
		t.Fatalf("%d записей, more=%v", len(recs), more)
	}
	recs, _, _, _ = r.Poll(context.Background(), sub, pos)
	if len(recs) != 201 || len(recs[200].GetMessage()) != MaxMessage {
		t.Fatalf("остаток: %d, длина последней %d", len(recs), len(recs[len(recs)-1].GetMessage()))
	}
}

func appendTo(t *testing.T, p, s string) {
	t.Helper()
	f, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0)
	must(t, err)
	_, err = f.WriteString(s)
	must(t, err)
	must(t, f.Close())
}

const journalOut = `{"__CURSOR":"s=1;i=1","__REALTIME_TIMESTAMP":"1700000000123456","PRIORITY":"3","MESSAGE":"Failed password for root token=ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","_SYSTEMD_UNIT":"ssh.service","SYSLOG_IDENTIFIER":"sshd","_PID":"42"}
not json
{"__CURSOR":"s=1;i=2","__REALTIME_TIMESTAMP":"1700000001000000","PRIORITY":"6","MESSAGE":[104,105,255],"_SYSTEMD_UNIT":"ssh.service"}
`

func TestJournal(t *testing.T) {
	var gotArgs []string
	r := &Reader{Now: time.Now, Journal: func(_ context.Context, args []string) (io.ReadCloser, func() error, error) {
		gotArgs = args
		return io.NopCloser(strings.NewReader(journalOut)), func() error { return nil }, nil
	}}
	ssh := &agentv1.LogSource{Kind: agentv1.LogSourceKind_LOG_SOURCE_KIND_SSH}
	sub := &Subscription{CreatedAtMs: 1_700_000_000_000, MinLevel: agentv1.LogLevel_LOG_LEVEL_WARN, Sources: []*agentv1.LogSource{ssh}}
	recs, pos, _, errs := r.Poll(context.Background(), sub, nil)
	if len(errs) != 0 || len(recs) != 2 || pos[Key(ssh)] != "s=1;i=2" {
		t.Fatalf("%v %v %v", recs, pos, errs)
	}
	if !strings.Contains(strings.Join(gotArgs, " "), "--since=@1700000000") || !strings.Contains(strings.Join(gotArgs, " "), "--priority=0..4") ||
		!strings.Contains(strings.Join(gotArgs, " "), "--unit=sshd.service") {
		t.Fatalf("аргументы: %v", gotArgs)
	}
	a := recs[0]
	if a.GetTimeMs() != 1_700_000_000_123 || a.GetLevel() != agentv1.LogLevel_LOG_LEVEL_ERROR || a.GetFields()["pid"] != "42" ||
		strings.Contains(a.GetMessage(), "ghp_") {
		t.Fatalf("запись: %+v", a)
	}
	if recs[1].GetMessage() != "hi�" {
		t.Fatalf("двоичное сообщение: %q", recs[1].GetMessage())
	}
	// Следующий опрос — после курсора.
	_, _, _, _ = r.Poll(context.Background(), sub, pos)
	if !strings.Contains(strings.Join(gotArgs, " "), "--after-cursor=s=1;i=2") {
		t.Fatalf("аргументы: %v", gotArgs)
	}
	// grep у logs.read — подстрока: спецсимволы PCRE экранированы.
	_, _ = r.Read(context.Background(), ssh, 10, "a.b(c")
	if !strings.Contains(strings.Join(gotArgs, " "), `--grep=a\.b\(c`) {
		t.Fatalf("grep: %v", gotArgs)
	}
}

func TestReadFile(t *testing.T) {
	rt := root(t)
	r := &Reader{Root: rt, Now: time.Now}
	p := filepath.Join(rt, "var/log/app/app.log")
	appendTo(t, p, "a1\nb2\na3\na4\n")
	res, err := r.Read(context.Background(), file("/var/log/app/app.log"), 2, "a")
	if err != nil || len(res.GetRecords()) != 2 || res.GetRecords()[0].GetMessage() != "a3" || res.GetRecords()[1].GetMessage() != "a4" {
		t.Fatalf("%v %+v", err, res)
	}
	if _, err := r.Read(context.Background(), file("/var/log/shadow.log"), 2, ""); err == nil {
		t.Fatal("прочитана ссылка наружу")
	}
}
