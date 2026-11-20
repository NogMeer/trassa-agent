// SPDX-License-Identifier: AGPL-3.0-only

package helper

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/helperrpc"
	"github.com/NogMeer/trassa-agent/internal/logsrc"
	"github.com/NogMeer/trassa-agent/internal/ops"
)

func logsParams(sources ...*agentv1.LogSource) *agentv1.OperationParams {
	return &agentv1.OperationParams{Params: &agentv1.OperationParams_LogsSubscribe{LogsSubscribe: &agentv1.LogsSubscribeParams{Sources: sources}}}
}

func fileSrc(p string) *agentv1.LogSource {
	return &agentv1.LogSource{Kind: agentv1.LogSourceKind_LOG_SOURCE_KIND_FILE, Name: p}
}

func (f *fixture) poll(sub string, pos map[string]string) helperrpc.Response {
	var out helperrpc.Response
	f.e.Serve(context.Background(), helperrpc.Request{Method: helperrpc.MethodLogsPoll, Subscription: sub, Positions: pos},
		func(r helperrpc.Response) error { out = r; return nil })
	return out
}

func TestLogsSubscribeAndPoll(t *testing.T) {
	f := newFixture(t)
	logDir := filepath.Join(f.root, "var/log")
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		t.Fatal(err)
	}
	app := filepath.Join(logDir, "app.log")
	if err := os.WriteFile(app, []byte("before\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/passwd", filepath.Join(logDir, "evil.log")); err != nil {
		t.Fatal(err)
	}
	f.e.Logs = &logsrc.Reader{Root: f.root, Now: f.clock.Now}

	// Без подписки опрос пуст.
	if r := f.poll("", nil); r.Kind != helperrpc.KindLogs || len(r.Records) != 0 || r.Subscription != "" {
		t.Fatalf("без подписки: %+v", r)
	}
	b := f.body(ops.TypeLogsSubscribe, logsParams(fileSrc("/var/log/app.log"), fileSrc("/var/log/evil.log")))
	o := f.exec(sealed(b))
	if !o.accepted || o.result.GetOutcome() != agentv1.OperationOutcome_OPERATION_OUTCOME_SUCCEEDED {
		t.Fatalf("logs.subscribe: %+v", o)
	}
	st := o.result.GetLogsSubscribe().GetSources()
	if len(st) != 2 || !st[0].GetOpened() || st[1].GetReason() != logsrc.ReasonPathForbidden {
		t.Fatalf("статусы: %+v", st)
	}
	sub := strings.ToLower(b.GetOperationId())
	// Строка, дописанная между подпиской и первым опросом, не теряется.
	if err := os.WriteFile(app, []byte("before\nbetween\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := f.poll("", nil)
	if len(r.Records) != 1 {
		t.Fatalf("строка между подпиской и опросом: %+v", r)
	}
	r = f.poll(sub, r.Positions)
	if r.Subscription != sub || len(r.Records) != 0 || len(r.Positions) != 1 {
		t.Fatalf("первый опрос: %+v", r)
	}
	if err := os.WriteFile(app, []byte("before\nbetween\nafter token=trs_live_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r2 := f.poll(sub, r.Positions)
	if len(r2.Records) != 1 {
		t.Fatalf("новая строка: %+v", r2)
	}
	var rec agentv1.LogRecord
	if err := proto.Unmarshal(r2.Records[0], &rec); err != nil || !strings.HasPrefix(rec.GetMessage(), "after") || strings.Contains(rec.GetMessage(), "abcdefghijkl") {
		t.Fatalf("запись: %v %+v", err, &rec)
	}
	// Позиции чужой подписки не принимаются: отсчёт от начала действующей подписки.
	if r3 := f.poll("other", r2.Positions); len(r3.Records) != 2 {
		t.Fatalf("позиции прежней подписки: %+v", r3)
	}
	// Пустой список выключает сбор.
	o = f.exec(sealed(f.body(ops.TypeLogsSubscribe, logsParams())))
	if o.result.GetOutcome() != agentv1.OperationOutcome_OPERATION_OUTCOME_SUCCEEDED {
		t.Fatalf("выключение: %+v", o)
	}
	if r := f.poll(sub, r2.Positions); len(r.Records) != 0 || len(r.Positions) != 0 {
		t.Fatalf("после выключения: %+v", r)
	}
}

func TestLogsRejected(t *testing.T) {
	f := newFixture(t)
	f.e.Logs = &logsrc.Reader{Root: f.root, Now: f.clock.Now}
	bad := []*agentv1.OperationParams{
		logsParams(fileSrc("/etc/shadow")),
		logsParams(fileSrc("/var/log/../etc/shadow")),
		logsParams(&agentv1.LogSource{Kind: agentv1.LogSourceKind_LOG_SOURCE_KIND_UNIT, Name: "--output=export"}),
		logsParams(&agentv1.LogSource{Kind: agentv1.LogSourceKind_LOG_SOURCE_KIND_SYSTEM, Name: "x"}),
		{Params: &agentv1.OperationParams_LogsRead{LogsRead: &agentv1.LogsReadParams{Source: fileSrc("/var/log/syslog"), Lines: 501}}},
		{Params: &agentv1.OperationParams_LogsRead{LogsRead: &agentv1.LogsReadParams{Source: fileSrc("/var/log/syslog"), Lines: 5, Grep: strings.Repeat("я", 201)}}},
	}
	many := make([]*agentv1.LogSource, ops.MaxLogSources+1)
	for i := range many {
		many[i] = &agentv1.LogSource{Kind: agentv1.LogSourceKind_LOG_SOURCE_KIND_SYSTEM}
	}
	bad = append(bad, logsParams(many...))
	for i, p := range bad {
		b := f.body(ops.TypeLogsSubscribe, p)
		if p.GetLogsRead() != nil {
			b.Type = ops.TypeLogsRead
		}
		if o := f.exec(sealed(b)); o.accepted || o.code != ops.CodeParamsInvalid {
			t.Errorf("%d: %+v", i, o)
		}
	}
}

func TestLogsRead(t *testing.T) {
	f := newFixture(t)
	logDir := filepath.Join(f.root, "var/log")
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(logDir, "app.log"), []byte("x1\ny\nx2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	f.e.Logs = &logsrc.Reader{Root: f.root, Now: f.clock.Now}
	b := f.body(ops.TypeLogsRead, &agentv1.OperationParams{Params: &agentv1.OperationParams_LogsRead{LogsRead: &agentv1.LogsReadParams{
		Source: fileSrc("/var/log/app.log"), Lines: 10, Grep: "x",
	}}})
	o := f.exec(sealed(b))
	recs := o.result.GetLogsRead().GetRecords()
	if len(recs) != 2 || recs[1].GetMessage() != "x2" {
		t.Fatalf("%+v", o.result)
	}
	b = f.body(ops.TypeLogsRead, &agentv1.OperationParams{Params: &agentv1.OperationParams_LogsRead{LogsRead: &agentv1.LogsReadParams{
		Source: fileSrc("/var/log/missing.log"), Lines: 10,
	}}})
	if o := f.exec(sealed(b)); o.result.GetErrorCode() != logsrc.ReasonNotFound {
		t.Fatalf("нет файла: %+v", o.result)
	}
}
