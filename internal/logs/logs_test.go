// SPDX-License-Identifier: AGPL-3.0-only

package logs

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
)

// fakeHelper отдаёт записи «строка N» с позиции N.
type fakeHelper struct {
	sub   string
	total int
	err   error
	calls int
}

func (f *fakeHelper) LogsPoll(_ context.Context, sub string, pos map[string]string) (string, [][]byte, map[string]string, bool, error) {
	f.calls++
	if f.err != nil {
		return "", nil, nil, false, f.err
	}
	from := 0
	if sub == f.sub {
		from, _ = strconv.Atoi(pos["file"])
	}
	to := min(from+3, f.total)
	var raw [][]byte
	for i := from; i < to; i++ {
		b, _ := proto.Marshal(&agentv1.LogRecord{Message: "строка " + strconv.Itoa(i), Cursor: strconv.Itoa(i)})
		raw = append(raw, b)
	}
	return f.sub, raw, map[string]string{"file": strconv.Itoa(to)}, to < f.total, nil
}

func messages(t *testing.T, s *Spool) []string {
	t.Helper()
	var out []string
	for _, seq := range s.Pending() {
		c, err := s.Load(seq)
		if err != nil || c == nil {
			t.Fatalf("пачка %d: %v", seq, err)
		}
		for _, r := range c.GetRecords() {
			out = append(out, r.GetMessage())
		}
	}
	return out
}

func TestSpoolAndRestart(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	h := &fakeHelper{sub: "op1", total: 7}
	for {
		more, err := step(context.Background(), h, s)
		if err != nil {
			t.Fatal(err)
		}
		if !more {
			break
		}
	}
	if got := messages(t, s); len(got) != 7 || got[6] != "строка 6" {
		t.Fatalf("%v", got)
	}
	if p := s.Pending(); len(p) != 3 || p[0] != 1 || p[2] != 3 {
		t.Fatalf("пачки %v", p)
	}
	c, _ := s.Load(1)
	if c.GetSubscriptionId() != "op1" || c.GetSeq() != 1 {
		t.Fatalf("%+v", c)
	}
	s.Ack(1)

	// Перезапуск агента: позиции и номера пачек продолжаются, повторов нет.
	s2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	h.total = 9
	if _, err := step(context.Background(), h, s2); err != nil {
		t.Fatal(err)
	}
	got := messages(t, s2)
	if len(got) != 6 || got[len(got)-1] != "строка 8" {
		t.Fatalf("после перезапуска: %v", got)
	}
	if p := s2.Pending(); p[len(p)-1] != 4 {
		t.Fatalf("номер пачки после перезапуска: %v", p)
	}
	// Пустой опрос без смены позиций не пишет пачку.
	if _, err := step(context.Background(), h, s2); err != nil || len(s2.Pending()) != 3 {
		t.Fatalf("пустой опрос: %v %v", err, s2.Pending())
	}
	// Новая подписка: позиции прежней не передаются помощнику как свои.
	h.sub = "op2"
	h.total = 2
	if _, err := step(context.Background(), h, s2); err != nil {
		t.Fatal(err)
	}
	last, _ := s2.Load(s2.Pending()[len(s2.Pending())-1])
	if last.GetSubscriptionId() != "op2" || len(last.GetRecords()) != 2 {
		t.Fatalf("новая подписка: %+v", last)
	}
}

func TestSpoolLimit(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s.Max = 3000
	big := strings.Repeat("x", 1000)
	for i := 0; i < 10; i++ {
		if err := s.Append("op", []*agentv1.LogRecord{{Message: big}}, map[string]string{"f": strconv.Itoa(i)}); err != nil {
			t.Fatal(err)
		}
	}
	p := s.Pending()
	if len(p) > 3 || p[len(p)-1] != 10 {
		t.Fatalf("пачки %v", p)
	}
	// Следующая пачка несёт число пропущенных записей, и счёт обнуляется.
	if err := s.Append("op", []*agentv1.LogRecord{{Message: "after"}}, nil); err != nil {
		t.Fatal(err)
	}
	c, _ := s.Load(11)
	if c.GetDropped() == 0 {
		t.Fatalf("dropped = 0: %+v", c.GetDropped())
	}
	if err := s.Append("op", []*agentv1.LogRecord{{Message: "next"}}, nil); err != nil {
		t.Fatal(err)
	}
	c, _ = s.Load(12)
	if c.GetDropped() != 0 {
		t.Fatalf("счёт пропущенных не обнулён: %d", c.GetDropped())
	}
}

func TestPollError(t *testing.T) {
	s, _ := Open(t.TempDir())
	h := &fakeHelper{err: errors.New("helper: PEER_FORBIDDEN")}
	if _, err := step(context.Background(), h, s); err == nil {
		t.Fatal("ошибка помощника проглочена")
	}
	if len(s.Pending()) != 0 {
		t.Fatal("пачка без записей")
	}
}
