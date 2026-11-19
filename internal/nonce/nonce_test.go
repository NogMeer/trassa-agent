// SPDX-License-Identifier: AGPL-3.0-only

package nonce

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func n(i int) []byte {
	b := make([]byte, 16)
	binary.BigEndian.PutUint64(b, uint64(i))
	return b
}

func TestReplayAfterRestart(t *testing.T) {
	p := filepath.Join(t.TempDir(), "nonces")
	c := &clock{t: time.Unix(1_800_000_000, 0)}
	s, err := Open(p, c.now)
	if err != nil {
		t.Fatal(err)
	}
	if s.Check(n(1), "op-1") != Fresh {
		t.Fatal("новый номер не Fresh")
	}
	if err := s.Record(n(1), "op-1", c.t.Add(5*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if s.Check(n(1), "op-1") != SameOperation {
		t.Fatal("та же операция не опознана")
	}
	if s.Check(n(1), "op-2") != Replay {
		t.Fatal("чужая операция с тем же номером не Replay")
	}
	if err := s.Record(n(1), "op-2", c.t.Add(time.Minute)); !errors.Is(err, ErrReplay) {
		t.Fatalf("запись повтора: %v", err)
	}
	_ = s.Close()

	// Перезапуск помощника: окно восстановлено с диска.
	s2, err := Open(p, c.now)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if s2.Check(n(1), "op-2") != Replay {
		t.Fatal("после перезапуска повтор принят")
	}
	st, _ := os.Stat(p)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("права журнала %v", st.Mode().Perm())
	}
}

func TestExpiryAndClockShift(t *testing.T) {
	p := filepath.Join(t.TempDir(), "nonces")
	c := &clock{t: time.Unix(1_800_000_000, 0)}
	s, err := Open(p, c.now)
	if err != nil {
		t.Fatal(err)
	}
	notAfter := c.t.Add(5 * time.Minute)
	if err := s.Record(n(1), "op-1", notAfter); err != nil {
		t.Fatal(err)
	}
	// Часы ушли назад на час: запись жива, повтор отклоняется.
	c.t = c.t.Add(-time.Hour)
	if s.Check(n(1), "op-2") != Replay {
		t.Fatal("сдвиг часов назад стёр запись")
	}
	// Запись живёт до not_after + 2 минуты.
	c.t = notAfter.Add(Grace - time.Second)
	if s.Check(n(1), "op-2") != Replay {
		t.Fatal("запись умерла раньше not_after + 2 мин")
	}
	c.t = notAfter.Add(Grace + time.Second)
	if s.Check(n(1), "op-2") != Fresh || s.Len() != 0 {
		t.Fatal("просроченная запись не забыта")
	}
	_ = s.Close()
	s2, err := Open(p, c.now)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if s2.Len() != 0 {
		t.Fatal("просроченная запись пережила перезапуск")
	}
}

func Test10000Entries(t *testing.T) {
	p := filepath.Join(t.TempDir(), "nonces")
	c := &clock{t: time.Unix(1_800_000_000, 0)}
	// Журнал из 10 000 строк собирается напрямую: 10 000 fsync подряд проверяют диск, а не окно.
	var buf []byte
	exp := c.t.Add(10*time.Minute + Grace).UnixMilli()
	for i := 0; i < 10_000; i++ {
		b, _ := json.Marshal(line{N: hex.EncodeToString(n(i)), O: "op", E: exp})
		buf = append(append(buf, b...), '\n')
	}
	if err := os.WriteFile(p, buf, 0o600); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	s2, err := Open(p, c.now)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("открытие 10 000 записей заняло %v", d)
	}
	if s2.Len() != 10_000 {
		t.Fatalf("записей %d", s2.Len())
	}
	for i := 0; i < 10_000; i += 997 {
		if s2.Check(n(i), "other") != Replay {
			t.Fatalf("номер %d забыт", i)
		}
	}
	// Все просрочены: следующая запись запускает уплотнение журнала.
	c.t = c.t.Add(time.Hour)
	if err := s2.Record(n(-1), "op-x", c.t.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(p)
	if st.Size() > 1024 {
		t.Fatalf("журнал не уплотнён: %d байт", st.Size())
	}
}

func TestCorruption(t *testing.T) {
	dir := t.TempDir()
	torn := filepath.Join(dir, "torn")
	if err := os.WriteFile(torn, []byte(`{"n":"aa","o":"op","e":99999999999999}`+"\n"+`{"n":"bb","o`), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := Open(torn, nil)
	if err != nil {
		t.Fatalf("оборванный хвост: %v", err)
	}
	if s.Len() != 1 {
		t.Fatalf("записей %d", s.Len())
	}
	_ = s.Close()
	bad := filepath.Join(dir, "bad")
	if err := os.WriteFile(bad, []byte("мусор\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(bad, nil); err == nil {
		t.Fatal("повреждённый журнал принят")
	}
}
