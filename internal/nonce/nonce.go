// SPDX-License-Identifier: AGPL-3.0-only

// Package nonce — окно одноразовых номеров помощника (E05-T13, проверка 4 раздела 6).
//
// Файл /var/lib/trassa/helper/nonces (root, 0600) — журнал строк JSON, по одной на номер: номер, operation_id
// и срок жизни записи (not_after + 2 минуты). Запись дописывается с fsync до выполнения операции, поэтому повтор
// после перезапуска помощника отклоняется. При открытии и по мере накопления просроченных журнал переписывается
// атомарно только с живыми записями.
package nonce

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/NogMeer/trassa-agent/internal/fsutil"
)

// Grace — сколько запись живёт после not_after.
const Grace = 2 * time.Minute

// Status — итог проверки номера.
type Status int

const (
	// Fresh — номер не встречался.
	Fresh Status = iota
	// SameOperation — номер уже записан за этой же операцией: повторная доставка, не ошибка.
	SameOperation
	// Replay — номер уже записан за другой операцией (код REPLAY).
	Replay
)

type entry struct {
	op      string
	expires int64 // unix ms
}

type line struct {
	N string `json:"n"`
	O string `json:"o"`
	E int64  `json:"e"`
}

// Store — окно номеров. Безопасен для одновременного использования.
type Store struct {
	mu        sync.Mutex
	path      string
	f         *os.File
	now       func() time.Time
	live      map[string]entry
	dead      int // просроченных строк в файле
	lastPrune time.Time
}

// Open читает журнал. Повреждённая строка в середине — ошибка: помощник не стартует, а не забывает номера.
// Оборванная последняя строка (сбой во время дописывания) отбрасывается: её операция не начиналась.
func Open(path string, now func() time.Time) (*Store, error) {
	if now == nil {
		now = time.Now
	}
	s := &Store{path: path, now: now, live: map[string]entry{}}
	raw, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	nowMs := now().UnixMilli()
	for len(raw) > 0 {
		i := bytes.IndexByte(raw, '\n')
		if i < 0 {
			break // оборванная запись
		}
		var l line
		if err := json.Unmarshal(raw[:i], &l); err != nil || l.N == "" || l.O == "" {
			return nil, fmt.Errorf("nonces: повреждённая строка: %v", err)
		}
		raw = raw[i+1:]
		if l.E > nowMs {
			s.live[l.N] = entry{op: l.O, expires: l.E}
		}
	}
	if err := s.rewrite(); err != nil {
		return nil, err
	}
	return s, nil
}

// Close закрывает журнал.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f == nil {
		return nil
	}
	err := s.f.Close()
	s.f = nil
	return err
}

// Len — число живых записей.
func (s *Store) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(true)
	return len(s.live)
}

// Check сообщает, встречался ли номер. Просроченная запись считается забытой: операция с таким номером всё равно
// отклоняется по not_after.
func (s *Store) Check(nonce []byte, operationID string) Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.live[hex.EncodeToString(nonce)]
	if !ok || e.expires <= s.now().UnixMilli() {
		return Fresh
	}
	if e.op == operationID {
		return SameOperation
	}
	return Replay
}

// Record записывает номер до выполнения операции. Ошибка записи — операция не выполняется.
// Повторная запись того же номера за той же операцией — не ошибка; за другой — Replay.
func (s *Store) Record(nonce []byte, operationID string, notAfter time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f == nil {
		return errors.New("nonces: журнал закрыт")
	}
	key := hex.EncodeToString(nonce)
	nowMs := s.now().UnixMilli()
	if e, ok := s.live[key]; ok && e.expires > nowMs {
		if e.op == operationID {
			return nil
		}
		return ErrReplay
	}
	exp := notAfter.Add(Grace).UnixMilli()
	b, err := json.Marshal(line{N: key, O: operationID, E: exp})
	if err != nil {
		return err
	}
	if _, err := s.f.Write(append(b, '\n')); err != nil {
		return err
	}
	if err := s.f.Sync(); err != nil {
		return err
	}
	s.live[key] = entry{op: operationID, expires: exp}
	s.pruneLocked(false)
	if s.dead > 1000 && s.dead > len(s.live) {
		return s.rewrite()
	}
	return nil
}

// ErrReplay — номер уже записан за другой операцией.
var ErrReplay = errors.New("REPLAY")

func (s *Store) pruneLocked(force bool) {
	now := s.now()
	if !force && now.Sub(s.lastPrune) < time.Minute && now.After(s.lastPrune) {
		return
	}
	s.lastPrune = now
	nowMs := now.UnixMilli()
	for k, e := range s.live {
		if e.expires <= nowMs {
			delete(s.live, k)
			s.dead++
		}
	}
}

// rewrite атомарно заменяет журнал живыми записями и открывает его на дописывание.
func (s *Store) rewrite() error {
	if s.f != nil {
		_ = s.f.Close()
		s.f = nil
	}
	err := fsutil.WriteAtomic(s.path, 0o600, fsutil.Keep, func(w io.Writer) error {
		bw := bufio.NewWriter(w)
		for k, e := range s.live {
			b, err := json.Marshal(line{N: k, O: e.op, E: e.expires})
			if err != nil {
				return err
			}
			bw.Write(b)
			bw.WriteByte('\n')
		}
		return bw.Flush()
	})
	if err != nil {
		return err
	}
	f, err := os.OpenFile(s.path, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	s.f = f
	s.dead = 0
	return nil
}
