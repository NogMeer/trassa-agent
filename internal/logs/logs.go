// SPDX-License-Identifier: AGPL-3.0-only

// Package logs — журналы на стороне агента (E08-T15). Агент без прав журналов не читает: записи по подписке
// отдаёт помощник (logs.poll), уже без секретов. Агент складывает их пачками на диск (до 50 МБ без связи) и
// отправляет шлюзу до квитанции InboundAck. Позиции источников пишутся после пачки: сбой между записями даёт
// повтор не больше одной пачки, потерь нет.
package logs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/fsutil"
)

// Пределы (E08, раздел 6).
const (
	MaxSpool     = 50 << 20
	PollInterval = 2 * time.Second
)

// Poller — помощник глазами сборщика (helperrpc.Client.LogsPoll).
type Poller interface {
	LogsPoll(ctx context.Context, subscription string, positions map[string]string) (string, [][]byte, map[string]string, bool, error)
}

type state struct {
	Subscription string            `json:"subscription"`
	Positions    map[string]string `json:"positions"`
	NextSeq      uint32            `json:"next_seq"`
	Dropped      uint64            `json:"dropped"`
}

// Spool — пачки на диске до квитанции. Файл пачки: chunk-<seq>-<записей>.pb.
type Spool struct {
	Dir string
	Max int64

	mu     sync.Mutex
	st     state
	notify chan struct{}
}

// Open читает состояние каталога. Повреждённое состояние — ошибка: позиции угадывать нельзя.
func Open(dir string) (*Spool, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	s := &Spool{Dir: dir, Max: MaxSpool, notify: make(chan struct{}, 1), st: state{NextSeq: 1}}
	b, err := os.ReadFile(filepath.Join(dir, "state.json"))
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return nil, err
	default:
		if err := json.Unmarshal(b, &s.st); err != nil {
			return nil, fmt.Errorf("logs: состояние: %w", err)
		}
	}
	// Номер следующей пачки не меньше последнего файла: состояние могло не успеть записаться после пачки.
	for _, c := range s.list() {
		if c.seq >= s.st.NextSeq {
			s.st.NextSeq = c.seq + 1
		}
	}
	return s, nil
}

type chunkFile struct {
	seq   uint32
	count uint64
	size  int64
	name  string
}

func (s *Spool) list() []chunkFile {
	ents, _ := os.ReadDir(s.Dir)
	var out []chunkFile
	for _, e := range ents {
		n := e.Name()
		if !strings.HasPrefix(n, "chunk-") || !strings.HasSuffix(n, ".pb") {
			continue
		}
		parts := strings.Split(strings.TrimSuffix(strings.TrimPrefix(n, "chunk-"), ".pb"), "-")
		if len(parts) != 2 {
			continue
		}
		seq, err1 := strconv.ParseUint(parts[0], 10, 32)
		cnt, err2 := strconv.ParseUint(parts[1], 10, 64)
		fi, err3 := e.Info()
		if err1 != nil || err2 != nil || err3 != nil {
			continue
		}
		out = append(out, chunkFile{seq: uint32(seq), count: cnt, size: fi.Size(), name: n})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].seq < out[j].seq })
	return out
}

func (s *Spool) saveState() error {
	b, err := json.Marshal(s.st)
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(filepath.Join(s.Dir, "state.json"), b, 0o600, fsutil.Keep)
}

// Position — подписка и позиции для следующего опроса помощника.
func (s *Spool) Position() (string, map[string]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	pos := make(map[string]string, len(s.st.Positions))
	for k, v := range s.st.Positions {
		pos[k] = v
	}
	return s.st.Subscription, pos
}

// Append кладёт записи пачкой и запоминает новые позиции. Сначала пачка, потом позиции. Пачки сверх Max
// удаляются, самые старые первыми; их записи считаются в dropped следующей пачки.
func (s *Spool) Append(sub string, recs []*agentv1.LogRecord, pos map[string]string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(recs) > 0 {
		c := &agentv1.LogChunk{SubscriptionId: sub, Seq: s.st.NextSeq, Records: recs, Dropped: s.st.Dropped}
		b, err := proto.Marshal(c)
		if err != nil {
			return err
		}
		name := fmt.Sprintf("chunk-%010d-%d.pb", c.Seq, len(recs))
		if err := fsutil.WriteFileAtomic(filepath.Join(s.Dir, name), b, 0o600, fsutil.Keep); err != nil {
			return err
		}
		s.st.NextSeq++
		s.st.Dropped = 0
		s.trimLocked()
	}
	s.st.Subscription, s.st.Positions = sub, pos
	if err := s.saveState(); err != nil {
		return err
	}
	if len(recs) > 0 {
		select {
		case s.notify <- struct{}{}:
		default:
		}
	}
	return nil
}

func (s *Spool) trimLocked() {
	files := s.list()
	var total int64
	for _, f := range files {
		total += f.size
	}
	// Последняя (только что записанная) пачка не удаляется.
	for i := 0; i < len(files)-1 && total > s.Max; i++ {
		if err := fsutil.RemoveSync(filepath.Join(s.Dir, files[i].name)); err != nil {
			return
		}
		total -= files[i].size
		s.st.Dropped += files[i].count
	}
}

// Pending — номера пачек, ждущих квитанции, по порядку.
func (s *Spool) Pending() []uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	files := s.list()
	out := make([]uint32, len(files))
	for i, f := range files {
		out[i] = f.seq
	}
	return out
}

// Load читает пачку; удалённая (вытеснена или подтверждена) — nil.
func (s *Spool) Load(seq uint32) (*agentv1.LogChunk, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, f := range s.list() {
		if f.seq != seq {
			continue
		}
		b, err := os.ReadFile(filepath.Join(s.Dir, f.name))
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		var c agentv1.LogChunk
		if err := proto.Unmarshal(b, &c); err != nil {
			// Пачку не прочитать — отправлять нечего; она удаляется, записи считаются пропущенными.
			_ = fsutil.RemoveSync(filepath.Join(s.Dir, f.name))
			s.st.Dropped += f.count
			return nil, fmt.Errorf("logs: пачка %d повреждена: %w", seq, err)
		}
		return &c, nil
	}
	return nil, nil
}

// Ack — шлюз подтвердил пачку.
func (s *Spool) Ack(seq uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, f := range s.list() {
		if uint64(f.seq) == seq {
			_ = fsutil.RemoveSync(filepath.Join(s.Dir, f.name))
			return
		}
	}
}

// Notify — сигнал «появилась пачка».
func (s *Spool) Notify() <-chan struct{} { return s.notify }

// Run опрашивает помощника раз в every (сразу ещё раз, если записей больше одной пачки) и складывает записи.
func Run(ctx context.Context, p Poller, s *Spool, every time.Duration, log *slog.Logger) {
	failing := ""
	for {
		more, err := step(ctx, p, s)
		if err != nil {
			if err.Error() != failing {
				log.Warn("журналы: опрос помощника", "err", err)
			}
			failing = err.Error()
		} else {
			failing = ""
		}
		if more && err == nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		}
	}
}

func step(ctx context.Context, p Poller, s *Spool) (bool, error) {
	sub, pos := s.Position()
	nsub, raw, npos, more, err := p.LogsPoll(ctx, sub, pos)
	if err != nil {
		return false, err
	}
	recs := make([]*agentv1.LogRecord, 0, len(raw))
	for _, b := range raw {
		var r agentv1.LogRecord
		if err := proto.Unmarshal(b, &r); err != nil {
			return false, fmt.Errorf("запись помощника: %w", err)
		}
		recs = append(recs, &r)
	}
	if len(recs) == 0 && nsub == sub && equal(npos, pos) {
		return false, nil
	}
	return more, s.Append(nsub, recs, npos)
}

func equal(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}
