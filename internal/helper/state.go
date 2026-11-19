// SPDX-License-Identifier: AGPL-3.0-only

package helper

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/NogMeer/trassa-agent/internal/config"
	"github.com/NogMeer/trassa-agent/internal/fsutil"
)

// Статусы операции на диске помощника.
const (
	StatusRunning         = "running"
	StatusAwaitingConfirm = "awaiting_confirm"
	StatusDone            = "done"
)

// OpState — состояние операции в /var/lib/trassa/helper/ops/<operation_id>.json. Переживает перезапуск
// помощника и агента: итог хранится, пока шлюз не подтвердит приём (Reported).
type OpState struct {
	OperationID string `json:"operation_id"`
	Type        string `json:"type"`
	Nonce       string `json:"nonce"`
	Mutating    bool   `json:"mutating"`
	Status      string `json:"status"`
	Result      []byte `json:"result,omitempty"` // OperationResult (protobuf)
	Outcome     int32  `json:"outcome,omitempty"`
	Reported    bool   `json:"reported"`
	UpdatedAtMs int64  `json:"updated_at_ms"`
}

// States — каталог состояний.
type States struct{ Dir string }

func (s States) path(op string) (string, error) {
	if !config.IsUUID(op) {
		return "", fmt.Errorf("operation_id %q", op)
	}
	return filepath.Join(s.Dir, strings.ToLower(op)+".json"), nil
}

// Get возвращает состояние или nil, если операции нет.
func (s States) Get(op string) (*OpState, error) {
	p, err := s.path(op)
	if err != nil {
		return nil, err
	}
	raw, err := fsutil.ReadLimited(p, 8<<20)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var st OpState
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, fmt.Errorf("состояние %s повреждено: %w", op, err)
	}
	return &st, nil
}

// Put атомарно записывает состояние.
func (s States) Put(st *OpState) error {
	p, err := s.path(st.OperationID)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(p, raw, 0o600, fsutil.Keep)
}

// List — все состояния.
func (s States) List() ([]*OpState, error) {
	ents, err := os.ReadDir(s.Dir)
	if err != nil {
		return nil, err
	}
	var out []*OpState
	for _, e := range ents {
		name := e.Name()
		if !strings.HasSuffix(name, ".json") || strings.HasPrefix(name, ".") {
			continue
		}
		st, err := s.Get(strings.TrimSuffix(name, ".json"))
		if err != nil {
			return nil, err
		}
		if st != nil {
			out = append(out, st)
		}
	}
	return out, nil
}

// Prune удаляет завершённые и доставленные состояния старше maxAge.
func (s States) Prune(now time.Time, maxAge time.Duration) error {
	all, err := s.List()
	if err != nil {
		return err
	}
	for _, st := range all {
		if st.Status == StatusDone && st.Reported && now.Sub(time.UnixMilli(st.UpdatedAtMs)) > maxAge {
			p, _ := s.path(st.OperationID)
			if err := fsutil.RemoveSync(p); err != nil {
				return err
			}
		}
	}
	return nil
}

// FileLock — межпроцессная блокировка (flock): serve и «trassa-helper rollback» из таймера не меняют состояние
// одновременно. Блокировки flock принадлежат открытому файлу, поэтому две горутины одного процесса тоже
// исключают друг друга.
type FileLock struct{ Path string }

// Lock ждёт блокировку до отмены ctx.
func (l FileLock) Lock(ctx context.Context) (func(), error) {
	f, err := os.OpenFile(l.Path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	for {
		err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return func() {
				_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
				_ = f.Close()
			}, nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EINTR) {
			f.Close()
			return nil, err
		}
		select {
		case <-ctx.Done():
			f.Close()
			return nil, ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}
