// SPDX-License-Identifier: AGPL-3.0-only

// Package rollback — точка отката CONFIG (E05-T18, R13).
//
// Каталог /var/lib/trassa/rollback/<operation_id>/: manifest.json (пути, права, владельцы, sha256, службы к
// перезапуску, время) и копии файлов files/<n>. Манифест пишется последним: точка без манифеста считается
// несозданной и удаляется. Лимиты: 100 МБ на операцию, хранение 30 дней или 50 последних.
package rollback

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/NogMeer/trassa-agent/internal/config"
	"github.com/NogMeer/trassa-agent/internal/fsutil"
)

// Пределы по умолчанию (раздел 6).
const (
	DefaultMaxBytes = 100 << 20
	DefaultMaxAge   = 30 * 24 * time.Hour
	DefaultMaxCount = 50
)

var (
	// ErrUnavailable — точку отката создать нельзя: операция не выполняется (ROLLBACK_UNAVAILABLE).
	ErrUnavailable = errors.New("ROLLBACK_UNAVAILABLE")
	// ErrFailed — вернуть состояние не удалось (ROLLBACK_FAILED).
	ErrFailed = errors.New("ROLLBACK_FAILED")
	// ErrNotFound — точки отката нет.
	ErrNotFound = errors.New("rollback point not found")
)

// File — сохранённый файл.
type File struct {
	Path    string `json:"path"`
	Existed bool   `json:"existed"`
	Mode    uint32 `json:"mode,omitempty"`
	UID     int    `json:"uid,omitempty"`
	GID     int    `json:"gid,omitempty"`
	Size    int64  `json:"size,omitempty"`
	SHA256  string `json:"sha256,omitempty"`
	Copy    string `json:"copy,omitempty"`
}

// Manifest — описание точки.
type Manifest struct {
	OperationID string   `json:"operation_id"`
	CreatedAtMs int64    `json:"created_at_ms"`
	Files       []File   `json:"files"`
	Services    []string `json:"services"`
	TotalBytes  int64    `json:"total_bytes"`
}

// Store — каталог точек.
type Store struct {
	Dir      string
	MaxBytes int64
	MaxAge   time.Duration
	MaxCount int
	Now      func() time.Time
}

func (s *Store) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Store) dir(op string) (string, error) {
	if !config.IsUUID(op) {
		return "", fmt.Errorf("operation_id %q", op)
	}
	return filepath.Join(s.Dir, strings.ToLower(op)), nil
}

func unavailable(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrUnavailable, fmt.Sprintf(format, a...))
}

// Create сохраняет файлы paths. Поддерживаются обычные файлы и отсутствующие пути (при возврате они удаляются).
// Любая ошибка — ErrUnavailable, частично созданная точка удаляется.
func (s *Store) Create(op string, paths, services []string) (m *Manifest, err error) {
	dir, err := s.dir(op)
	if err != nil {
		return nil, unavailable("%v", err)
	}
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return nil, unavailable("%v", err)
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		return nil, unavailable("каталог точки: %v", err)
	}
	defer func() {
		if err != nil {
			_ = os.RemoveAll(dir)
		}
	}()
	if err := os.Mkdir(filepath.Join(dir, "files"), 0o700); err != nil {
		return nil, unavailable("%v", err)
	}
	limit := s.MaxBytes
	if limit <= 0 {
		limit = DefaultMaxBytes
	}
	m = &Manifest{OperationID: op, CreatedAtMs: s.now().UnixMilli(), Services: append([]string{}, services...)}
	seen := map[string]bool{}
	for i, p := range paths {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p {
			return nil, unavailable("путь %q", p)
		}
		if seen[p] {
			continue
		}
		seen[p] = true
		st, lerr := os.Lstat(p)
		if errors.Is(lerr, os.ErrNotExist) {
			m.Files = append(m.Files, File{Path: p})
			continue
		}
		if lerr != nil {
			return nil, unavailable("%v", lerr)
		}
		if !st.Mode().IsRegular() {
			return nil, unavailable("%s: не обычный файл", p)
		}
		m.TotalBytes += st.Size()
		if m.TotalBytes > limit {
			return nil, unavailable("больше %d байт", limit)
		}
		f := File{Path: p, Existed: true, Mode: uint32(st.Mode().Perm()), Size: st.Size(), Copy: strconv.Itoa(i)}
		if sys, ok := st.Sys().(*syscall.Stat_t); ok {
			f.UID, f.GID = int(sys.Uid), int(sys.Gid)
		}
		sum, cerr := copyFile(p, filepath.Join(dir, "files", f.Copy), st.Size())
		if cerr != nil {
			return nil, unavailable("копия %s: %v", p, cerr)
		}
		f.SHA256 = sum
		m.Files = append(m.Files, f)
	}
	if err := fsutil.SyncDir(filepath.Join(dir, "files")); err != nil {
		return nil, unavailable("%v", err)
	}
	raw, _ := json.MarshalIndent(m, "", "  ")
	if err := fsutil.WriteFileAtomic(filepath.Join(dir, "manifest.json"), raw, 0o600, fsutil.Keep); err != nil {
		return nil, unavailable("манифест: %v", err)
	}
	if err := fsutil.SyncDir(s.Dir); err != nil {
		return nil, unavailable("%v", err)
	}
	return m, nil
}

// copyFile копирует ровно size байт (файл мог вырасти во время копии — тогда ошибка) и возвращает sha256.
func copyFile(src, dst string, size int64) (string, error) {
	in, err := os.Open(src)
	if err != nil {
		return "", err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(out, h), io.LimitReader(in, size+1))
	if err == nil && n != size {
		err = fmt.Errorf("размер изменился во время копии")
	}
	if err == nil {
		err = out.Sync()
	}
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Load читает манифест.
func (s *Store) Load(op string) (*Manifest, error) {
	dir, err := s.dir(op)
	if err != nil {
		return nil, err
	}
	raw, err := fsutil.ReadLimited(filepath.Join(dir, "manifest.json"), 4<<20)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	if m.OperationID != op {
		return nil, fmt.Errorf("манифест чужой операции")
	}
	return &m, nil
}

// Restore возвращает файлы точки op и сверяет sha256, права и владельцев. Любое расхождение — ErrFailed.
func (s *Store) Restore(op string) (*Manifest, error) {
	m, err := s.Load(op)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFailed, err)
	}
	dir, _ := s.dir(op)
	var errs []error
	for _, f := range m.Files {
		if err := restoreFile(dir, f); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", f.Path, err))
		}
	}
	if len(errs) > 0 {
		return m, fmt.Errorf("%w: %v", ErrFailed, errors.Join(errs...))
	}
	return m, nil
}

func restoreFile(dir string, f File) error {
	if !f.Existed {
		return fsutil.RemoveSync(f.Path)
	}
	src, err := os.Open(filepath.Join(dir, "files", f.Copy))
	if err != nil {
		return err
	}
	defer src.Close()
	err = fsutil.WriteAtomic(f.Path, os.FileMode(f.Mode), fsutil.Owner{UID: f.UID, GID: f.GID}, func(w io.Writer) error {
		_, err := io.Copy(w, src)
		return err
	})
	if err != nil {
		return err
	}
	return Matches(f)
}

// Matches сверяет файл на диске с записью манифеста.
func Matches(f File) error {
	st, err := os.Lstat(f.Path)
	if !f.Existed {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("файл не должен существовать")
	}
	if err != nil {
		return err
	}
	if uint32(st.Mode().Perm()) != f.Mode {
		return fmt.Errorf("права %o, ждали %o", st.Mode().Perm(), f.Mode)
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); ok && (int(sys.Uid) != f.UID || int(sys.Gid) != f.GID) {
		return fmt.Errorf("владелец %d:%d, ждали %d:%d", sys.Uid, sys.Gid, f.UID, f.GID)
	}
	sum, err := HashFile(f.Path)
	if err != nil {
		return err
	}
	if sum != f.SHA256 {
		return fmt.Errorf("sha256 не совпал")
	}
	return nil
}

// HashFile — шестнадцатеричный sha256 файла.
func HashFile(p string) (string, error) {
	in, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer in.Close()
	h := sha256.New()
	if _, err := io.Copy(h, in); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Delete удаляет точку.
func (s *Store) Delete(op string) error {
	dir, err := s.dir(op)
	if err != nil {
		return err
	}
	return os.RemoveAll(dir)
}

// Prune оставляет не больше MaxCount точек не старше MaxAge. keep — точки, которые удалять нельзя (ждут
// подтверждения или автооткатa).
func (s *Store) Prune(keep map[string]bool) error {
	ents, err := os.ReadDir(s.Dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	type pt struct {
		op string
		at int64
	}
	var pts []pt
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		m, err := s.Load(e.Name())
		if err != nil {
			// Точка без манифеста — недосозданная; её операция не выполнялась.
			if errors.Is(err, ErrNotFound) {
				_ = os.RemoveAll(filepath.Join(s.Dir, e.Name()))
			}
			continue
		}
		pts = append(pts, pt{m.OperationID, m.CreatedAtMs})
	}
	sort.Slice(pts, func(i, j int) bool { return pts[i].at > pts[j].at })
	maxAge, maxCount := s.MaxAge, s.MaxCount
	if maxAge <= 0 {
		maxAge = DefaultMaxAge
	}
	if maxCount <= 0 {
		maxCount = DefaultMaxCount
	}
	cutoff := s.now().Add(-maxAge).UnixMilli()
	for i, p := range pts {
		if keep[p.op] {
			continue
		}
		if i >= maxCount || p.at < cutoff {
			if err := s.Delete(p.op); err != nil {
				return err
			}
		}
	}
	return nil
}
