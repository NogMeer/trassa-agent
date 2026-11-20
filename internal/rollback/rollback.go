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
	// Dir — каталог: сохраняются только права и владелец (исправления прав, E10).
	Dir bool `json:"dir,omitempty"`
	// Special — биты setuid (04000), setgid (02000) и sticky (01000): их тоже возвращает откат.
	Special uint32 `json:"special,omitempty"`
}

func specialBits(m os.FileMode) uint32 {
	var b uint32
	if m&os.ModeSetuid != 0 {
		b |= 0o4000
	}
	if m&os.ModeSetgid != 0 {
		b |= 0o2000
	}
	if m&os.ModeSticky != 0 {
		b |= 0o1000
	}
	return b
}

// fullMode — права вместе с особыми битами для os.Chmod.
func fullMode(f File) os.FileMode {
	m := os.FileMode(f.Mode).Perm()
	if f.Special&0o4000 != 0 {
		m |= os.ModeSetuid
	}
	if f.Special&0o2000 != 0 {
		m |= os.ModeSetgid
	}
	if f.Special&0o1000 != 0 {
		m |= os.ModeSticky
	}
	return m
}

// Manifest — описание точки.
type Manifest struct {
	OperationID string   `json:"operation_id"`
	CreatedAtMs int64    `json:"created_at_ms"`
	Files       []File   `json:"files"`
	Services    []string `json:"services"`
	TotalBytes  int64    `json:"total_bytes"`
	State       State    `json:"state,omitempty"`
}

// State — состояние системы вне файлов, которое возвращает откат (исправления центра безопасности, E10):
// прежние значения параметров ядра, состояние служб и пакеты, которые поставила сама операция.
type State struct {
	// Sysctl — имя параметра (net.ipv4.tcp_syncookies) → прежнее значение.
	Sysctl map[string]string `json:"sysctl,omitempty"`
	Units  []UnitState       `json:"units,omitempty"`
	// Packages — поставлены операцией: откат их удаляет вместе с настройками.
	Packages []string `json:"packages,omitempty"`
	// DaemonReload — после возврата файлов перечитать юниты (генераторы, например sshd-socket-generator).
	DaemonReload bool `json:"daemon_reload,omitempty"`
	// NftFile — набор nftables Trassa: после возврата файлов загрузить его (`nft -f`), а если файла не стало —
	// снять таблицу inet trassa. Загруженные правила так совпадают с файлом.
	NftFile string `json:"nft_file,omitempty"`
	// Commands — команды после возврата файлов (последними): помощник приводит систему к возвращённым файлам
	// (например, `trassa-helper wireguard-sync <iface>`). Только абсолютный путь программы.
	Commands [][]string `json:"commands,omitempty"`
}

// UnitState — служба до операции.
type UnitState struct {
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
	Active  bool   `json:"active"`
}

// Empty — откат не трогает ничего, кроме файлов.
func (s State) Empty() bool {
	return len(s.Sysctl) == 0 && len(s.Units) == 0 && len(s.Packages) == 0 && !s.DaemonReload && s.NftFile == "" && len(s.Commands) == 0
}

// Store — каталог точек.
type Store struct {
	Dir      string
	MaxBytes int64
	MaxAge   time.Duration
	MaxCount int
	Now      func() time.Time
	// ProcSys — корень параметров ядра (/proc/sys); Exec — запуск systemctl и apt-get без оболочки. Нужны
	// только для точек с State.
	ProcSys string
	Exec    func(name string, args ...string) error
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
func (s *Store) Create(op string, paths, services []string) (*Manifest, error) {
	return s.CreateState(op, paths, services, State{})
}

// CreateState — точка отката с состоянием системы вне файлов.
func (s *Store) CreateState(op string, paths, services []string, state State) (m *Manifest, err error) {
	if !state.Empty() && s.Exec == nil {
		return nil, unavailable("откат состояния системы на этой сборке недоступен")
	}
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
	m = &Manifest{OperationID: op, CreatedAtMs: s.now().UnixMilli(), Services: append([]string{}, services...), State: state}
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
		if st.IsDir() {
			f := File{Path: p, Existed: true, Dir: true, Mode: uint32(st.Mode().Perm()), Special: specialBits(st.Mode())}
			if sys, ok := st.Sys().(*syscall.Stat_t); ok {
				f.UID, f.GID = int(sys.Uid), int(sys.Gid)
			}
			m.Files = append(m.Files, f)
			continue
		}
		if !st.Mode().IsRegular() {
			return nil, unavailable("%s: не обычный файл", p)
		}
		m.TotalBytes += st.Size()
		if m.TotalBytes > limit {
			return nil, unavailable("больше %d байт", limit)
		}
		f := File{Path: p, Existed: true, Mode: uint32(st.Mode().Perm()), Special: specialBits(st.Mode()), Size: st.Size(), Copy: strconv.Itoa(i)}
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
	// Сначала службы и пакеты операции (иначе служба держит файлы), потом файлы, потом параметры ядра.
	errs = append(errs, s.restoreUnits(m.State.Units)...)
	if len(m.State.Packages) > 0 {
		args := append([]string{"purge", "-y", "-q"}, m.State.Packages...)
		if err := s.Exec("apt-get", args...); err != nil {
			errs = append(errs, fmt.Errorf("apt-get purge %v: %w", m.State.Packages, err))
		}
	}
	for _, f := range m.Files {
		if err := restoreFile(dir, f); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", f.Path, err))
		}
	}
	if m.State.DaemonReload {
		if err := s.Exec("systemctl", "daemon-reload"); err != nil {
			errs = append(errs, fmt.Errorf("systemctl daemon-reload: %w", err))
		}
	}
	errs = append(errs, s.restoreSysctl(m.State.Sysctl)...)
	if f := m.State.NftFile; f != "" {
		if _, err := os.Stat(f); err == nil {
			if err := s.Exec("nft", "-f", f); err != nil {
				errs = append(errs, fmt.Errorf("nft -f %s: %w", f, err))
			}
		} else if s.Exec("nft", "list", "table", "inet", "trassa") == nil {
			if err := s.Exec("nft", "delete", "table", "inet", "trassa"); err != nil {
				errs = append(errs, fmt.Errorf("nft delete table inet trassa: %w", err))
			}
		}
	}
	for _, c := range m.State.Commands {
		if len(c) == 0 || !filepath.IsAbs(c[0]) {
			errs = append(errs, fmt.Errorf("команда %v", c))
			continue
		}
		if err := s.Exec(c[0], c[1:]...); err != nil {
			errs = append(errs, fmt.Errorf("%v: %w", c, err))
		}
	}
	if len(errs) > 0 {
		return m, fmt.Errorf("%w: %v", ErrFailed, errors.Join(errs...))
	}
	return m, nil
}

func (s *Store) restoreUnits(units []UnitState) []error {
	var errs []error
	for _, u := range units {
		if !validUnit(u.Name) {
			errs = append(errs, fmt.Errorf("служба %q", u.Name))
			continue
		}
		en, act := "disable", "stop"
		if u.Enabled {
			en = "enable"
		}
		if u.Active {
			act = "start"
		}
		for _, a := range []string{en, act} {
			if err := s.Exec("systemctl", a, "--", u.Name); err != nil {
				errs = append(errs, fmt.Errorf("systemctl %s %s: %w", a, u.Name, err))
			}
		}
	}
	return errs
}

func (s *Store) restoreSysctl(vals map[string]string) []error {
	var errs []error
	names := make([]string, 0, len(vals))
	for n := range vals {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		p, ok := SysctlPath(s.ProcSys, n)
		if !ok {
			errs = append(errs, fmt.Errorf("параметр %q", n))
			continue
		}
		// Значение не менялось (применение упало раньше) — писать нечего.
		if cur, err := os.ReadFile(p); err == nil && strings.TrimSpace(string(cur)) == vals[n] {
			continue
		}
		if err := os.WriteFile(p, []byte(vals[n]+"\n"), 0o644); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", n, err))
			continue
		}
		got, err := os.ReadFile(p)
		if err != nil || strings.TrimSpace(string(got)) != vals[n] {
			errs = append(errs, fmt.Errorf("%s: после возврата %q, ждали %q", n, strings.TrimSpace(string(got)), vals[n]))
		}
	}
	return errs
}

// SysctlPath — файл параметра ядра под root (обычно /proc/sys). Имя — точки и [a-z0-9_-]: без «..» и «/».
func SysctlPath(root, name string) (string, bool) {
	if root == "" {
		root = "/proc/sys"
	}
	if name == "" || strings.Contains(name, "..") {
		return "", false
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.') {
			return "", false
		}
	}
	return filepath.Join(root, strings.ReplaceAll(name, ".", "/")), true
}

func validUnit(n string) bool {
	if n == "" || strings.HasPrefix(n, "-") || len(n) > 256 {
		return false
	}
	for _, c := range n {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("@._:-\\", c)) {
			return false
		}
	}
	return true
}

func restoreFile(dir string, f File) error {
	// Ни удаление, ни запись, ни права не идут по ссылкам на пути: каталог над файлом мог стать ссылкой (домашний
	// каталог пользователя), и root не должен писать или менять права в чужом месте.
	if !f.Existed {
		return fsutil.RemoveNoFollow(f.Path)
	}
	if f.Dir {
		if err := fsutil.ChmodChownNoFollow(f.Path, fsutil.FileID{}, fullMode(f), f.UID, f.GID); err != nil {
			return err
		}
		return Matches(f)
	}
	src, err := os.Open(filepath.Join(dir, "files", f.Copy))
	if err != nil {
		return err
	}
	defer src.Close()
	err = fsutil.WriteAtomicNoFollow(f.Path, fullMode(f), fsutil.Owner{UID: f.UID, GID: f.GID}, func(w io.Writer) error {
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
	if uint32(st.Mode().Perm()) != f.Mode || specialBits(st.Mode()) != f.Special {
		return fmt.Errorf("права %o (особые %o), ждали %o (%o)", st.Mode().Perm(), specialBits(st.Mode()), f.Mode, f.Special)
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); ok && (int(sys.Uid) != f.UID || int(sys.Gid) != f.GID) {
		return fmt.Errorf("владелец %d:%d, ждали %d:%d", sys.Uid, sys.Gid, f.UID, f.GID)
	}
	if f.Dir {
		if !st.IsDir() {
			return fmt.Errorf("ждали каталог")
		}
		return nil
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
