// SPDX-License-Identifier: AGPL-3.0-only

package fsinspect

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"unicode/utf8"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/redact"
)

// MaxConfigBytes — предел файла config.read.
const MaxConfigBytes = 64 << 10

var (
	// Шаблоны (раздел 6 E20): весь /etc/nginx, службы systemd в /etc/systemd/system (без подкаталогов),
	// daemon.json Docker и compose приложения Trassa (единственное исключение из запрета /var/lib/trassa: секреты
	// деплоя туда не пишутся, они идут окружением процесса compose).
	configAllowed = []*regexp.Regexp{
		regexp.MustCompile(`^/etc/nginx/.+$`),
		regexp.MustCompile(`^/etc/systemd/system/[^/]+\.service$`),
		regexp.MustCompile(`^/etc/docker/daemon\.json$`),
		regexp.MustCompile(`^/var/lib/trassa/apps/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/compose/compose\.json$`),
	}
	// Запреты поверх шаблонов: ключи и сертификаты, пароли, .env, службы Trassa.
	configDenied = regexp.MustCompile(`(?i)(\.(key|pem|p12|pfx|jks|keystore|der|p8|csr)$|(^|/)private(/|$)|(^|/)\.?htpasswd|(^|/)\.env|(^|/)[^/]*passw|(^|/)[^/]*secret|(^|/)trassa[^/]*\.service$)`)
)

// ConfigPathAllowed — путь подходит под шаблон и не под запрет.
func ConfigPathAllowed(p string) bool {
	if !cleanAbs(p) || configDenied.MatchString(p) {
		return false
	}
	for _, re := range configAllowed {
		if re.MatchString(p) {
			return true
		}
	}
	return false
}

// ValidateConfigRead — проверка параметров до запуска.
func ValidateConfigRead(p *agentv1.ConfigReadParams) error {
	if !ConfigPathAllowed(p.GetPath()) {
		return fmt.Errorf("%w: %s", ErrConfigPathForbidden, p.GetPath())
	}
	return nil
}

// ConfigRead — файл после ссылок тоже должен подходить (sites-enabled → sites-available можно, ссылка на
// /etc/shadow — нет). Путь сверяется по открытому дескриптору (/proc/self/fd), поэтому подмена ссылки между
// проверкой и чтением ничего не даёт; FIFO не вешает помощник (O_NONBLOCK).
func (e *Env) ConfigRead(p *agentv1.ConfigReadParams) (*agentv1.ConfigReadResult, error) {
	if err := ValidateConfigRead(p); err != nil {
		return nil, err
	}
	// До открытия: путь после ссылок тоже в списке — иначе root открыл бы, например, /dev/watchdog или чужой pty
	// (открытие устройства уже действие). После открытия — та же сверка по дескриптору против подмены.
	pre, err := e.resolvedPath(p.GetPath())
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%w: %s", ErrConfigNotFound, p.GetPath())
	}
	if err != nil {
		return nil, err
	}
	if !ConfigPathAllowed(pre) {
		return nil, fmt.Errorf("%w: %s ведёт в %s", ErrConfigPathForbidden, p.GetPath(), printable(pre))
	}
	f, err := os.OpenFile(e.real(p.GetPath()), os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOCTTY, 0)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%w: %s", ErrConfigNotFound, p.GetPath())
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	resolved, err := e.openedPath(f, p.GetPath())
	if err != nil {
		return nil, err
	}
	if !ConfigPathAllowed(resolved) {
		return nil, fmt.Errorf("%w: %s ведёт в %s", ErrConfigPathForbidden, p.GetPath(), printable(resolved))
	}
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %s — не обычный файл", ErrConfigNotText, p.GetPath())
	}
	if fi.Size() > MaxConfigBytes {
		return nil, fmt.Errorf("%w: %d байт, предел %d", ErrConfigTooLarge, fi.Size(), MaxConfigBytes)
	}
	raw, err := io.ReadAll(io.LimitReader(f, MaxConfigBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > MaxConfigBytes {
		return nil, fmt.Errorf("%w: больше %d байт", ErrConfigTooLarge, MaxConfigBytes)
	}
	if bytes.IndexByte(raw, 0) >= 0 || !utf8.Valid(raw) {
		return nil, fmt.Errorf("%w: %s", ErrConfigNotText, p.GetPath())
	}
	text := string(raw)
	clean := redact.Text(text)
	n := strings.Count(clean, redact.Mask) - strings.Count(text, redact.Mask)
	if n < 0 {
		n = 0
	}
	return &agentv1.ConfigReadResult{Path: p.GetPath(), ResolvedPath: resolved, Content: clean, SizeBytes: uint64(len(raw)),
		Redacted: uint32(n), ModifiedAtMs: fi.ModTime().UnixMilli()}, nil
}

// resolvedPath — путь после ссылок относительно Root (до открытия).
func (e *Env) resolvedPath(asked string) (string, error) {
	real, err := filepath.EvalSymlinks(e.real(asked))
	if err != nil {
		return "", err
	}
	return e.rel(real, asked)
}

func (e *Env) rel(real, asked string) (string, error) {
	base, err := filepath.EvalSymlinks(e.Root)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(base, real)
	if err != nil || rel == ".." || strings.HasPrefix(rel, "../") {
		return "", fmt.Errorf("%w: %s вне корня", ErrConfigPathForbidden, asked)
	}
	return path.Join("/", filepath.ToSlash(rel)), nil
}

// openedPath — путь открытого файла относительно Root: на Linux по /proc/self/fd, иначе (тесты на macOS) — по
// ссылкам пути.
func (e *Env) openedPath(f *os.File, asked string) (string, error) {
	real, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(int(f.Fd())))
	if err != nil {
		real, err = filepath.EvalSymlinks(e.real(asked))
		if err != nil {
			return "", err
		}
	}
	return e.rel(real, asked)
}
