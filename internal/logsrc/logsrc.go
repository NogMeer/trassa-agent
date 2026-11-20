// SPDX-License-Identifier: AGPL-3.0-only

// Package logsrc — чтение журналов в помощнике (E08-T15): journald через journalctl без оболочки и файлы
// внутри /var/log/ без следования по ссылкам. Записи уходят агенту уже без секретов (redact): сетевой процесс
// не видит ни сырых журналов, ни путей вне /var/log/.
package logsrc

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"golang.org/x/sys/unix"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/ops"
	"github.com/NogMeer/trassa-agent/internal/redact"
)

// Пределы записи и пачки (E08, разделы 4 и 6).
const (
	MaxMessage    = 8 << 10
	maxField      = 200
	MaxRecords    = 500
	MaxChunkBytes = 256 << 10
	MaxReadBytes  = 512 << 10
	// fileTail — сколько байт с конца файла читает logs.read.
	fileTail = 4 << 20
)

// Причины, по которым источник не открылся (LogSourceStatus.reason).
const (
	ReasonPathForbidden = "PATH_FORBIDDEN"
	ReasonNotFound      = "NOT_FOUND"
	ReasonNotRegular    = "NOT_REGULAR"
	ReasonUnsupported   = "SOURCE_UNSUPPORTED"
	ReasonDuplicate     = "DUPLICATE"
)

// Reader читает журналы. Root — корень, внутри которого лежит /var/log (в тестах — временный каталог);
// Journal запускает journalctl с аргументами и отдаёт его вывод.
type Reader struct {
	Root    string
	Journal func(ctx context.Context, args []string) (io.ReadCloser, func() error, error)
	Now     func() time.Time
}

// New — читатель настоящей системы.
func New() *Reader { return &Reader{Root: "/", Journal: journalctl, Now: time.Now} }

func journalctl(ctx context.Context, args []string) (io.ReadCloser, func() error, error) {
	cmd := exec.CommandContext(ctx, "journalctl", args...)
	cmd.Env = []string{"LANG=C.UTF-8", "SYSTEMD_PAGER=", "SYSTEMD_COLORS=0"}
	cmd.Stderr = io.Discard
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, nil, err
	}
	return out, func() error {
		_ = cmd.Process.Kill() // прочитали сколько нужно: остальное не нужно
		_ = cmd.Wait()
		return nil
	}, nil
}

// Key — ключ источника в позициях и при поиске повторов.
func Key(s *agentv1.LogSource) string { return strconv.Itoa(int(s.GetKind())) + ":" + s.GetName() }

// ---------- Файлы ----------

// OpenFile открывает файл журнала: путь проверен по схеме (ops.ValidLogPath), каждый компонент открывается
// openat с O_NOFOLLOW — ни одна ссылка по пути не проходится, выйти из /var/log нельзя. Только обычный файл.
func (r *Reader) OpenFile(p string) (*os.File, string, error) {
	if err := ops.ValidLogPath(p); err != nil {
		return nil, ReasonPathForbidden, err
	}
	dir, err := unix.Open(strings.TrimSuffix(r.Root, "/")+"/var/log", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ReasonNotFound, err
	}
	parts := strings.Split(strings.TrimPrefix(p, ops.LogDir), "/")
	for i, c := range parts {
		flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC
		if i < len(parts)-1 {
			flags |= unix.O_DIRECTORY
		} else {
			flags |= unix.O_NONBLOCK // FIFO не повесит чтение; обычный файл флаг не замечает
		}
		fd, err := unix.Openat(dir, c, flags, 0)
		unix.Close(dir)
		if err != nil {
			switch {
			case errors.Is(err, unix.ELOOP), errors.Is(err, unix.ENOTDIR), errors.Is(err, unix.EMLINK):
				return nil, ReasonPathForbidden, fmt.Errorf("%s: ссылка или не каталог по пути", p)
			case errors.Is(err, unix.ENOENT):
				return nil, ReasonNotFound, err
			default:
				return nil, ReasonNotFound, err
			}
		}
		dir = fd
	}
	f := os.NewFile(uintptr(dir), p)
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		f.Close()
		return nil, ReasonNotRegular, fmt.Errorf("%s: не обычный файл", p)
	}
	return f, "", nil
}

func inode(fi os.FileInfo) uint64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Ino)
	}
	return 0
}

// filePos — позиция в файле «inode:смещение».
func filePos(ino uint64, off int64) string {
	return strconv.FormatUint(ino, 10) + ":" + strconv.FormatInt(off, 10)
}

func parseFilePos(s string) (uint64, int64, bool) {
	a, b, ok := strings.Cut(s, ":")
	if !ok {
		return 0, 0, false
	}
	ino, err1 := strconv.ParseUint(a, 10, 64)
	off, err2 := strconv.ParseInt(b, 10, 64)
	return ino, off, err1 == nil && err2 == nil && off >= 0
}

// fileLevel — уровень строки файла по словам: точного уровня у произвольного файла нет.
func fileLevel(line string) agentv1.LogLevel {
	l := strings.ToLower(line)
	switch {
	case strings.Contains(l, "error"), strings.Contains(l, "fatal"), strings.Contains(l, "crit"), strings.Contains(l, "panic"),
		strings.Contains(l, "emerg"), strings.Contains(l, "alert"):
		return agentv1.LogLevel_LOG_LEVEL_ERROR
	case strings.Contains(l, "warn"):
		return agentv1.LogLevel_LOG_LEVEL_WARN
	case strings.Contains(l, "debug"):
		return agentv1.LogLevel_LOG_LEVEL_DEBUG
	}
	return agentv1.LogLevel_LOG_LEVEL_INFO
}

// pollFile читает новые полные строки с позиции pos. Пустая позиция — начать с конца файла (журнал отправляется
// с момента подписки). Файл сменился (ротация) или стал короче — чтение с начала нового файла.
func (r *Reader) pollFile(src *agentv1.LogSource, pos string, min agentv1.LogLevel, maxRec, maxBytes int) ([]*agentv1.LogRecord, string, bool, error) {
	f, _, err := r.OpenFile(src.GetName())
	if err != nil {
		return nil, pos, false, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, pos, false, err
	}
	ino := inode(fi)
	pino, off, ok := parseFilePos(pos)
	if !ok {
		return nil, filePos(ino, fi.Size()), false, nil
	}
	if pino != ino || off > fi.Size() {
		off = 0
	}
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		return nil, pos, false, err
	}
	br := bufio.NewReaderSize(io.LimitReader(f, int64(maxBytes)+MaxMessage), 64<<10)
	var out []*agentv1.LogRecord
	size := 0
	now := r.Now().UnixMilli()
	for len(out) < maxRec && size < maxBytes {
		line, err := br.ReadString('\n')
		if err != nil {
			// Неполная строка остаётся до следующего раза; слишком длинная уходит обрезанной.
			if len(line) < MaxMessage {
				break
			}
		}
		start := off
		off += int64(len(line))
		text := strings.TrimRight(line, "\r\n")
		if text == "" {
			continue
		}
		lvl := fileLevel(text)
		if !passes(lvl, min) {
			continue
		}
		rec := &agentv1.LogRecord{TimeMs: now, Level: lvl, Source: src, Message: clean(text), Cursor: filePos(ino, start)}
		out = append(out, rec)
		size += recSize(rec)
	}
	more := len(out) >= maxRec || size >= maxBytes
	return out, filePos(ino, off), more, nil
}

// readFile — последние lines строк файла с отбором grep (logs.read).
func (r *Reader) readFile(src *agentv1.LogSource, lines int, grep string) ([]*agentv1.LogRecord, bool, error) {
	f, _, err := r.OpenFile(src.GetName())
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, false, err
	}
	start := max(fi.Size()-fileTail, 0)
	b, err := io.ReadAll(io.NewSectionReader(f, start, fi.Size()-start))
	if err != nil {
		return nil, false, err
	}
	all := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if start > 0 && len(all) > 0 {
		all = all[1:] // первая строка начата до окна
	}
	var keep []string
	for i := len(all) - 1; i >= 0 && len(keep) < lines; i-- {
		if all[i] != "" && (grep == "" || strings.Contains(all[i], grep)) {
			keep = append(keep, all[i])
		}
	}
	now := r.Now().UnixMilli()
	out := make([]*agentv1.LogRecord, 0, len(keep))
	for i := len(keep) - 1; i >= 0; i-- {
		out = append(out, &agentv1.LogRecord{TimeMs: now, Level: fileLevel(keep[i]), Source: src, Message: clean(keep[i])})
	}
	return out, false, nil
}

// ---------- journald ----------

// journalArgs — отбор journalctl для источника. Имена проверены схемой (без ведущего «-») и идут отдельными
// аргументами: оболочки нет.
func journalArgs(src *agentv1.LogSource, min agentv1.LogLevel) ([]string, error) {
	args := []string{"--output=json", "--no-pager", "--quiet", "--priority=0.." + strconv.Itoa(priority(min))}
	switch src.GetKind() {
	case agentv1.LogSourceKind_LOG_SOURCE_KIND_SYSTEM:
	case agentv1.LogSourceKind_LOG_SOURCE_KIND_SSH:
		args = append(args, "--unit=ssh.service", "--unit=sshd.service")
	case agentv1.LogSourceKind_LOG_SOURCE_KIND_UNIT:
		args = append(args, "--unit="+src.GetName())
	default:
		return nil, errors.New("не journald")
	}
	return args, nil
}

// priority — верхняя граница PRIORITY для уровня: error 0–3, warn 4, info 5–6, debug 7. Без уровня — info.
func priority(l agentv1.LogLevel) int {
	switch l {
	case agentv1.LogLevel_LOG_LEVEL_ERROR:
		return 3
	case agentv1.LogLevel_LOG_LEVEL_WARN:
		return 4
	case agentv1.LogLevel_LOG_LEVEL_DEBUG:
		return 7
	}
	return 6
}

func journalLevel(p string) agentv1.LogLevel {
	n, err := strconv.Atoi(p)
	switch {
	case err != nil:
		return agentv1.LogLevel_LOG_LEVEL_INFO
	case n <= 3:
		return agentv1.LogLevel_LOG_LEVEL_ERROR
	case n == 4:
		return agentv1.LogLevel_LOG_LEVEL_WARN
	case n == 7:
		return agentv1.LogLevel_LOG_LEVEL_DEBUG
	}
	return agentv1.LogLevel_LOG_LEVEL_INFO
}

// journalEntry — нужные поля записи journalctl --output=json. MESSAGE бывает строкой или массивом байтов.
type journalEntry struct {
	Cursor     string          `json:"__CURSOR"`
	Realtime   string          `json:"__REALTIME_TIMESTAMP"`
	Priority   string          `json:"PRIORITY"`
	Message    json.RawMessage `json:"MESSAGE"`
	Unit       string          `json:"_SYSTEMD_UNIT"`
	Identifier string          `json:"SYSLOG_IDENTIFIER"`
	PID        string          `json:"_PID"`
	Container  string          `json:"CONTAINER_NAME"`
}

func (j journalEntry) message() string {
	var s string
	if json.Unmarshal(j.Message, &s) == nil {
		return s
	}
	var b []byte
	var nums []int
	if json.Unmarshal(j.Message, &nums) == nil {
		for _, n := range nums {
			b = append(b, byte(n))
		}
	}
	return string(b)
}

func (r *Reader) journal(ctx context.Context, src *agentv1.LogSource, extra []string, min agentv1.LogLevel, maxRec, maxBytes int, grep string) ([]*agentv1.LogRecord, string, bool, error) {
	args, err := journalArgs(src, min)
	if err != nil {
		return nil, "", false, err
	}
	args = append(args, extra...)
	if grep != "" {
		args = append(args, "--grep="+regexpQuote(grep), "--case-sensitive=true")
	}
	jctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	out, done, err := r.Journal(jctx, args)
	if err != nil {
		return nil, "", false, fmt.Errorf("journalctl: %w", err)
	}
	defer done()
	sc := bufio.NewScanner(out)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	var recs []*agentv1.LogRecord
	last := ""
	size := 0
	for sc.Scan() && len(recs) < maxRec && size < maxBytes {
		var e journalEntry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil || e.Cursor == "" {
			continue
		}
		last = e.Cursor
		us, _ := strconv.ParseInt(e.Realtime, 10, 64)
		fields := map[string]string{}
		for k, v := range map[string]string{"unit": e.Unit, "identifier": e.Identifier, "pid": e.PID, "container": e.Container} {
			if v != "" {
				fields[k] = clip(redact.String(v), maxField)
			}
		}
		rec := &agentv1.LogRecord{
			TimeMs: us / 1000, Level: journalLevel(e.Priority), Source: src, Message: clean(e.message()),
			Fields: fields, Cursor: e.Cursor,
		}
		recs = append(recs, rec)
		size += recSize(rec)
	}
	if err := sc.Err(); err != nil && len(recs) == 0 {
		return nil, "", false, fmt.Errorf("journalctl: %w", err)
	}
	more := len(recs) >= maxRec || size >= maxBytes
	return recs, last, more, nil
}

// regexpQuote — grep у logs.read подстрока, а journalctl --grep принимает PCRE: экранируем всё.
func regexpQuote(s string) string {
	var b strings.Builder
	for _, r := range s {
		if strings.ContainsRune(`\.+*?()|[]{}^$#&-~`, r) {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// ---------- Общее ----------

func passes(l, min agentv1.LogLevel) bool {
	if min == agentv1.LogLevel_LOG_LEVEL_UNSPECIFIED {
		min = agentv1.LogLevel_LOG_LEVEL_INFO
	}
	return l <= min
}

// clean — секреты вычищены, текст в UTF-8, не длиннее 8 КБ.
func clean(s string) string { return clip(redact.String(strings.ToValidUTF8(s, "�")), MaxMessage) }

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	s = s[:n]
	for !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}

func recSize(r *agentv1.LogRecord) int {
	n := len(r.GetMessage()) + len(r.GetCursor()) + 32
	for k, v := range r.GetFields() {
		n += len(k) + len(v)
	}
	return n
}

var errUnsupported = errors.New("источник не поддерживается")

// Poll — новые записи подписки с позиций pos. Возвращает записи (не больше MaxRecords и MaxChunkBytes вместе),
// новые позиции (только для источников подписки) и more — есть ещё. Источник с ошибкой пропускается до
// следующего раза, его позиция не меняется; ошибки — в errs.
func (r *Reader) Poll(ctx context.Context, sub *Subscription, pos map[string]string) ([]*agentv1.LogRecord, map[string]string, bool, []error) {
	next := map[string]string{}
	var all []*agentv1.LogRecord
	var errs []error
	more := false
	size := 0
	for _, src := range sub.Sources {
		k := Key(src)
		p, had := pos[k]
		next[k] = p
		leftRec, leftBytes := MaxRecords-len(all), MaxChunkBytes-size
		if leftRec <= 0 || leftBytes <= 0 {
			more = true
			continue
		}
		var recs []*agentv1.LogRecord
		var np string
		var m bool
		var err error
		switch src.GetKind() {
		case agentv1.LogSourceKind_LOG_SOURCE_KIND_FILE:
			if p == "" {
				p = sub.Start[k]
			}
			recs, np, m, err = r.pollFile(src, p, sub.MinLevel, leftRec, leftBytes)
		case agentv1.LogSourceKind_LOG_SOURCE_KIND_SYSTEM, agentv1.LogSourceKind_LOG_SOURCE_KIND_SSH, agentv1.LogSourceKind_LOG_SOURCE_KIND_UNIT:
			var extra []string
			if had && p != "" {
				extra = []string{"--after-cursor=" + p}
			} else {
				// Первый опрос: журнал с момента подписки, а не вся история.
				extra = []string{"--since=@" + strconv.FormatInt(sub.CreatedAtMs/1000, 10)}
			}
			recs, np, m, err = r.journal(ctx, src, extra, sub.MinLevel, leftRec, leftBytes, "")
			if np == "" {
				np = p
			}
		default:
			err = errUnsupported
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", k, err))
			continue
		}
		next[k] = np
		all = append(all, recs...)
		for _, x := range recs {
			size += recSize(x)
		}
		more = more || m
	}
	return all, next, more, errs
}

// Read — logs.read: последние lines записей источника с отбором grep, не больше MaxReadBytes.
func (r *Reader) Read(ctx context.Context, src *agentv1.LogSource, lines int, grep string) (*agentv1.LogsReadResult, error) {
	var recs []*agentv1.LogRecord
	var err error
	switch src.GetKind() {
	case agentv1.LogSourceKind_LOG_SOURCE_KIND_FILE:
		recs, _, err = r.readFile(src, lines, grep)
	case agentv1.LogSourceKind_LOG_SOURCE_KIND_SYSTEM, agentv1.LogSourceKind_LOG_SOURCE_KIND_SSH, agentv1.LogSourceKind_LOG_SOURCE_KIND_UNIT:
		recs, _, _, err = r.journal(ctx, src, []string{"--lines=" + strconv.Itoa(lines)}, agentv1.LogLevel_LOG_LEVEL_DEBUG, lines, MaxReadBytes*2, grep)
	default:
		return nil, errUnsupported
	}
	if err != nil {
		return nil, err
	}
	res := &agentv1.LogsReadResult{}
	size := 0
	// С конца: при обрезке по размеру остаются самые свежие строки.
	for i := len(recs) - 1; i >= 0; i-- {
		size += recSize(recs[i])
		if size > MaxReadBytes {
			res.Truncated = true
			recs = recs[i+1:]
			break
		}
	}
	res.Records = recs
	return res, nil
}

// Subscription — действующая подписка (operation_id logs.subscribe, когда создана, что и с какого уровня).
type Subscription struct {
	ID          string
	CreatedAtMs int64
	MinLevel    agentv1.LogLevel
	Sources     []*agentv1.LogSource
	// Start — позиции файлов в момент подписки: строки, дописанные до первого опроса, не теряются.
	Start map[string]string
}

// Open проверяет источники подписки: повторы, неподдерживаемые и недоступные файлы получают причину;
// в подписку попадают только открывшиеся. start — позиции открывшихся файлов (конец файла сейчас).
func (r *Reader) Open(sources []*agentv1.LogSource) ([]*agentv1.LogSourceStatus, []*agentv1.LogSource, map[string]string) {
	start := map[string]string{}
	seen := map[string]bool{}
	var st []*agentv1.LogSourceStatus
	var ok []*agentv1.LogSource
	for _, s := range sources {
		k := Key(s)
		res := &agentv1.LogSourceStatus{Source: s}
		switch {
		case seen[k]:
			res.Reason = ReasonDuplicate
		case s.GetKind() == agentv1.LogSourceKind_LOG_SOURCE_KIND_DOCKER:
			res.Reason = ReasonUnsupported
		case s.GetKind() == agentv1.LogSourceKind_LOG_SOURCE_KIND_FILE:
			f, reason, err := r.OpenFile(s.GetName())
			if err != nil {
				res.Reason = reason
				break
			}
			if fi, err := f.Stat(); err == nil {
				start[k] = filePos(inode(fi), fi.Size())
			}
			f.Close()
			res.Opened = true
		default:
			res.Opened = true
		}
		seen[k] = true
		st = append(st, res)
		if res.Opened {
			ok = append(ok, s)
		}
	}
	return st, ok, start
}
