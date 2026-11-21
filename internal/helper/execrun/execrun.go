// SPDX-License-Identifier: AGPL-3.0-only

// Package execrun — исполнение exec.run (E20-T4): проверка параметров и запуск команды во временной службе systemd.
//
// Без оболочки: argv запускается напрямую (systemd делает execve), поэтому конвейеров, подстановок, перенаправлений
// и шаблонов нет. Программа ищется в фиксированном PATH, ссылки раскрываются, файл и каталоги на пути к нему —
// root и без записи для группы и остальных (иначе локальный пользователь подменил бы бинарник между
// подтверждением и запуском), запускается по полному пути. Окружение фиксированное, из запроса не берётся.
// Служба даёт пользователя run_as, каталог cwd и свою группу управления (cgroup): по таймауту останавливается вся
// группа процессов, включая ушедшие в setsid. Каталоги Trassa в службе недоступны (InaccessiblePaths).
package execrun

import (
	"bufio"
	"context"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/helper/execpolicy"
	"github.com/NogMeer/trassa-agent/internal/redact"
)

// Коды отказа.
const (
	CodeDisabled    = "EXEC_DISABLED_ON_SERVER"
	CodeDenied      = "EXEC_DENIED"
	CodeUserInvalid = "EXEC_USER_INVALID"
	CodeCwdInvalid  = "EXEC_CWD_INVALID"
	CodeTimeout     = "EXEC_TIMEOUT"
	CodeFailed      = "EXEC_FAILED"
	CodeUnavailable = "EXEC_UNAVAILABLE"
)

// Пределы параметров (раздел 6 E20).
const (
	MaxTimeoutSec = 300
	MaxOutput     = 262144
	maxCwd        = 512
)

var (
	ErrUserInvalid = errors.New(CodeUserInvalid)
	ErrCwdInvalid  = errors.New(CodeCwdInvalid)
	ErrUnavailable = errors.New(CodeUnavailable)
	// ErrProgramInvalid — программы нет или её файл может подменить не root (EXEC_DENIED с этим кодом).
	ErrProgramInvalid = errors.New("EXEC_PROGRAM_INVALID")
	userRe            = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
	// Каталоги Trassa: ни каталогом запуска, ни внутри службы.
	trassaDirs = []string{"/etc/trassa", "/var/lib/trassa", "/run/trassa", "/var/cache/trassa", "/usr/local/lib/trassa", "/opt/trassa"}
	// secretPaths — недоступны в службе всегда: запрет по словам не видит «grep -r root /etc» или
	// «tar -C /etc shadow», а это ограничение исполняет ядро.
	secretPaths = []string{"/etc/shadow", "/etc/gshadow", "/etc/shadow-", "/etc/gshadow-", "/etc/ssl/private",
		"/etc/ssh/ssh_host_rsa_key", "/etc/ssh/ssh_host_ecdsa_key", "/etc/ssh/ssh_host_ed25519_key",
		"/etc/ssh/ssh_host_dsa_key", "/etc/letsencrypt/keys", "/etc/letsencrypt/archive", "/root/.ssh",
		"/etc/ppp/chap-secrets", "/etc/ppp/pap-secrets"}
)

// Validate — схема параметров (проверка 6): форма argv и пределы. Запреты R28 — Check, у обработчика после флага.
func Validate(p *agentv1.ExecRunParams) error {
	if p.GetCommand() != "" {
		return errors.New("command не принимается: программа и аргументы — в argv")
	}
	if v := execpolicy.CheckShape(p.GetArgv()); !v.Allowed {
		return fmt.Errorf("argv: %s", v.Detail)
	}
	if p.GetTimeoutSec() < 1 || p.GetTimeoutSec() > MaxTimeoutSec {
		return errors.New("timeout_sec: 1–300")
	}
	if p.GetMaxOutputBytes() < 1 || p.GetMaxOutputBytes() > MaxOutput {
		return errors.New("max_output_bytes: 1–262144")
	}
	if err := checkUserName(runAs(p)); err != nil {
		return err
	}
	return checkCwdName(cwd(p))
}

func runAs(p *agentv1.ExecRunParams) string {
	if p.GetRunAs() == "" {
		return "root"
	}
	return p.GetRunAs()
}

func cwd(p *agentv1.ExecRunParams) string {
	if p.GetCwd() == "" {
		return "/"
	}
	return p.GetCwd()
}

func checkUserName(u string) error {
	if !userRe.MatchString(u) || strings.HasPrefix(u, "trassa") {
		return fmt.Errorf("%w: run_as", ErrUserInvalid)
	}
	return nil
}

func checkCwdName(d string) error {
	if len(d) > maxCwd || !strings.HasPrefix(d, "/") || path.Clean(d) != d || !utf8.ValidString(d) {
		return fmt.Errorf("%w: cwd — абсолютный путь без «..»", ErrCwdInvalid)
	}
	for _, r := range d {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%w: cwd", ErrCwdInvalid)
		}
	}
	if underTrassa(d) {
		return fmt.Errorf("%w: каталоги Trassa", ErrCwdInvalid)
	}
	return nil
}

func underTrassa(d string) bool {
	for _, t := range trassaDirs {
		if d == t || strings.HasPrefix(d, t+"/") {
			return true
		}
	}
	return false
}

// SearchPath — где ищется программа по имени; /usr/local не входит: там нет файлов пакетов.
var SearchPath = []string{"/usr/sbin", "/usr/bin", "/sbin", "/bin"}

// packagedDirs — где может лежать программа после ссылок.
var packagedDirs = []string{"/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/"}

// Program — файл программы: найден в SearchPath (или абсолютный путь), ссылки раскрыты, обычный исполняемый
// файл; он и все каталоги до корня — root и без записи для группы и остальных; лежит в /usr/bin, /usr/sbin, /bin
// или /sbin и совпадает по md5 с файлом пакета дистрибутива (/var/lib/dpkg/info/*.md5sums). Последнее закрывает
// переименование: копия bash под другим именем или поверх /usr/bin/ls — не файл пакета, и запрет по имени не
// обойти.
func Program(root, name string) (string, error) {
	if root == "" {
		root = "/"
	}
	base, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", err
	}
	cands := []string{name}
	if !strings.HasPrefix(name, "/") {
		cands = cands[:0]
		for _, d := range SearchPath {
			cands = append(cands, path.Join(d, name))
		}
	}
	for _, c := range cands {
		real, err := filepath.EvalSymlinks(filepath.Join(root, c))
		if err != nil {
			continue
		}
		rel, err := filepath.Rel(base, real)
		if err != nil || rel == ".." || strings.HasPrefix(rel, "../") {
			return "", fmt.Errorf("%w: %s вне корня", ErrProgramInvalid, c)
		}
		vp := path.Join("/", filepath.ToSlash(rel))
		if underTrassa(vp) {
			return "", fmt.Errorf("%w: программа Trassa", ErrProgramInvalid)
		}
		if err := rootOwned(base, real); err != nil {
			return "", fmt.Errorf("%w: %s: %v", ErrProgramInvalid, vp, err)
		}
		if err := packaged(base, vp, real); err != nil {
			return "", fmt.Errorf("%w: %s: %v", ErrProgramInvalid, vp, err)
		}
		return vp, nil
	}
	return "", fmt.Errorf("%w: %s не найдена", ErrProgramInvalid, name)
}

// packaged — vp в каталоге программ, есть в md5sums пакета и совпадает с ним.
func packaged(base, vp, real string) error {
	ok := false
	for _, d := range packagedDirs {
		if strings.HasPrefix(vp, d) && !strings.Contains(vp[len(d):], "/") {
			ok = true
		}
	}
	if !ok {
		return errors.New("не в /usr/bin, /usr/sbin, /bin, /sbin")
	}
	rel := strings.TrimPrefix(vp, "/")
	names := map[string]bool{rel: true}
	switch {
	case strings.HasPrefix(rel, "usr/"):
		names[strings.TrimPrefix(rel, "usr/")] = true
	default:
		names["usr/"+rel] = true
	}
	want, err := dpkgMD5(filepath.Join(base, "var/lib/dpkg/info"), names)
	if err != nil {
		return err
	}
	f, err := os.Open(real)
	if err != nil {
		return err
	}
	defer f.Close()
	h := md5.New() //nolint:gosec // сверка с md5sums dpkg, не защита от коллизий подобранных пар
	if _, err := io.Copy(h, io.LimitReader(f, 512<<20)); err != nil {
		return err
	}
	if hex.EncodeToString(h.Sum(nil)) != want {
		return errors.New("файл отличается от файла пакета")
	}
	return nil
}

// dpkgMD5 — сумма файла из md5sums пакетов: строки «<md5>  usr/bin/x».
func dpkgMD5(dir string, names map[string]bool) (string, error) {
	lists, err := filepath.Glob(filepath.Join(dir, "*.md5sums"))
	if err != nil {
		return "", err
	}
	for _, l := range lists {
		f, err := os.Open(l)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() {
			sum, name, ok := strings.Cut(sc.Text(), "  ")
			if ok && names[name] && len(sum) == 32 {
				_ = f.Close()
				return sum, nil
			}
		}
		_ = f.Close()
	}
	return "", errors.New("не файл пакета дистрибутива")
}

// rootOwned — файл исполняемый и обычный, он и каталоги до base — владельца OwnerUID без записи группе и остальным.
func rootOwned(base, real string) error {
	fi, err := os.Stat(real)
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() || fi.Mode().Perm()&0o111 == 0 {
		return errors.New("не исполняемый файл")
	}
	for p := real; ; p = filepath.Dir(p) {
		st, err := os.Stat(p)
		if err != nil {
			return err
		}
		sys, ok := st.Sys().(*syscall.Stat_t)
		if !ok || sys.Uid != OwnerUID || st.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("%s: владелец не root или запись для группы и остальных", p)
		}
		if p == base || p == filepath.Dir(p) {
			return nil
		}
	}
}

// OwnerUID — владелец программ (root; в тестах — свой uid).
var OwnerUID uint32 = 0

// Check — запреты R28 для argv в каталоге запуска: как в панели и ещё раз с найденной программой и путями после
// ссылок. root — корень файловой системы.
func Check(root string, p *agentv1.ExecRunParams, program string) execpolicy.Verdict {
	if v := execpolicy.Check(p.GetArgv(), cwd(p), execpolicy.Options{}); !v.Allowed {
		return v
	}
	if root == "" {
		root = "/"
	}
	resolve := func(v string) (string, bool) {
		base, err := filepath.EvalSymlinks(root)
		if err != nil {
			return "", false
		}
		real, err := filepath.EvalSymlinks(filepath.Join(root, v))
		if err != nil {
			return "", false
		}
		rel, err := filepath.Rel(base, real)
		if err != nil {
			return "", false
		}
		return path.Join("/", filepath.ToSlash(rel)), true
	}
	comm := func(pid string) string {
		b, err := os.ReadFile(filepath.Join(root, "proc", pid, "comm"))
		if err != nil {
			return ""
		}
		return strings.TrimSpace(string(b))
	}
	argv := append([]string{program}, p.GetArgv()[1:]...)
	return execpolicy.Check(argv, cwd(p), execpolicy.Options{Resolve: resolve, Comm: comm})
}

// Job — один запуск.
type Job struct {
	Name    string // имя службы: trassa-exec-<id>
	Program string // полный путь программы (Program)
	Params  *agentv1.ExecRunParams
	Output  func(stream agentv1.LogStream, chunk string) // вывод в журнал (уже в пределе max_output_bytes)
	Timeout time.Duration
}

// Outcome — итог запуска.
type Outcome struct {
	ExitCode  int32
	TimedOut  bool
	Total     uint64
	Truncated bool
	Duration  time.Duration
}

// Runner — запуск команды. Prepare — пользователь и каталог существуют (EXEC_USER_INVALID, EXEC_CWD_INVALID),
// программа найдена и прошла запреты с путями после ссылок; возвращает полный путь программы.
type Runner interface {
	Prepare(p *agentv1.ExecRunParams) (program string, v execpolicy.Verdict, err error)
	Run(ctx context.Context, j Job) (Outcome, error)
}

// Systemd — запуск через systemd-run --wait --pipe.
type Systemd struct {
	SystemdRun string // /usr/bin/systemd-run
	Systemctl  string // /usr/bin/systemctl
	// Lookup — пользователь по имени (os/user, без cgo читает /etc/passwd).
	Lookup func(string) (*user.User, error)
	// Root — корень файловой системы для проверки cwd (в тестах — временный каталог).
	Root string
}

// Args — командная строка systemd-run.
func (s Systemd) Args(j Job) []string {
	p := j.Params
	a := []string{"--wait", "--pipe", "--quiet", "--collect", "--unit=" + j.Name, "--uid=" + runAs(p),
		"--working-directory=" + cwd(p)}
	inacc := make([]string, 0, len(trassaDirs)+len(secretPaths))
	for _, d := range append(append([]string{}, trassaDirs...), secretPaths...) {
		inacc = append(inacc, "-"+d)
	}
	for _, prop := range []string{
		"Type=exec",
		// Запас сверх нашего таймера: systemd остановит службу и без помощника.
		"RuntimeMaxSec=" + strconv.Itoa(int(p.GetTimeoutSec())+10),
		"KillMode=control-group",
		"TimeoutStopSec=5",
		"LimitCORE=0",
		// Модули ядра не грузятся и из root (запрет EXEC_KERNEL_MODULE исполняется ядром).
		"ProtectKernelModules=yes",
		"InaccessiblePaths=" + strings.Join(inacc, " "),
		"Environment=LANG=C.UTF-8 TERM=dumb",
	} {
		a = append(a, "-p", prop)
	}
	return append(append(a, "--", j.Program), p.GetArgv()[1:]...)
}

// Prepare — пользователь существует, каталог есть и не ведёт в каталоги Trassa, программа найдена и прошла запреты.
func (s Systemd) Prepare(p *agentv1.ExecRunParams) (string, execpolicy.Verdict, error) {
	lookup := s.Lookup
	if lookup == nil {
		lookup = user.Lookup
	}
	if _, err := lookup(runAs(p)); err != nil {
		return "", execpolicy.Verdict{}, fmt.Errorf("%w: пользователя нет", ErrUserInvalid)
	}
	root := s.Root
	if root == "" {
		root = "/"
	}
	real := path.Join(root, cwd(p))
	fi, err := os.Stat(real)
	if err != nil || !fi.IsDir() {
		return "", execpolicy.Verdict{}, fmt.Errorf("%w: каталога нет", ErrCwdInvalid)
	}
	// Каталог через ссылку в каталоги Trassa — тоже нет (запреты проверяли путь как написан).
	resolved, err := filepath.EvalSymlinks(real)
	base, berr := filepath.EvalSymlinks(root)
	if err != nil || berr != nil {
		return "", execpolicy.Verdict{}, fmt.Errorf("%w: каталог", ErrCwdInvalid)
	}
	if rel, err := filepath.Rel(base, resolved); err != nil || underTrassa(path.Join("/", filepath.ToSlash(rel))) {
		return "", execpolicy.Verdict{}, fmt.Errorf("%w: каталоги Trassa", ErrCwdInvalid)
	}
	prog, err := Program(root, p.GetArgv()[0])
	if err != nil {
		return "", execpolicy.Verdict{}, err
	}
	return prog, Check(root, p, prog), nil
}

// Run — запустить и дождаться; по таймауту — systemctl kill всей группы и остановка службы.
func (s Systemd) Run(ctx context.Context, j Job) (Outcome, error) {
	if !strings.HasPrefix(j.Name, "trassa-exec-") || !unitNameOK(j.Name) {
		return Outcome{}, fmt.Errorf("имя службы %q", j.Name)
	}
	cmd := exec.Command(s.SystemdRun, s.Args(j)...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C"}
	return runCmd(ctx, cmd, j, func() {
		kctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		_ = exec.CommandContext(kctx, s.Systemctl, "kill", "--signal=SIGKILL", j.Name+".service").Run()
		_ = exec.CommandContext(kctx, s.Systemctl, "stop", j.Name+".service").Run()
	})
}

func unitNameOK(n string) bool {
	if len(n) > 100 {
		return false
	}
	for _, r := range n {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return true
}

// runCmd — общий ход для systemd и тестов: вывод stdout и stderr построчно в журнал до предела, дальше —
// только счёт байт (процесс не блокируется на полном канале), таймаут — kill и Kill процесса.
func runCmd(ctx context.Context, cmd *exec.Cmd, j Job, kill func()) (Outcome, error) {
	limit := uint64(j.Params.GetMaxOutputBytes())
	out := &limited{limit: limit, emit: j.Output}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return Outcome{}, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return Outcome{}, err
	}
	start := time.Now()
	if err := cmd.Start(); err != nil {
		if errors.Is(err, exec.ErrNotFound) || errors.Is(err, os.ErrNotExist) {
			return Outcome{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
		}
		return Outcome{}, err
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); out.copy(agentv1.LogStream_LOG_STREAM_STDOUT, stdout) }()
	go func() { defer wg.Done(); out.copy(agentv1.LogStream_LOG_STREAM_STDERR, stderr) }()
	timer := time.NewTimer(j.Timeout)
	defer timer.Stop()
	done := make(chan struct{})
	watcher := make(chan bool, 1) // true — остановлено по таймауту или отмене
	go func() {
		select {
		case <-timer.C:
		case <-ctx.Done():
		case <-done:
			watcher <- false
			return
		}
		if kill != nil {
			kill()
		}
		_ = cmd.Process.Kill()
		watcher <- true
	}()
	wg.Wait()
	werr := cmd.Wait()
	close(done)
	var o Outcome
	o.TimedOut = <-watcher
	o.Duration = time.Since(start)
	o.Total, o.Truncated = out.total, out.truncated
	o.ExitCode = -1
	if cmd.ProcessState != nil {
		if ws, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); ok && ws.Exited() {
			o.ExitCode = int32(ws.ExitStatus())
		}
	}
	var ee *exec.ExitError
	if werr != nil && !errors.As(werr, &ee) {
		return o, werr
	}
	return o, nil
}

// limited — вывод до предела: строки целиком, хвост без перевода строки — в конце.
type limited struct {
	mu        sync.Mutex
	limit     uint64
	sent      uint64
	total     uint64
	truncated bool
	emit      func(agentv1.LogStream, string)
	// lines — состояние фильтра секретов по потоку: конец ключа PEM в stdout не сбрасывает его в stderr.
	lines map[agentv1.LogStream]*redact.Lines
}

func (l *limited) copy(stream agentv1.LogStream, r io.Reader) {
	buf := make([]byte, 32<<10)
	var pending []byte
	for {
		n, err := r.Read(buf)
		if n > 0 {
			pending = append(pending, buf[:n]...)
			if i := lastNL(pending); i >= 0 {
				l.write(stream, pending[:i+1])
				pending = append([]byte(nil), pending[i+1:]...)
			} else if len(pending) >= 16<<10 {
				l.write(stream, pending)
				pending = nil
			}
		}
		if err != nil {
			if len(pending) > 0 {
				l.write(stream, pending)
			}
			return
		}
	}
}

func lastNL(b []byte) int {
	for i := len(b) - 1; i >= 0; i-- {
		if b[i] == '\n' {
			return i
		}
	}
	return -1
}

func (l *limited) write(stream agentv1.LogStream, b []byte) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.total += uint64(len(b))
	if l.sent >= l.limit {
		l.truncated = true
		return
	}
	if room := l.limit - l.sent; uint64(len(b)) > room {
		b = b[:room]
		l.truncated = true
	}
	l.sent += uint64(len(b))
	if l.emit == nil {
		return
	}
	if l.lines == nil {
		l.lines = map[agentv1.LogStream]*redact.Lines{}
	}
	st := l.lines[stream]
	if st == nil {
		st = &redact.Lines{}
		l.lines[stream] = st
	}
	// proto требует UTF-8: неверные байты — U+FFFD. Секреты вычищаются здесь по потоку и ещё раз в журнале.
	text := strings.ToValidUTF8(string(b), "\uFFFD")
	var out []string
	for _, line := range strings.SplitAfter(text, "\n") {
		if line == "" {
			continue
		}
		nl := strings.HasSuffix(line, "\n")
		if v, ok := st.Line(strings.TrimSuffix(line, "\n")); ok {
			if nl {
				v += "\n"
			}
			out = append(out, v)
		}
	}
	if len(out) > 0 {
		l.emit(stream, strings.Join(out, ""))
	}
}
