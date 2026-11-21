// SPDX-License-Identifier: AGPL-3.0-only

package backup

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/NogMeer/trassa-agent/internal/redact"
)

// Коды выхода restic (doc/075_scripting.rst, decisions E13 п. 1.6). Неизвестный код — сбой команды.
const (
	ExitOK          = 0
	ExitFailed      = 1
	ExitPartial     = 3 // backup прочитал не всё, forget удалил не всё
	ExitNoRepo      = 10
	ExitLocked      = 11
	ExitBadPassword = 12
	ExitCancelled   = 130
)

// StopGrace — сколько ждать мягкого завершения restic после SIGTERM (срок окна), потом SIGKILL.
const StopGrace = 60 * time.Second

// Restic — запуск restic для одного репозитория. Пароль — файлом (RESTIC_PASSWORD_FILE), ключи хранилища —
// окружением дочернего процесса: ни в аргументах, ни в выводе ps их нет.
type Restic struct {
	Bin      string // абсолютный путь проверенного бинарника
	CacheDir string // кэш restic (RESTIC_CACHE_DIR)
	TmpDir   string // TMPDIR
	Repo     *Repo
	// PasswordFile — файл с паролем (root, 0600); SSHKey и KnownHosts — для sftp: (цель SERVER).
	PasswordFile string
	SSHKey       string
	KnownHosts   string
	// Nice — приоритет процесса (0 — не менять): бэкап не отнимает процессор у рабочих служб.
	Nice int
	// Credential — запуск от пользователя цели (чистка локального репозитория цели: файлы остаются его).
	Credential *syscall.Credential
	// NoLock — без блокировок (--no-lock): восстановление на другом сервере читает репозиторий ключом без права
	// записи.
	NoLock bool
}

// Exit — итог команды: код и сообщение exit_error (без секретов).
type Exit struct {
	Code    int
	Message string
}

func (e *Exit) Error() string { return fmt.Sprintf("restic: код %d: %s", e.Code, e.Message) }

// ErrDeadline — срок окна вышел, restic остановлен.
var ErrDeadline = errors.New("BACKUP_WINDOW_EXCEEDED")

func (r *Restic) env() ([]string, error) {
	if r.Repo == nil || r.PasswordFile == "" || !filepath.IsAbs(r.Bin) {
		return nil, errors.New("restic: не настроен")
	}
	env := []string{
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C",
		"HOME=" + filepath.Dir(r.PasswordFile),
		"RESTIC_REPOSITORY=" + r.Repo.URL,
		"RESTIC_PASSWORD_FILE=" + r.PasswordFile,
	}
	if r.CacheDir != "" {
		env = append(env, "RESTIC_CACHE_DIR="+r.CacheDir)
	}
	if r.TmpDir != "" {
		env = append(env, "TMPDIR="+r.TmpDir)
	}
	for _, n := range EnvNames {
		if v, ok := r.Repo.Env[n]; ok {
			env = append(env, n+"="+v)
		}
	}
	return env, nil
}

// sshArgs — для sftp: и rclone: своя команда ssh: ключ плана, свой known_hosts, только по ключу, без
// переадресаций. Ключ хоста только закреплённый (StrictHostKeyChecking=yes): пустой known_hosts — отказ, а не
// accept-new. Порт из sftp://host:port идёт в -p: при sftp.command restic адрес не разбирает.
// rclone: (цель SERVER) — rclone.program = ssh: на цели принудительная команда rclone serve restic
// --append-only, аргументы с этой стороны не значат ничего.
func (r *Restic) sshArgs() ([]string, error) {
	if !strings.HasPrefix(r.Repo.URL, "sftp:") && !strings.HasPrefix(r.Repo.URL, "rclone:") {
		return nil, nil
	}
	user, host, port, err := SSHTarget(r.Repo.URL)
	if err != nil {
		return nil, fmt.Errorf("адрес ssh: %w", err)
	}
	if r.SSHKey == "" || r.KnownHosts == "" {
		return nil, errors.New("ssh: нет ключа плана")
	}
	if st, err := os.Stat(r.KnownHosts); err != nil || st.Size() == 0 {
		return nil, fmt.Errorf("%w: ключ хоста цели не закреплён", ErrTargetPrecondition)
	}
	cmd := []string{"ssh", "-i", r.SSHKey, "-p", strconv.Itoa(port), "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
		"-o", "UserKnownHostsFile=" + r.KnownHosts, "-o", "StrictHostKeyChecking=yes", "-o", "UpdateHostKeys=no",
		"-o", "ServerAliveInterval=60", "-o", "ServerAliveCountMax=240",
		"-o", "ClearAllForwardings=yes", "--", user + "@" + host}
	if strings.HasPrefix(r.Repo.URL, "sftp:") {
		cmd = append(cmd, "-s", "sftp")
	}
	for _, c := range cmd {
		if strings.ContainsAny(c, " \t\"'\\") {
			return nil, fmt.Errorf("ssh: недопустимый символ в %q", c)
		}
	}
	if strings.HasPrefix(r.Repo.URL, "sftp:") {
		return []string{"-o", "sftp.command=" + strings.Join(cmd, " ")}, nil
	}
	return []string{"-o", "rclone.program=" + strings.Join(cmd, " "), "-o", "rclone.args=serve restic --stdio"}, nil
}

// Command — подготовленный запуск: аргументы после глобальных опций.
type Command struct {
	Args  []string
	Stdin io.Reader
	// Line — каждая строка stdout (JSON lines); nil — вывод отбрасывается.
	Line func([]byte)
	// Deadline — конец окна; ноль — без срока.
	Deadline time.Time
	// LimitUploadKiB — --limit-upload (KiB/s), 0 — без ограничения.
	LimitUploadKiB uint32
	// Stdout — поток данных (dump) вместо JSON lines; Raw — без --json.
	Stdout io.Writer
	Raw    bool
}

// Run запускает restic и ждёт конца. Код ≠ 0 — *Exit; срок окна — ErrDeadline (обёрнутый с *Exit).
func (r *Restic) Run(ctx context.Context, c Command) error {
	env, err := r.env()
	if err != nil {
		return err
	}
	var args []string
	if !c.Raw {
		args = append(args, "--json")
	}
	if r.NoLock {
		args = append(args, "--no-lock")
	}
	sa, err := r.sshArgs()
	if err != nil {
		return err
	}
	args = append(args, sa...)
	if c.LimitUploadKiB > 0 {
		args = append(args, "--limit-upload", fmt.Sprint(c.LimitUploadKiB))
	}
	args = append(args, c.Args...)
	runCtx, cancel := ctx, context.CancelFunc(func() {})
	if !c.Deadline.IsZero() {
		runCtx, cancel = context.WithDeadline(ctx, c.Deadline)
	}
	defer cancel()
	cmd := exec.CommandContext(runCtx, r.Bin, args...)
	cmd.Env = env
	cmd.Dir = "/"
	cmd.Stdin = c.Stdin
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Credential: r.Credential}
	// Срок: SIGTERM всей группе (restic завершается чисто и снимка не оставляет), через StopGrace — SIGKILL.
	cmd.Cancel = func() error { return unix.Kill(-cmd.Process.Pid, unix.SIGTERM) }
	cmd.WaitDelay = StopGrace
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	var stderr tail
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("restic: запуск: %w", err)
	}
	if r.Nice != 0 {
		_ = unix.Setpriority(unix.PRIO_PGRP, cmd.Process.Pid, r.Nice)
	}
	var copyErr error
	if c.Stdout != nil {
		_, copyErr = io.Copy(c.Stdout, stdout)
		if copyErr != nil {
			_ = unix.Kill(-cmd.Process.Pid, unix.SIGTERM)
		}
	} else {
		sc := bufio.NewScanner(stdout)
		sc.Buffer(make([]byte, 64<<10), 4<<20)
		for sc.Scan() {
			if c.Line != nil {
				c.Line(sc.Bytes())
			}
		}
	}
	_, _ = io.Copy(io.Discard, stdout)
	werr := cmd.Wait()
	// Группа могла оставить потомков (ssh для sftp): добить после выхода.
	_ = unix.Kill(-cmd.Process.Pid, unix.SIGKILL)
	if werr == nil {
		if copyErr != nil {
			return fmt.Errorf("restic: поток: %w", copyErr)
		}
		return nil
	}
	var ee *exec.ExitError
	if !errors.As(werr, &ee) {
		if runCtx.Err() != nil && ctx.Err() == nil {
			return fmt.Errorf("%w: %v", ErrDeadline, werr)
		}
		return fmt.Errorf("restic: %w", werr)
	}
	ex := &Exit{Code: ee.ExitCode(), Message: r.clean(exitMessage(stderr.Bytes()))}
	if runCtx.Err() != nil && ctx.Err() == nil {
		return fmt.Errorf("%w: %w", ErrDeadline, ex)
	}
	return ex
}

// clean — текст для панели: без значений секретов плана и без шаблонных секретов (redact).
func (r *Restic) clean(s string) string { return Clean(s, r.Repo.Secrets()) }

// Clean вырезает значения секретов и шаблонные секреты из текста.
func Clean(s string, secrets []string) string {
	for _, v := range secrets {
		if len(v) >= 4 {
			s = strings.ReplaceAll(s, v, redact.Mask)
		}
	}
	s = redact.Text(s)
	if len(s) > 2000 {
		s = s[:2000]
	}
	return strings.ToValidUTF8(s, "")
}

// exitMessage — сообщение из последнего exit_error в stderr; нет его — последние строки stderr.
func exitMessage(b []byte) string {
	lines := bytes.Split(bytes.TrimSpace(b), []byte("\n"))
	for i := len(lines) - 1; i >= 0; i-- {
		var m struct {
			Type    string `json:"message_type"`
			Message string `json:"message"`
		}
		if json.Unmarshal(lines[i], &m) == nil && m.Type == "exit_error" {
			return m.Message
		}
	}
	if len(lines) > 5 {
		lines = lines[len(lines)-5:]
	}
	return string(bytes.Join(lines, []byte("\n")))
}

// ExitCode — код выхода restic из ошибки Run (−1 — не restic: запуск, срок без кода).
func ExitCode(err error) int {
	var ex *Exit
	if errors.As(err, &ex) {
		return ex.Code
	}
	return -1
}

// tail — последние 64 КиБ потока.
type tail struct{ b []byte }

func (t *tail) Write(p []byte) (int, error) {
	t.b = append(t.b, p...)
	if len(t.b) > 64<<10 {
		t.b = append([]byte(nil), t.b[len(t.b)-64<<10:]...)
	}
	return len(p), nil
}

func (t *tail) Bytes() []byte { return t.b }

// TempPasswordFile — временный файл пароля (ключи обслуживания backup.prune): только на время операции.
func TempPasswordFile(dir string, pw []byte) (string, func(), error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", nil, err
	}
	f, err := os.CreateTemp(dir, ".pw-*")
	if err != nil {
		return "", nil, err
	}
	name := f.Name()
	cleanup := func() { _ = os.Remove(name) }
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		cleanup()
		return "", nil, err
	}
	if _, err := f.Write(pw); err != nil {
		f.Close()
		cleanup()
		return "", nil, err
	}
	if err := f.Close(); err != nil {
		cleanup()
		return "", nil, err
	}
	return name, cleanup, nil
}
