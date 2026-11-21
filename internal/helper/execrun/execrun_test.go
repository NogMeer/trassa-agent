// SPDX-License-Identifier: AGPL-3.0-only

package execrun

import (
	"context"
	"crypto/md5"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
)

func params(argv ...string) *agentv1.ExecRunParams {
	return &agentv1.ExecRunParams{Argv: argv, TimeoutSec: 10, MaxOutputBytes: 1024}
}

func TestValidate(t *testing.T) {
	if err := Validate(params("uptime")); err != nil {
		t.Fatal(err)
	}
	bad := map[string]func(p *agentv1.ExecRunParams){
		"command":       func(p *agentv1.ExecRunParams) { p.Command = "uptime" },
		"пусто":         func(p *agentv1.ExecRunParams) { p.Argv = nil },
		"$":             func(p *agentv1.ExecRunParams) { p.Argv = []string{"cat", "/etc/sha${X}dow"} },
		"длинная":       func(p *agentv1.ExecRunParams) { p.Argv = []string{"echo", strings.Repeat("x", 2001)} },
		"таймаут 0":     func(p *agentv1.ExecRunParams) { p.TimeoutSec = 0 },
		"таймаут 301":   func(p *agentv1.ExecRunParams) { p.TimeoutSec = 301 },
		"вывод 0":       func(p *agentv1.ExecRunParams) { p.MaxOutputBytes = 0 },
		"вывод большой": func(p *agentv1.ExecRunParams) { p.MaxOutputBytes = MaxOutput + 1 },
		"trassa":        func(p *agentv1.ExecRunParams) { p.RunAs = "trassa" },
		"trassa-probe":  func(p *agentv1.ExecRunParams) { p.RunAs = "trassa-vpnprobe" },
		"имя":           func(p *agentv1.ExecRunParams) { p.RunAs = "Root;id" },
		"cwd отн":       func(p *agentv1.ExecRunParams) { p.Cwd = "tmp" },
		"cwd ..":        func(p *agentv1.ExecRunParams) { p.Cwd = "/srv/../etc" },
		"cwd trassa":    func(p *agentv1.ExecRunParams) { p.Cwd = "/var/lib/trassa/apps" },
		"cwd etc":       func(p *agentv1.ExecRunParams) { p.Cwd = "/etc/trassa" },
		"cwd упр":       func(p *agentv1.ExecRunParams) { p.Cwd = "/tmp/a\nb" },
	}
	for name, mut := range bad {
		p := params("uptime")
		mut(p)
		if Validate(p) == nil {
			t.Errorf("%s принят", name)
		}
	}
}

func TestSystemdArgs(t *testing.T) {
	s := Systemd{SystemdRun: "/usr/bin/systemd-run"}
	p := params("systemctl", "status", "nginx; id")
	p.RunAs, p.Cwd = "www-data", "/var/www"
	a := s.Args(Job{Name: "trassa-exec-0123456789abcdef", Program: "/usr/bin/systemctl", Params: p})
	for _, want := range []string{"--wait", "--pipe", "--collect", "--unit=trassa-exec-0123456789abcdef", "--uid=www-data",
		"--working-directory=/var/www", "RuntimeMaxSec=20", "KillMode=control-group",
		"ProtectKernelModules=yes",
		"InaccessiblePaths=-/etc/trassa -/var/lib/trassa -/run/trassa -/var/cache/trassa -/usr/local/lib/trassa -/opt/trassa " +
			"-/etc/shadow -/etc/gshadow -/etc/shadow- -/etc/gshadow- -/etc/ssl/private -/etc/ssh/ssh_host_rsa_key " +
			"-/etc/ssh/ssh_host_ecdsa_key -/etc/ssh/ssh_host_ed25519_key -/etc/ssh/ssh_host_dsa_key -/etc/letsencrypt/keys " +
			"-/etc/letsencrypt/archive -/root/.ssh -/etc/ppp/chap-secrets -/etc/ppp/pap-secrets"} {
		if !slices.Contains(a, want) {
			t.Errorf("нет %q в %q", want, a)
		}
	}
	// Без оболочки: после -- полный путь программы и аргументы как есть, слово «nginx; id» одно.
	i := slices.Index(a, "--")
	if i < 0 || !slices.Equal(a[i+1:], []string{"/usr/bin/systemctl", "status", "nginx; id"}) || slices.Contains(a, "/bin/bash") {
		t.Fatalf("%q", a)
	}
	if def := s.Args(Job{Name: "trassa-exec-x", Program: "/usr/bin/uptime", Params: params("uptime")}); !slices.Contains(def, "--uid=root") ||
		!slices.Contains(def, "--working-directory=/") {
		t.Fatalf("по умолчанию: %q", def)
	}
	if _, err := s.Run(context.Background(), Job{Name: "nginx", Params: p}); err == nil {
		t.Fatal("чужое имя службы")
	}
}

// fsRoot — корень с /usr/bin, /srv, /etc/trassa; владелец — тест (OwnerUID на время теста).
func fsRoot(t *testing.T) string {
	t.Helper()
	old := OwnerUID
	OwnerUID = uint32(os.Getuid())
	t.Cleanup(func() { OwnerUID = old })
	root := t.TempDir()
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"usr/bin", "srv/app", "etc/trassa", "tmp", "home/u/bin"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(filepath.Join(root, "tmp"), 0o777); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"usr/bin/ls", "usr/bin/dash", "usr/bin/vim.basic", "tmp/ls", "home/u/bin/tool"} {
		if err := os.WriteFile(filepath.Join(root, f), []byte("x"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(filepath.Join(root, "home/u/bin/tool"), 0o777); err != nil {
		t.Fatal(err)
	}
	for l, target := range map[string]string{"usr/bin/sh": "dash", "usr/bin/view": "vim.basic", "srv/link": "../etc/trassa",
		"srv/sh": filepath.Join(root, "etc/shadow"), "usr/bin/tmpls": filepath.Join(root, "tmp/ls")} {
		if err := os.Symlink(target, filepath.Join(root, l)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "etc/shadow"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Файлы пакетов: ls, dash, vim.basic (у dash в списке путь без usr/, как до слияния /usr).
	for _, f := range []string{"usr/bin/copy", "usr/bin/changed"} {
		if err := os.WriteFile(filepath.Join(root, f), []byte("x"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	sum := fmt.Sprintf("%x", md5.Sum([]byte("x")))
	other := fmt.Sprintf("%x", md5.Sum([]byte("original")))
	if err := os.MkdirAll(filepath.Join(root, "var/lib/dpkg/info"), 0o755); err != nil {
		t.Fatal(err)
	}
	list := sum + "  usr/bin/ls\n" + sum + "  bin/dash\n" + sum + "  usr/bin/vim.basic\n" + other + "  usr/bin/changed\n"
	if err := os.WriteFile(filepath.Join(root, "var/lib/dpkg/info/base.md5sums"), []byte(list), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestProgram(t *testing.T) {
	root := fsRoot(t)
	if p, err := Program(root, "ls"); err != nil || p != "/usr/bin/ls" {
		t.Fatalf("%q %v", p, err)
	}
	if p, err := Program(root, "view"); err != nil || p != "/usr/bin/vim.basic" {
		t.Fatalf("ссылка: %q %v", p, err)
	}
	if p, err := Program(root, "sh"); err != nil || p != "/usr/bin/dash" {
		t.Fatalf("bin/dash в списке пакета: %q %v", p, err)
	}
	// Копия под другим именем и изменённый файл пакета — не программы пакета.
	for _, name := range []string{"nothere", "/tmp/ls", "tmpls", "/home/u/bin/tool", "/srv/app", "copy", "changed"} {
		if _, err := Program(root, name); !errors.Is(err, ErrProgramInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestPrepare(t *testing.T) {
	root := fsRoot(t)
	s := Systemd{Root: root, Lookup: func(n string) (*user.User, error) {
		if n == "root" || n == "www-data" {
			return &user.User{Username: n}, nil
		}
		return nil, user.UnknownUserError(n)
	}}
	p := params("ls", "-la")
	p.Cwd = "/srv/app"
	if prog, v, err := s.Prepare(p); err != nil || !v.Allowed || prog != "/usr/bin/ls" {
		t.Fatalf("%q %+v %v", prog, v, err)
	}
	for _, c := range []struct {
		user, cwd string
		want      error
	}{
		{"nobody2", "/srv/app", ErrUserInvalid}, {"root", "/srv/none", ErrCwdInvalid}, {"root", "/srv/link", ErrCwdInvalid},
	} {
		p.RunAs, p.Cwd = c.user, c.cwd
		if _, _, err := s.Prepare(p); !errors.Is(err, c.want) {
			t.Errorf("%+v: %v", c, err)
		}
	}
	// Запреты с программой и путями после ссылок: sh → dash, view → vim.basic, /srv/sh → /etc/shadow.
	for argv, code := range map[string]string{"sh": "EXEC_RUNS_COMMANDS", "view /etc/hosts": "EXEC_RUNS_COMMANDS",
		"ls /srv/sh": "EXEC_SECRETS_READ", "ls /srv/link": "EXEC_TRASSA_AGENT"} {
		p := params(strings.Fields(argv)...)
		_, v, err := s.Prepare(p)
		if err != nil || v.Allowed || v.Code != code {
			t.Errorf("%s: %+v %v", argv, v, err)
		}
	}
}

type sink struct {
	mu  sync.Mutex
	out strings.Builder
}

func (s *sink) emit(_ agentv1.LogStream, c string) {
	s.mu.Lock()
	s.out.WriteString(c)
	s.mu.Unlock()
}

// direct — тот же runCmd без systemd: argv напрямую, своя группа процессов, по таймауту убивается вся.
func direct(ctx context.Context, p *agentv1.ExecRunParams, out *sink) (Outcome, error) {
	c := exec.Command(p.GetArgv()[0], p.GetArgv()[1:]...)
	c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return runCmd(ctx, c, Job{Params: p, Output: out.emit, Timeout: time.Duration(p.GetTimeoutSec()) * time.Second}, func() {
		if c.Process != nil {
			_ = syscall.Kill(-c.Process.Pid, syscall.SIGKILL)
		}
	})
}

func TestRunOutputExitAndLimit(t *testing.T) {
	var s sink
	o, err := direct(context.Background(), params("/bin/sh", "-c", "echo hello; echo err >&2; exit 3"), &s)
	if err != nil || o.ExitCode != 3 || o.TimedOut || !strings.Contains(s.out.String(), "hello") || !strings.Contains(s.out.String(), "err") {
		t.Fatalf("%+v %v %q", o, err, s.out.String())
	}
	// Аргументы как есть: «/*» и «a; b» не раскрываются и не делятся.
	s = sink{}
	if _, err := direct(context.Background(), params("/bin/echo", "/*", "a; b"), &s); err != nil || strings.TrimSpace(s.out.String()) != "/* a; b" {
		t.Fatalf("argv: %q %v", s.out.String(), err)
	}
	// Предел вывода: в журнал — не больше max_output_bytes, процесс не блокируется, считается всё.
	s = sink{}
	p := params("/bin/sh", "-c", "head -c 1000000 /dev/zero | tr '\\0' 'a'")
	p.MaxOutputBytes = 100
	o, err = direct(context.Background(), p, &s)
	if err != nil || o.ExitCode != 0 || !o.Truncated || o.Total != 1000000 || s.out.Len() != 100 {
		t.Fatalf("%+v %v len=%d", o, err, s.out.Len())
	}
	// Неверный UTF-8 — U+FFFD (proto не принял бы строку).
	s = sink{}
	if _, err := direct(context.Background(), params("/usr/bin/printf", "a\\377b\\n"), &s); err != nil || !strings.Contains(s.out.String(), "a�b") {
		t.Fatalf("utf8: %q", s.out.String())
	}
	// Ключ PEM в stderr вычищается, хотя stdout в это время пишет своё: состояние фильтра — по потоку.
	s = sink{}
	script := "printf -- '-----BEGIN PRIVATE KEY-----\\n' >&2; echo out; printf 'AAAASECRETLINE\\n-----END PRIVATE KEY-----\\n' >&2"
	if _, err := direct(context.Background(), params("/bin/sh", "-c", script), &s); err != nil || strings.Contains(s.out.String(), "AAAASECRETLINE") {
		t.Fatalf("pem: %q %v", s.out.String(), err)
	}
}

// Таймаут останавливает и дочерние процессы группы (T4: интеграционный тест таймаута).
func TestRunTimeoutKillsGroup(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "alive")
	p := params("/bin/sh", "-c", "(sleep 3; touch "+marker+") & sleep 30")
	p.TimeoutSec = 1
	var s sink
	start := time.Now()
	o, err := direct(context.Background(), p, &s)
	if err != nil || !o.TimedOut || o.ExitCode != -1 || time.Since(start) > 10*time.Second {
		t.Fatalf("%+v %v %s", o, err, time.Since(start))
	}
	time.Sleep(4 * time.Second)
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("дочерний процесс пережил таймаут")
	}
}

func TestRunUnavailable(t *testing.T) {
	s := Systemd{SystemdRun: filepath.Join(t.TempDir(), "no-systemd-run")}
	if _, err := s.Run(context.Background(), Job{Name: "trassa-exec-x", Program: "/usr/bin/uptime", Params: params("uptime"), Timeout: time.Second}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("%v", err)
	}
}
