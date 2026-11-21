// SPDX-License-Identifier: AGPL-3.0-only

package vpnprobe

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Unit — запуск движка во временной службе systemd.
type Unit struct {
	// Name — имя службы без .service (trassa-vpnprobe-…).
	Name string
	Exec []string
	// AllowIPs — куда движку можно ходить кроме 127.0.0.1; пусто — никуда (пробный запуск version).
	AllowIPs []string
	// Visible — каталоги, которые движок видит только на чтение поверх скрытых (каталог замера).
	Visible []string
	// Timeout — секунд до принудительной остановки (RuntimeMaxSec).
	Timeout int
	Env     []string
}

// Process — запущенный движок.
type Process interface {
	// Exited — закрыт, когда служба завершилась.
	Exited() <-chan struct{}
	// Output — вывод движка (до 64 КиБ хвоста); только для разбора, наружу не уходит.
	Output() []byte
	Stop(ctx context.Context) error
}

// Sandbox — запуск движка без прав.
type Sandbox interface {
	Run(ctx context.Context, u Unit) ([]byte, error)
	Start(ctx context.Context, u Unit) (Process, error)
}

// Systemd — песочница на systemd-run (решения E25-agent): пользователь trassa без возможностей, файловая система
// только на чтение, каталоги Trassa скрыты пустым tmpfs (ключ агента, сокет помощника, бэкапы и соседние замеры),
// сеть — только петля и адреса входа (IPAddressAllow; на ядре без eBPF это не действует, поэтому главное
// ограничение — конфигурация, которую строит помощник), ptrace и чужие процессы недоступны, память, задачи,
// файлы и время ограничены.
type Systemd struct {
	SystemdRun string // /usr/bin/systemd-run
	Systemctl  string // /usr/bin/systemctl
	User       string // trassa
	// Hidden — каталоги, скрытые от движка (TemporaryFileSystem).
	Hidden []string
	// EngineDir — каталог движков (виден на чтение поверх Hidden).
	EngineDir string
}

// Properties — свойства временной службы.
func (s Systemd) Properties(u Unit) []string {
	allow := append([]string{"localhost"}, u.AllowIPs...)
	props := []string{
		"Type=exec",
		"NoNewPrivileges=yes",
		"CapabilityBoundingSet=",
		"AmbientCapabilities=",
		"ProtectSystem=strict",
		"ProtectHome=yes",
		"PrivateTmp=yes",
		"PrivateDevices=yes",
		"ProtectKernelTunables=yes",
		"ProtectKernelModules=yes",
		"ProtectKernelLogs=yes",
		"ProtectControlGroups=yes",
		"ProtectClock=yes",
		"ProtectHostname=yes",
		"ProtectProc=invisible",
		"RestrictAddressFamilies=AF_INET AF_INET6 AF_NETLINK",
		"RestrictNamespaces=yes",
		"RestrictRealtime=yes",
		"RestrictSUIDSGID=yes",
		"LockPersonality=yes",
		"MemoryDenyWriteExecute=yes",
		"SystemCallArchitectures=native",
		"SystemCallFilter=@system-service",
		"SystemCallFilter=~@privileged @debug @mount @reboot @swap @module @raw-io",
		"UMask=0077",
		"IPAddressDeny=any",
		"IPAddressAllow=" + strings.Join(allow, " "),
		"MemoryMax=256M",
		"TasksMax=64",
		"LimitNOFILE=1024",
		"LimitCORE=0",
		"CPUQuota=50%",
		"RuntimeMaxSec=" + strconv.Itoa(max(u.Timeout, 1)),
		"TemporaryFileSystem=" + strings.Join(withRO(s.Hidden), " "),
		"BindReadOnlyPaths=" + strings.Join(append([]string{s.EngineDir}, u.Visible...), " "),
	}
	for _, e := range u.Env {
		props = append(props, "Environment="+e)
	}
	return props
}

func withRO(dirs []string) []string {
	out := make([]string, 0, len(dirs))
	for _, d := range dirs {
		out = append(out, d+":ro")
	}
	return out
}

// args — командная строка systemd-run: служба ждёт конца (--wait), вывод в канал (--pipe), выгружается сразу.
func (s Systemd) args(u Unit) []string {
	a := []string{"--wait", "--pipe", "--quiet", "--collect", "--unit=" + u.Name, "--uid=" + s.User, "--gid=" + s.User}
	for _, p := range s.Properties(u) {
		a = append(a, "-p", p)
	}
	return append(append(a, "--"), u.Exec...)
}

// Run — запустить и дождаться конца; вывод — stdout и stderr вместе (до 64 КиБ).
func (s Systemd) Run(ctx context.Context, u Unit) ([]byte, error) {
	p, err := s.Start(ctx, u)
	if err != nil {
		return nil, err
	}
	select {
	case <-p.Exited():
	case <-ctx.Done():
		_ = p.Stop(context.WithoutCancel(ctx))
		return nil, ctx.Err()
	}
	sp := p.(*sdProcess)
	if sp.err != nil {
		return sp.Output(), fmt.Errorf("%w: %v", ErrEngineFailed, sp.err)
	}
	return sp.Output(), nil
}

// Start — запустить в фоне.
func (s Systemd) Start(ctx context.Context, u Unit) (Process, error) {
	if !unitNameRe(u.Name) {
		return nil, fmt.Errorf("имя службы %q", u.Name)
	}
	cmd := exec.Command(s.SystemdRun, s.args(u)...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C"}
	out := &tailBuffer{max: 64 << 10}
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Start(); err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return nil, fmt.Errorf("%w: %v", ErrSandboxUnavailable, err)
		}
		return nil, err
	}
	p := &sdProcess{s: s, name: u.Name, cmd: cmd, out: out, done: make(chan struct{})}
	go func() {
		p.err = cmd.Wait()
		close(p.done)
	}()
	return p, nil
}

func unitNameRe(n string) bool {
	if !strings.HasPrefix(n, "trassa-vpnprobe-") || len(n) > 100 {
		return false
	}
	for _, r := range n {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return true
}

type sdProcess struct {
	s    Systemd
	name string
	cmd  *exec.Cmd
	out  *tailBuffer
	done chan struct{}
	err  error
}

func (p *sdProcess) Exited() <-chan struct{} { return p.done }
func (p *sdProcess) Output() []byte          { return p.out.Bytes() }

// Stop — остановить службу и дождаться выхода systemd-run; не остановилась — убить systemd-run.
func (p *sdProcess) Stop(ctx context.Context) error {
	select {
	case <-p.done:
		return nil
	default:
	}
	sctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	stop := exec.CommandContext(sctx, p.s.Systemctl, "stop", "--", p.name+".service")
	stop.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C"}
	serr := stop.Run()
	select {
	case <-p.done:
		return nil
	case <-sctx.Done():
		_ = p.cmd.Process.Kill()
		<-p.done
		if serr != nil {
			return fmt.Errorf("systemctl stop %s: %v", p.name, serr)
		}
		return fmt.Errorf("служба %s не остановилась", p.name)
	}
}

// tailBuffer — последние max байт вывода.
type tailBuffer struct {
	mu  sync.Mutex
	max int
	b   []byte
}

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.b = append(t.b, p...)
	if len(t.b) > t.max {
		t.b = append([]byte(nil), t.b[len(t.b)-t.max:]...)
	}
	return len(p), nil
}

func (t *tailBuffer) Bytes() []byte {
	t.mu.Lock()
	defer t.mu.Unlock()
	return bytes.Clone(t.b)
}

var _ io.Writer = (*tailBuffer)(nil)

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
