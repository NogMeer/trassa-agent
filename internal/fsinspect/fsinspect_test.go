// SPDX-License-Identifier: AGPL-3.0-only

package fsinspect

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
)

func write(t *testing.T, root, rel string, size int) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, make([]byte, size), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDiskPathAllowed(t *testing.T) {
	for _, p := range []string{"/", "/var", "/var/log", "/var/lib/docker/volumes", "/home/u", "/tmp", "/root"} {
		if !DiskPathAllowed(p) {
			t.Errorf("%s запрещён", p)
		}
	}
	for _, p := range []string{"", "var", "/etc", "/proc", "/sys/kernel", "/var/", "/var/../etc", "/var/./log", "//var",
		"/variable", "/var/log\x00", "/home/u\n", "/run/trassa"} {
		if DiskPathAllowed(p) {
			t.Errorf("%q разрешён", p)
		}
	}
	for _, p := range []*agentv1.DiskUsageParams{{Path: "/var", Depth: 0, Top: 5}, {Path: "/var", Depth: 4, Top: 5},
		{Path: "/var", Depth: 1, Top: 0}, {Path: "/var", Depth: 1, Top: 21}} {
		if ValidateDiskUsage(p) == nil {
			t.Errorf("%+v принят", p)
		}
	}
}

func TestDiskUsage(t *testing.T) {
	root := t.TempDir()
	write(t, root, "var/log/big.log", 300<<10)
	write(t, root, "var/log/nginx/access.log", 100<<10)
	write(t, root, "var/cache/apt/a.deb", 50<<10)
	write(t, root, "var/tiny", 10)
	// Жёсткая ссылка считается один раз.
	if err := os.Link(filepath.Join(root, "var/log/big.log"), filepath.Join(root, "var/zz.hard")); err != nil {
		t.Fatal(err)
	}
	// Ссылка на каталог не раскрывается.
	if err := os.Symlink(filepath.Join(root, "var/log"), filepath.Join(root, "var/loglink")); err != nil {
		t.Fatal(err)
	}
	e := &Env{Root: root}
	res, err := e.DiskUsage(context.Background(), &agentv1.DiskUsageParams{Path: "/var", Depth: 2, Top: 4})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.GetEntries()) != 4 || res.GetEntries()[0].GetPath() != "/var/log" || !res.GetEntries()[0].GetDir() || res.GetEntries()[0].GetDepth() != 1 {
		t.Fatalf("записи: %+v", res.GetEntries())
	}
	for i := 1; i < len(res.GetEntries()); i++ {
		if res.GetEntries()[i].GetBytes() > res.GetEntries()[i-1].GetBytes() {
			t.Fatal("не по убыванию")
		}
	}
	got := map[string]uint64{}
	for _, en := range res.GetEntries() {
		got[en.GetPath()] = en.GetBytes()
	}
	if got["/var/log"] < 400<<10 || got["/var/log/big.log"] < 300<<10 {
		t.Fatalf("размеры: %v", got)
	}
	// big.log и zz.hard (обход по алфавиту: учтён первый) — один inode: общий итог меньше 2×300 КиБ.
	if res.GetTotalBytes() >= 750<<10 || res.GetTotalBytes() < 450<<10 {
		t.Fatalf("итог %d", res.GetTotalBytes())
	}
	if res.GetFsSizeBytes() == 0 || res.GetTruncated() {
		t.Fatalf("фс: %+v", res)
	}
	// Глубина 1 — только прямые потомки.
	res, err = e.DiskUsage(context.Background(), &agentv1.DiskUsageParams{Path: "/var", Depth: 1, Top: 20})
	if err != nil {
		t.Fatal(err)
	}
	for _, en := range res.GetEntries() {
		if en.GetDepth() != 1 || strings.Count(en.GetPath(), "/") != 2 {
			t.Fatalf("глубина: %+v", en)
		}
	}
	// Путь через ссылку и отсутствующий путь — свои коды.
	if err := os.Symlink(filepath.Join(root, "var"), filepath.Join(root, "srv")); err != nil {
		t.Fatal(err)
	}
	if _, err := e.DiskUsage(context.Background(), &agentv1.DiskUsageParams{Path: "/srv", Depth: 1, Top: 5}); !errors.Is(err, ErrDiskPathForbidden) {
		t.Fatalf("ссылка: %v", err)
	}
	if _, err := e.DiskUsage(context.Background(), &agentv1.DiskUsageParams{Path: "/opt", Depth: 1, Top: 5}); !errors.Is(err, ErrDiskPathNotFound) {
		t.Fatalf("нет пути: %v", err)
	}
	// Время вышло — частичный итог с отметкой.
	now := time.Now()
	calls := 0
	e.Now = func() time.Time { calls++; return now.Add(time.Duration(calls) * time.Hour) }
	if _, err := e.DiskUsage(context.Background(), &agentv1.DiskUsageParams{Path: "/var", Depth: 1, Top: 5}); err != nil {
		t.Fatal(err)
	}
	// Отменённый контекст — прерванный обход, не ошибка.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	e.Now = nil
	if r, err := e.DiskUsage(ctx, &agentv1.DiskUsageParams{Path: "/var", Depth: 1, Top: 5}); err != nil || !r.GetTruncated() {
		t.Fatalf("отмена: %+v %v", r, err)
	}
}

func TestPrintable(t *testing.T) {
	if got := printable("/var/a\x1b[31mb\xff\u202ec"); got != "/var/a?[31mb??c" {
		t.Fatalf("%q", got)
	}
	if got := printable(strings.Repeat("я", 600)); len(got) > maxPathBytes || !strings.HasPrefix(got, "я") {
		t.Fatalf("обрезка: %d", len(got))
	}
}

func TestConfigPathAllowed(t *testing.T) {
	for _, p := range []string{"/etc/nginx/nginx.conf", "/etc/nginx/sites-enabled/app", "/etc/nginx/conf.d/a.conf",
		"/etc/systemd/system/app.service", "/etc/docker/daemon.json",
		"/var/lib/trassa/apps/01a1f4b6-f327-7a5d-ac23-e95c272c0fe8/compose/compose.json"} {
		if !ConfigPathAllowed(p) {
			t.Errorf("%s запрещён", p)
		}
	}
	for _, p := range []string{"/etc/shadow", "/etc/nginx", "/etc/nginx/", "/etc/nginx/../shadow", "/etc/nginx/./x",
		"/etc/nginx/ssl/server.key", "/etc/nginx/ssl/fullchain.pem", "/etc/nginx/private/x.conf", "/etc/nginx/.htpasswd",
		"/etc/nginx/htpasswd.users", "/etc/nginx/.env", "/etc/nginx/passwords.conf", "/etc/nginx/secrets.conf",
		"/etc/systemd/system/trassa-agent.service", "/etc/systemd/system/trassa-helper.service",
		"/etc/systemd/system/app.service.d/override.conf", "/etc/systemd/system/app.timer", "/etc/trassa/agent.toml",
		"/var/lib/trassa/agent/agent.key", "/var/lib/trassa/apps/x/compose/compose.json",
		"/var/lib/trassa/apps/01a1f4b6-f327-7a5d-ac23-e95c272c0fe8/compose/compose.prev.json", "/etc/docker/key.json",
		"etc/nginx/nginx.conf", "/etc/nginx/a\nb"} {
		if ConfigPathAllowed(p) {
			t.Errorf("%q разрешён", p)
		}
	}
}

func TestConfigRead(t *testing.T) {
	root := t.TempDir()
	e := &Env{Root: root}
	read := func(p string) (*agentv1.ConfigReadResult, error) {
		return e.ConfigRead(&agentv1.ConfigReadParams{Path: p})
	}
	conf := "server {\n  # password = hunter2hunter2\n  listen 80;\n}\n"
	write(t, root, "etc/nginx/sites-available/app", 0)
	if err := os.WriteFile(filepath.Join(root, "etc/nginx/sites-available/app"), []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "etc/nginx/sites-enabled"), 0o755); err != nil {
		t.Fatal(err)
	}
	// sites-enabled → sites-available (относительная ссылка, как у Debian).
	if err := os.Symlink("../sites-available/app", filepath.Join(root, "etc/nginx/sites-enabled/app")); err != nil {
		t.Fatal(err)
	}
	r, err := read("/etc/nginx/sites-enabled/app")
	if err != nil {
		t.Fatal(err)
	}
	if r.GetResolvedPath() != "/etc/nginx/sites-available/app" || strings.Contains(r.GetContent(), "hunter2") ||
		r.GetRedacted() != 1 || r.GetSizeBytes() != uint64(len(conf)) {
		t.Fatalf("%+v", r)
	}
	// Ссылка из разрешённого места на запрещённое — отказ по пути после ссылок.
	write(t, root, "etc/shadow", 10)
	write(t, root, "etc/nginx/ssl/server.key", 10)
	for name, target := range map[string]string{"shadow.conf": filepath.Join(root, "etc/shadow"), "key.conf": "ssl/server.key",
		"out.conf": "/etc/hosts"} {
		if err := os.Symlink(target, filepath.Join(root, "etc/nginx", name)); err != nil {
			t.Fatal(err)
		}
		if _, err := read("/etc/nginx/" + name); !errors.Is(err, ErrConfigPathForbidden) {
			t.Errorf("%s → %s: %v", name, target, err)
		}
	}
	// Нет файла, большой, двоичный, каталог.
	if _, err := read("/etc/nginx/none.conf"); !errors.Is(err, ErrConfigNotFound) {
		t.Fatalf("нет: %v", err)
	}
	write(t, root, "etc/nginx/big.conf", MaxConfigBytes+1)
	if _, err := read("/etc/nginx/big.conf"); !errors.Is(err, ErrConfigTooLarge) {
		t.Fatalf("большой: %v", err)
	}
	write(t, root, "etc/nginx/bin.conf", 10)
	if _, err := read("/etc/nginx/bin.conf"); !errors.Is(err, ErrConfigNotText) {
		t.Fatalf("двоичный: %v", err)
	}
	if _, err := read("/etc/nginx/sites-enabled"); !errors.Is(err, ErrConfigNotText) {
		t.Fatalf("каталог: %v", err)
	}
	// FIFO не вешает чтение.
	if err := syscall.Mkfifo(filepath.Join(root, "etc/nginx/fifo.conf"), 0o644); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := read("/etc/nginx/fifo.conf"); done <- err }()
	select {
	case err := <-done:
		if !errors.Is(err, ErrConfigNotText) {
			t.Fatalf("fifo: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("чтение FIFO зависло")
	}
	if Code(ErrConfigTooLarge) != CodeConfigTooLarge || Code(errors.New("x")) != "" {
		t.Fatal("Code")
	}
}
