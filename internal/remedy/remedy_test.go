// SPDX-License-Identifier: AGPL-3.0-only

package remedy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/dockerapi"
)

// clock — время, которое двигает sleep (Poll), чтобы проверка 60 секунд шла мгновенно.
type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newEnv(t *testing.T) (*Env, *clock) {
	t.Helper()
	c := &clock{t: time.Unix(1_800_000_000, 0)}
	root, err := filepath.EvalSymlinks(t.TempDir()) // /var на macOS — ссылка, а пути проходятся без ссылок
	if err != nil {
		t.Fatal(err)
	}
	return &Env{Root: root, Now: c.now, Poll: time.Millisecond, Stable: 60 * time.Second, Settle: 30 * time.Second}, c
}

// fakeSystemctl — show отдаёт очередное состояние из states (последнее — дальше), restart и start записываются.
type fakeSystemctl struct {
	mu     sync.Mutex
	states []string
	calls  []string
	clock  *clock
	step   time.Duration
}

func (f *fakeSystemctl) run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, name+" "+strings.Join(args, " "))
	if args[0] != "show" {
		return nil, nil
	}
	f.clock.t = f.clock.t.Add(f.step)
	s := f.states[0]
	if len(f.states) > 1 {
		f.states = f.states[1:]
	}
	return []byte(s), nil
}

func showOut(active, pid, since string) string {
	return fmt.Sprintf("LoadState=loaded\nActiveState=%s\nSubState=running\nMainPID=%s\nActiveEnterTimestampMonotonic=%s\nNRestarts=2\n", active, pid, since)
}

func TestUnitStable(t *testing.T) {
	e, c := newEnv(t)
	f := &fakeSystemctl{clock: c, step: 5 * time.Second, states: []string{showOut("failed", "0", "0"), showOut("activating", "0", "0"), showOut("active", "42", "100")}}
	e.Run = f.run
	res, err := e.Service(context.Background(), &agentv1.ServiceRestartParams{Unit: "nginx.service"}, false)
	if err != nil || !res.GetActive() || res.GetRestarts() != 2 {
		t.Fatalf("%v %+v", err, res)
	}
	if !strings.Contains(strings.Join(f.calls, "\n"), "systemctl restart -- nginx.service") {
		t.Fatalf("calls %v", f.calls)
	}
	// Перезапуск за время проверки (новый MainPID) — SERVICE_NOT_STABLE.
	f = &fakeSystemctl{clock: c, step: 5 * time.Second, states: []string{showOut("active", "42", "100"), showOut("active", "42", "100"), showOut("active", "43", "200")}}
	e.Run = f.run
	if _, err := e.Service(context.Background(), &agentv1.ServiceRestartParams{Unit: "nginx.service"}, false); !errors.Is(err, ErrNotStable) {
		t.Fatalf("смена PID: %v", err)
	}
	// start активной службы — без команды, только проверка.
	f = &fakeSystemctl{clock: c, step: 5 * time.Second, states: []string{showOut("active", "42", "100")}}
	e.Run = f.run
	if _, err := e.Service(context.Background(), &agentv1.ServiceRestartParams{Unit: "nginx.service"}, true); err != nil {
		t.Fatal(err)
	}
	for _, call := range f.calls {
		if strings.Contains(call, " start ") {
			t.Fatalf("активная служба запущена повторно: %v", f.calls)
		}
	}
	// Не поднялась за Settle.
	f = &fakeSystemctl{clock: c, step: 5 * time.Second, states: []string{showOut("failed", "0", "0")}}
	e.Run = f.run
	if _, err := e.Service(context.Background(), &agentv1.ServiceRestartParams{Unit: "nginx.service"}, true); !errors.Is(err, ErrNotStable) {
		t.Fatalf("не поднялась: %v", err)
	}
	// Нет такой службы.
	f = &fakeSystemctl{clock: c, states: []string{"LoadState=not-found\nActiveState=inactive\n"}}
	e.Run = f.run
	if _, err := e.Service(context.Background(), &agentv1.ServiceRestartParams{Unit: "nope.service"}, false); !errors.Is(err, ErrNotFound) {
		t.Fatalf("нет службы: %v", err)
	}
}

// fakeDocker — Engine API на Unix-сокете для контейнеров, df и prune.
type fakeDocker struct {
	mu      sync.Mutex
	c       *clock
	cont    map[string]map[string]any // имя → inspect
	list    []map[string]any
	df      map[string]any
	deleted []string
	posts   []string
}

func startDocker(t *testing.T, c *clock) (*fakeDocker, *dockerapi.Client) {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "trr")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	l, err := net.Listen("unix", filepath.Join(dir, "d.sock"))
	if err != nil {
		t.Skipf("unix-сокет: %v", err)
	}
	d := &fakeDocker{c: c, cont: map[string]map[string]any{}}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d.mu.Lock()
		defer d.mu.Unlock()
		w.Header().Set("Api-Version", "1.44")
		p := strings.TrimPrefix(r.URL.Path, "/v1.44")
		parts := strings.Split(strings.Trim(p, "/"), "/")
		switch {
		case p == "/_ping":
		case p == "/containers/json":
			_ = json.NewEncoder(w).Encode(d.list)
		case len(parts) == 3 && parts[0] == "containers" && parts[2] == "json":
			ci, ok := d.cont[parts[1]]
			if !ok {
				for _, v := range d.cont {
					if v["Id"] == parts[1] {
						ci, ok = v, true
					}
				}
			}
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			d.c.t = d.c.t.Add(5 * time.Second)
			_ = json.NewEncoder(w).Encode(ci)
		case len(parts) == 3 && parts[0] == "containers" && parts[2] == "logs":
			msg := []byte("crash: ghp_" + strings.Repeat("A", 36) + "\n")
			_, _ = w.Write(append([]byte{2, 0, 0, 0, 0, 0, 0, byte(len(msg))}, msg...))
		case len(parts) == 3 && parts[0] == "containers":
			d.posts = append(d.posts, parts[2])
			w.WriteHeader(http.StatusNoContent)
		case p == "/images/docker.io/library/app:1/json":
			_, _ = w.Write([]byte(`{"Id":"sha256:release"}`))
		case p == "/system/df":
			_ = json.NewEncoder(w).Encode(d.df)
		case strings.HasPrefix(p, "/images/") && r.Method == http.MethodDelete:
			d.deleted = append(d.deleted, strings.TrimPrefix(p, "/images/"))
			_, _ = w.Write([]byte("[]"))
		case p == "/build/prune":
			d.posts = append(d.posts, "build-prune "+r.URL.Query().Get("filters"))
			_, _ = w.Write([]byte(`{"SpaceReclaimed":777}`))
		default:
			w.WriteHeader(http.StatusNotImplemented)
		}
	})}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
	return d, &dockerapi.Client{Socket: filepath.Join(dir, "d.sock")}
}

func inspect(id, name, status string, labels map[string]string) map[string]any {
	return map[string]any{"Id": id, "Name": "/" + name, "RestartCount": 0, "State": map[string]any{"Status": status, "StartedAt": "2026-11-21T10:00:00Z"},
		"Config": map[string]any{"Labels": labels}}
}

func TestContainerService(t *testing.T) {
	e, c := newEnv(t)
	d, cl := startDocker(t, c)
	e.Docker = cl
	d.cont["redis"] = inspect("c1", "redis", "running", nil)
	res, err := e.Service(context.Background(), &agentv1.ServiceRestartParams{Kind: agentv1.ServiceTargetKind_SERVICE_TARGET_KIND_CONTAINER, Container: "redis"}, false)
	if err != nil || !res.GetActive() || len(d.posts) != 1 || d.posts[0] != "restart" {
		t.Fatalf("%v %+v %v", err, res, d.posts)
	}
	// Не поднялся — SERVICE_NOT_STABLE и хвост журнала без секрета.
	d.cont["worker"] = inspect("c9", "worker", "exited", nil)
	res, err = e.Service(context.Background(), &agentv1.ServiceRestartParams{Kind: agentv1.ServiceTargetKind_SERVICE_TARGET_KIND_CONTAINER, Container: "worker"}, true)
	if !errors.Is(err, ErrNotStable) || len(res.GetLogTail()) != 1 || !strings.HasPrefix(res.GetLogTail()[0], "crash: ") || strings.Contains(res.GetLogTail()[0], "ghp_") {
		t.Fatalf("журнал: %v %+v", err, res)
	}
	d.posts = d.posts[:1]
	// Контейнеры Trassa — отказ без действий.
	d.cont["app"] = inspect("c2", "app", "exited", map[string]string{"trassa.app_id": "x"})
	d.cont["buildx_buildkit_trassa-2048"] = inspect("c3", "buildx_buildkit_trassa-2048", "running", nil)
	for _, n := range []string{"app", "buildx_buildkit_trassa-2048"} {
		if _, err := e.Service(context.Background(), &agentv1.ServiceRestartParams{Kind: agentv1.ServiceTargetKind_SERVICE_TARGET_KIND_CONTAINER, Container: n}, true); !errors.Is(err, ErrManaged) {
			t.Fatalf("%s: %v", n, err)
		}
	}
	// Engine API находит и по префиксу id — имя обязано совпасть.
	d.cont["c1"] = inspect("c1", "redis", "running", nil)
	if _, err := e.Service(context.Background(), &agentv1.ServiceRestartParams{Kind: agentv1.ServiceTargetKind_SERVICE_TARGET_KIND_CONTAINER, Container: "c1"}, false); !errors.Is(err, ErrNotFound) {
		t.Fatalf("по id: %v", err)
	}
	if len(d.posts) != 1 {
		t.Fatalf("лишние действия: %v", d.posts)
	}
}

func TestCleanup(t *testing.T) {
	e, c := newEnv(t)
	d, cl := startDocker(t, c)
	e.Docker = cl
	old := c.t.Add(-10 * 24 * time.Hour)
	for name, data := range map[string]string{
		"var/log/journal/m/system@0001-0002.journal": strings.Repeat("a", 1000),
		"var/log/journal/m/system.journal":           strings.Repeat("b", 500),
		"var/cache/apt/archives/x.deb":               strings.Repeat("c", 300),
		"var/cache/apt/archives/lock":                "",
	} {
		p := filepath.Join(e.Root, name)
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		_ = os.WriteFile(p, []byte(data), 0o644)
		_ = os.Chtimes(p, old, old)
	}
	// Ссылка в state.json записана иначе, чем тег у Docker: защита — по id образа.
	e.TrassaImages = func() (map[string]bool, error) { return map[string]bool{"docker.io/library/app:1": true}, nil }
	created := c.t.Add(-48 * time.Hour).Unix()
	d.df = map[string]any{"Images": []map[string]any{
		{"Id": "sha256:free", "Created": created, "Size": 100, "Containers": 0},
		{"Id": "sha256:used", "Created": created, "Size": 200, "Containers": 1},
		{"Id": "sha256:trassa", "Created": created, "Size": 300, "Containers": 0, "Labels": map[string]string{"trassa.app_id": "x"}},
		{"Id": "sha256:release", "Created": created, "Size": 400, "Containers": 0, "RepoTags": []string{"app:1"}},
		{"Id": "sha256:fresh", "Created": c.t.Unix(), "Size": 500, "Containers": 0},
	}, "BuildCache": []map[string]any{{"InUse": false, "Size": 50, "LastUsedAt": old.Format(time.RFC3339)}, {"InUse": true, "Size": 60}}}
	all := []agentv1.DiskCleanupCategory{agentv1.DiskCleanupCategory_DISK_CLEANUP_CATEGORY_JOURNAL, agentv1.DiskCleanupCategory_DISK_CLEANUP_CATEGORY_APT_CACHE,
		agentv1.DiskCleanupCategory_DISK_CLEANUP_CATEGORY_DOCKER_UNUSED, agentv1.DiskCleanupCategory_DISK_CLEANUP_CATEGORY_DOCKER_BUILD_CACHE}
	var runs []string
	e.Run = func(_ context.Context, name string, args ...string) ([]byte, error) {
		runs = append(runs, name+" "+strings.Join(args, " "))
		if name == "apt-get" {
			_ = os.Remove(filepath.Join(e.Root, "var/cache/apt/archives/x.deb"))
		}
		if name == "journalctl" {
			_ = os.Remove(filepath.Join(e.Root, "var/log/journal/m/system@0001-0002.journal"))
		}
		return nil, nil
	}
	p := &agentv1.DiskCleanupParams{Categories: all}
	est, err := e.Cleanup(context.Background(), p, true)
	if err != nil || len(runs) != 0 || len(d.deleted) != 0 {
		t.Fatalf("оценка изменила систему: %v %v %v", err, runs, d.deleted)
	}
	want := []uint64{1000, 300, 100, 50}
	for i, f := range est.GetFreed() {
		if f.GetBytes() != want[i] {
			t.Errorf("оценка %v: %d, ждали %d", f.GetCategory(), f.GetBytes(), want[i])
		}
	}
	e.Free = func(string) (uint64, uint64, error) { return 10, 1000, nil }
	res, err := e.Cleanup(context.Background(), p, false)
	if err != nil {
		t.Fatal(err)
	}
	if res.GetTotalBytes() != 1000 || res.GetFreeBeforeBytes() != 10 {
		t.Fatalf("раздел: %+v", res)
	}
	if strings.Join(d.deleted, ",") != "sha256:free" {
		t.Fatalf("удалены образы %v", d.deleted)
	}
	if !strings.Contains(strings.Join(runs, "\n"), "journalctl --vacuum-time=7d") || !strings.Contains(strings.Join(runs, "\n"), "apt-get clean") {
		t.Fatalf("команды %v", runs)
	}
	if res.GetFreed()[0].GetBytes() != 1000 || res.GetFreed()[1].GetBytes() != 300 || res.GetFreed()[3].GetBytes() != 777 ||
		!strings.Contains(strings.Join(d.posts, ","), `{"until":["24h"]}`) {
		t.Fatalf("итог %+v %v", res, d.posts)
	}
	// Список образов релизов не прочитан — образы не удаляются вовсе.
	d.deleted = nil
	e.TrassaImages = func() (map[string]bool, error) { return nil, errors.New("state.json повреждён") }
	res, err = e.Cleanup(context.Background(), &agentv1.DiskCleanupParams{Categories: all[2:3]}, false)
	if err == nil || len(d.deleted) != 0 || !strings.Contains(res.GetFreed()[0].GetError(), "не прочитаны") {
		t.Fatalf("без списка релизов: %v %v %+v", err, d.deleted, res)
	}
	// Менеджер пакетов занят — категория не чистится, остальные идут.
	e.PackagesBusy = func(context.Context) string { return "lock-frontend (apt, pid 12)" }
	res, err = e.Cleanup(context.Background(), &agentv1.DiskCleanupParams{Categories: all[1:2]}, false)
	if err == nil || !strings.Contains(res.GetFreed()[0].GetError(), "PACKAGE_MANAGER_BUSY") {
		t.Fatalf("занят: %v %+v", err, res)
	}
	for name, bad := range map[string]*agentv1.DiskCleanupParams{
		"пусто":   {},
		"повтор":  {Categories: []agentv1.DiskCleanupCategory{1, 1}},
		"чужая":   {Categories: []agentv1.DiskCleanupCategory{9}},
		"дни":     {Categories: all[:1], JournalKeepDays: 400},
		"раздел":  {Categories: all[:1], Mount: "../etc"},
		"нулевая": {Categories: []agentv1.DiskCleanupCategory{0}},
	} {
		if ValidateCleanup(bad) == nil {
			t.Errorf("%s: принято", name)
		}
	}
}

// certTree — /etc/letsencrypt с одним сертификатом certbot (ссылки live → archive), срок — notAfter.
func certTree(t *testing.T, root, name string, n int, notAfter time.Time) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(int64(n)), Subject: pkix.Name{CommonName: name}, Issuer: pkix.Name{CommonName: "R11"},
		NotBefore: notAfter.Add(-90 * 24 * time.Hour), NotAfter: notAfter, DNSNames: []string{name}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	arch := filepath.Join(root, "etc/letsencrypt/archive", name)
	live := filepath.Join(root, "etc/letsencrypt/live", name)
	_ = os.MkdirAll(arch, 0o700)
	_ = os.MkdirAll(live, 0o755)
	_ = os.MkdirAll(filepath.Join(root, "etc/letsencrypt/renewal"), 0o755)
	_ = os.WriteFile(filepath.Join(root, "etc/letsencrypt/renewal", name+".conf"), []byte("version = 2.9.0\n"), 0o644)
	for _, f := range certFiles {
		base := strings.TrimSuffix(f, ".pem")
		data := []byte("x")
		if f == "cert.pem" {
			data = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		}
		_ = os.WriteFile(filepath.Join(arch, fmt.Sprintf("%s%d.pem", base, n)), data, 0o600)
		_ = os.Remove(filepath.Join(live, f))
		if err := os.Symlink(fmt.Sprintf("../../archive/%s/%s%d.pem", name, base, n), filepath.Join(live, f)); err != nil {
			t.Fatal(err)
		}
	}
}

func TestCertRenew(t *testing.T) {
	e, c := newEnv(t)
	certTree(t, e.Root, "shop.example.com", 1, c.t.Add(10*24*time.Hour))
	conf, cmds, err := e.CertLineage("shop.example.com")
	if err != nil || !strings.HasSuffix(conf, "renewal/shop.example.com.conf") || len(cmds) != 4 ||
		strings.Join(cmds[0], " ") != "/bin/ln -sfn ../../archive/shop.example.com/cert1.pem /etc/letsencrypt/live/shop.example.com/cert.pem" {
		t.Fatalf("%v %s %v", err, conf, cmds)
	}
	var args []string
	e.Run = func(_ context.Context, name string, a ...string) ([]byte, error) {
		args = append([]string{name}, a...)
		certTree(t, e.Root, "shop.example.com", 2, c.t.Add(90*24*time.Hour))
		return nil, nil
	}
	var served time.Time
	e.Served = func(context.Context, string) (*x509.Certificate, error) { return &x509.Certificate{NotAfter: served}, nil }
	served = c.t.Add(90 * 24 * time.Hour).Truncate(time.Second)
	res, err := e.RenewCert(context.Background(), "shop.example.com")
	if err != nil || res.GetNotAfterMs() <= res.GetNotAfterBeforeMs() || res.GetIssuer() != "shop.example.com" || res.GetManager() != "certbot" || !res.GetServedNew() {
		t.Fatalf("%v %+v", err, res)
	}
	if st, err := e.CertState("shop.example.com"); err != nil || st.GetNotAfterBeforeMs() != res.GetNotAfterMs() || st.GetManager() != "certbot" {
		t.Fatalf("предпросмотр: %v %+v", err, st)
	}
	if strings.Join(args, " ") != "certbot renew --cert-name shop.example.com --non-interactive" {
		t.Fatalf("certbot: %v", args)
	}
	// certbot ничего не продлил (0 и рано) — CERT_NOT_DUE.
	e.Run = func(context.Context, string, ...string) ([]byte, error) { return nil, nil }
	if _, err := e.RenewCert(context.Background(), "shop.example.com"); !errors.Is(err, ErrCertNotDue) {
		t.Fatalf("рано: %v", err)
	}
	// Имя прокси Trassa, нет сертификата, ссылка мимо archive — отказы.
	e.ProxyHosts = func() []string { return []string{"*.example.com"} }
	if _, _, err := e.CertLineage("shop.example.com"); !errors.Is(err, ErrCertProxy) {
		t.Fatalf("прокси: %v", err)
	}
	e.ProxyHosts = nil
	if _, _, err := e.CertLineage("none.example.com"); !errors.Is(err, ErrCertNotFound) {
		t.Fatalf("нет: %v", err)
	}
	link := filepath.Join(e.Root, "etc/letsencrypt/live/shop.example.com/cert.pem")
	_ = os.Remove(link)
	_ = os.Symlink("/etc/shadow", link)
	if _, _, err := e.CertLineage("shop.example.com"); !errors.Is(err, ErrCertUnsupport) {
		t.Fatalf("ссылка наружу: %v", err)
	}
	if _, _, err := e.notAfter("shop.example.com"); err == nil {
		t.Fatal("сертификат по ссылке наружу прочитан")
	}
	for _, bad := range []string{"", "Shop.example.com", "../x", "a", "x y.com"} {
		if ValidateCertRenew(&agentv1.CertRenewParams{Domain: bad}) == nil {
			t.Errorf("%q принят", bad)
		}
	}
}

func TestWatcher(t *testing.T) {
	e, c := newEnv(t)
	d, cl := startDocker(t, c)
	e.Docker = cl
	crash := func(code int, policy string) map[string]any {
		return map[string]any{"Id": "c1", "State": map[string]any{"ExitCode": code}, "HostConfig": map[string]any{"RestartPolicy": map[string]any{"Name": policy}}}
	}
	d.list = []map[string]any{{"Id": "c1", "Names": []string{"/worker"}, "State": "exited", "Labels": map[string]string{}}}
	d.cont["c1"] = crash(1, "unless-stopped")
	w := &Watcher{Env: e}
	if ev := w.Containers(context.Background()); len(ev) != 0 {
		t.Fatalf("сразу: %v", ev)
	}
	c.t = c.t.Add(2 * time.Minute)
	ev := w.Containers(context.Background())
	if len(ev) != 1 || ev[0].GetKind() != EventContainerDown || ev[0].GetAttributes()["state"] != "firing" || ev[0].GetAttributes()["exit_code"] != "1" {
		t.Fatalf("упал: %v", ev)
	}
	if ev := w.Containers(context.Background()); len(ev) != 0 {
		t.Fatalf("повтор: %v", ev)
	}
	d.list[0]["State"] = "running"
	if ev := w.Containers(context.Background()); len(ev) != 1 || ev[0].GetAttributes()["state"] != "resolved" {
		t.Fatalf("поднялся: %v", ev)
	}
	// Остановлен вручную (143) или без политики — события нет.
	d.list[0]["State"] = "exited"
	d.cont["c1"] = crash(143, "always")
	c.t = c.t.Add(5 * time.Minute)
	_ = w.Containers(context.Background())
	c.t = c.t.Add(5 * time.Minute)
	if ev := w.Containers(context.Background()); len(ev) != 0 {
		t.Fatalf("ручная остановка: %v", ev)
	}
	// Цикл перезапусков — после трёх опросов.
	d.list[0]["State"] = "restarting"
	d.cont["c1"] = crash(0, "always")
	var got []*agentv1.Event
	for i := 0; i < RestartingTicks; i++ {
		got = append(got, w.Containers(context.Background())...)
	}
	if len(got) != 1 {
		t.Fatalf("цикл перезапусков: %v", got)
	}

	// Сертификаты: пороги 30, 14, 7 по одному разу, снятие после продления.
	certTree(t, e.Root, "a.example.com", 1, c.t.Add(20*24*time.Hour))
	if ev := w.Certs(); len(ev) != 1 || ev[0].GetAttributes()["threshold"] != "30" || ev[0].GetSeverity() != agentv1.EventSeverity_EVENT_SEVERITY_WARN {
		t.Fatalf("30: %v", ev)
	}
	if ev := w.Certs(); len(ev) != 0 {
		t.Fatalf("повтор: %v", ev)
	}
	c.t = c.t.Add(15 * 24 * time.Hour)
	if ev := w.Certs(); len(ev) != 1 || ev[0].GetAttributes()["threshold"] != "7" || ev[0].GetSeverity() != agentv1.EventSeverity_EVENT_SEVERITY_CRIT {
		t.Fatalf("7: %v", ev)
	}
	certTree(t, e.Root, "a.example.com", 2, c.t.Add(90*24*time.Hour))
	if ev := w.Certs(); len(ev) != 1 || ev[0].GetAttributes()["state"] != "resolved" {
		t.Fatalf("продлён: %v", ev)
	}
}
