// SPDX-License-Identifier: AGPL-3.0-only

package deploy

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/tools"
)

const app1 = "01a1f4b6-f2f2-7e66-85b4-8ff5645600a1"

func tool(name, version string) *agentv1.DeployTool {
	return &agentv1.DeployTool{Name: name, Version: version, Sha256: tools.Known[name][version][runtime.GOARCH], Url: "https://github.com/x/" + name}
}

func TestDockerKeyFingerprint(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "docker.asc"))
	if err != nil {
		t.Fatal(err)
	}
	fp, err := keyFingerprint(raw)
	if err != nil || fp != DockerKeyFingerprint {
		t.Fatalf("%s %v", fp, err)
	}
	if _, err := keyFingerprint([]byte("-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nAAAA\n-----END PGP PUBLIC KEY BLOCK-----\n")); err == nil {
		t.Fatal("мусор принят за ключ")
	}
	if aptVersion("29.9.3", "ubuntu", "24.04", "noble") != "5:29.9.3-1~ubuntu.24.04~noble" {
		t.Fatal(aptVersion("29.9.3", "ubuntu", "24.04", "noble"))
	}
	if cmpVersion("27.5.1", MinDocker) >= 0 || cmpVersion("29.1.3", MinDocker) < 0 || cmpVersion("28.0.0", MinDocker) != 0 {
		t.Fatal("сравнение версий")
	}
}

func TestValidate(t *testing.T) {
	ok := &agentv1.DockerEnsureParams{DockerVersion: "29.9.3", LogMaxSize: "20m", LogMaxFiles: 5,
		Plugins: []*agentv1.DeployTool{tool("docker-compose", "5.7.0"), tool("docker-buildx", "0.38.2")}}
	if err := ValidateDockerEnsure(ok); err != nil {
		t.Fatal(err)
	}
	bad := &agentv1.DockerEnsureParams{DockerVersion: "29.9.3", LogMaxSize: "20m", LogMaxFiles: 5,
		Plugins: []*agentv1.DeployTool{tool("docker-compose", "5.7.0"), {Name: "docker-buildx", Version: "0.38.2", Sha256: strings.Repeat("a", 64), Url: "https://x/b"}}}
	if err := ValidateDockerEnsure(bad); !errors.Is(err, ErrToolUnknown) {
		t.Fatalf("сумма не из таблицы: %v", err)
	}
	if ValidateDockerEnsure(&agentv1.DockerEnsureParams{DockerVersion: "27.0.0", LogMaxSize: "20m", LogMaxFiles: 5, Plugins: ok.Plugins}) == nil {
		t.Fatal("неподдерживаемая версия Docker принята")
	}
	if ValidateProxyEnsure(&agentv1.ProxyEnsureParams{Caddy: tool("caddy", "2.11.9"), AcmeEmail: "ops@example.com"}) != nil {
		t.Fatal("proxy.ensure")
	}
	if ValidateProxyEnsure(&agentv1.ProxyEnsureParams{Caddy: tool("railpack", "0.43.0"), AcmeEmail: "ops@example.com"}) == nil {
		t.Fatal("не caddy принят")
	}
	r := func(app string, hosts ...string) *agentv1.ProxyRoute {
		return &agentv1.ProxyRoute{AppId: app, Hosts: hosts}
	}
	if err := ValidateRouteApply(&agentv1.ProxyRouteApplyParams{Routes: []*agentv1.ProxyRoute{r(app1, "app.example.com", "*.example.org")}}); err != nil {
		t.Fatal(err)
	}
	for name, p := range map[string]*agentv1.ProxyRouteApplyParams{
		"пусто":       {},
		"имя дважды":  {Routes: []*agentv1.ProxyRoute{r(app1, "a.example.com"), r(app1, "a.example.com")}},
		"кривое имя":  {Routes: []*agentv1.ProxyRoute{r(app1, "a b.example.com")}},
		"без точки":   {Routes: []*agentv1.ProxyRoute{r(app1, "localhost")}},
		"base_hash":   {Routes: []*agentv1.ProxyRoute{r(app1, "a.example.com")}, BaseHash: "zz"},
		"app не UUID": {Routes: []*agentv1.ProxyRoute{r("app", "a.example.com")}},
	} {
		if ValidateRouteApply(p) == nil {
			t.Errorf("%s принят", name)
		}
	}
	if PinnedImage("registry.example.com:5000/team/app@sha256:"+strings.Repeat("a", 64)) != nil {
		t.Fatal("закреплённый образ отклонён")
	}
	for _, ref := range []string{"nginx:latest", "registry.example.com/app", "app@sha256:abc", "APP@sha256:" + strings.Repeat("a", 64)} {
		if !errors.Is(PinnedImage(ref), ErrImageNotPinned) {
			t.Errorf("%s принят", ref)
		}
	}
}

func targz(t *testing.T, entries map[string]*tar.Header, data map[string]string) []byte {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, h := range entries {
		h.Name = name
		h.Size = int64(len(data[name]))
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		_, _ = tw.Write([]byte(data[name]))
	}
	_ = tw.Close()
	_ = gz.Close()
	return buf.Bytes()
}

// Из архива — только обычный файл caddy в корне: ссылка и файл в подкаталоге не подходят.
func TestUntarOne(t *testing.T) {
	raw := targz(t, map[string]*tar.Header{
		"LICENSE": {Typeflag: tar.TypeReg, Mode: 0o644}, "sub/caddy": {Typeflag: tar.TypeReg, Mode: 0o755},
	}, map[string]string{"LICENSE": "x", "sub/caddy": "evil"})
	if _, err := untarOne(raw, "caddy"); err == nil {
		t.Fatal("файл из подкаталога принят")
	}
	raw = targz(t, map[string]*tar.Header{"caddy": {Typeflag: tar.TypeSymlink, Linkname: "/etc/shadow"}}, nil)
	if _, err := untarOne(raw, "caddy"); err == nil {
		t.Fatal("ссылка принята")
	}
	raw = targz(t, map[string]*tar.Header{"caddy": {Typeflag: tar.TypeReg, Mode: 0o755}}, map[string]string{"caddy": "binary"})
	if b, err := untarOne(raw, "caddy"); err != nil || string(b) != "binary" {
		t.Fatalf("%q %v", b, err)
	}
}

// fakeCaddy — админ-API на Unix-сокете: запоминает загруженный документ.
type fakeCaddy struct {
	mu   sync.Mutex
	docs []map[string]any
	code int
}

func startCaddy(t *testing.T, root string) *fakeCaddy {
	t.Helper()
	sock := filepath.Join(root, AdminSocket)
	_ = os.MkdirAll(filepath.Dir(sock), 0o755)
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Skipf("unix-сокет: %v", err)
	}
	fc := &fakeCaddy{code: http.StatusOK}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/load" {
			var d map[string]any
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &d)
			fc.mu.Lock()
			fc.docs = append(fc.docs, d)
			code := fc.code
			fc.mu.Unlock()
			w.WriteHeader(code)
			if code != http.StatusOK {
				_, _ = w.Write([]byte(`{"error":"loading config: listen tcp :443: bind: address already in use"}`))
			}
			return
		}
		w.WriteHeader(http.StatusOK)
	})}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
	return fc
}

func TestApplyRoutes(t *testing.T) {
	root, err := os.MkdirTemp("/tmp", "trd") // короткий путь для unix-сокета
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	e := &Env{Root: root, StateDir: filepath.Join(root, "state")}
	if _, err := e.ApplyRoutes(context.Background(), &agentv1.ProxyRouteApplyParams{}); !errors.Is(err, ErrProxyMissing) {
		t.Fatalf("без прокси: %v", err)
	}
	fc := startCaddy(t, root)
	st := &ProxyState{Version: "2.11.9", ACMEEmail: "ops@example.com", Apps: map[string][]RouteRec{
		app1: {{Hosts: []string{"app.example.com"}, Dial: "127.0.0.1:20001"}}}}
	if err := e.saveProxy(st); err != nil {
		t.Fatal(err)
	}
	base := RoutesHash(st)
	// Чужая основа — DEPLOY_ROUTES_STALE, ничего не загружается.
	if _, err := e.ApplyRoutes(context.Background(), &agentv1.ProxyRouteApplyParams{BaseHash: strings.Repeat("0", 64),
		Routes: []*agentv1.ProxyRoute{{AppId: app1, Hosts: []string{"new.example.com"}}}}); !errors.Is(err, ErrRoutesStale) || len(fc.docs) != 0 {
		t.Fatalf("устаревшая основа: %v", err)
	}
	res, err := e.ApplyRoutes(context.Background(), &agentv1.ProxyRouteApplyParams{BaseHash: base,
		Routes: []*agentv1.ProxyRoute{{AppId: app1, Hosts: []string{"new.example.com"}}}})
	if err != nil || res.GetRoutesHash() == base {
		t.Fatalf("%+v %v", res, err)
	}
	doc, _ := json.Marshal(fc.docs[0])
	for _, want := range []string{`"dial":"127.0.0.1:20001"`, `"new.example.com"`, `"stream_close_delay":"5m"`, `"listen":"unix//run/trassa-caddy/admin.sock"`, `"grace_period":"30s"`} {
		if !strings.Contains(string(doc), want) {
			t.Errorf("нет %s в %s", want, doc)
		}
	}
	// Ошибка загрузки — прежнее состояние остаётся, код занятого порта.
	fc.code = http.StatusBadRequest
	st2, _ := e.LoadProxy()
	if _, err := e.ApplyRoutes(context.Background(), &agentv1.ProxyRouteApplyParams{BaseHash: RoutesHash(st2),
		Routes: []*agentv1.ProxyRoute{{AppId: app1, Hosts: []string{"third.example.com"}}}}); !errors.Is(err, ErrProxyPort) {
		t.Fatalf("занятый порт: %v", err)
	}
	if st3, _ := e.LoadProxy(); RoutesHash(st3) != res.GetRoutesHash() {
		t.Fatal("состояние изменено при ошибке загрузки")
	}
}

func TestValidateReleaseBuild(t *testing.T) {
	issued := int64(1_800_000_000_000)
	img := "registry.example.com/team/app@sha256:" + strings.Repeat("b", 64)
	sec := &agentv1.SealedSecret{Kid: "0123456789abcdef", EncCt: make([]byte, 64)}
	rel := &agentv1.DeployReleaseParams{AppId: app1, ReleaseId: app1, Kind: agentv1.ReleaseKind_RELEASE_KIND_CONTAINER, ImageRef: img,
		ContainerPort: 8080, Strategy: agentv1.ReleaseStrategy_RELEASE_STRATEGY_ROLLING, DeadlineMs: issued + 600_000,
		Env: map[string]*agentv1.SealedSecret{"DB_PASSWORD": sec}, EnvPlain: map[string]string{"PORT": "8080"},
		Healthcheck: &agentv1.HealthCheck{Path: "/health", TimeoutSec: 120, IntervalMs: 1000, Successes: 3},
		Volumes:     []*agentv1.AppVolume{{Name: "data", MountPath: "/var/lib/app"}},
		Routes:      []*agentv1.ProxyRoute{{AppId: app1, Hosts: []string{"app.example.com"}}}}
	if err := ValidateRelease(rel, issued); err != nil {
		t.Fatal(err)
	}
	clone := func(mod func(p *agentv1.DeployReleaseParams)) *agentv1.DeployReleaseParams {
		c := &agentv1.DeployReleaseParams{}
		*c = agentv1.DeployReleaseParams{AppId: rel.AppId, ReleaseId: rel.ReleaseId, Kind: rel.Kind, ImageRef: rel.ImageRef, ContainerPort: rel.ContainerPort,
			Strategy: rel.Strategy, DeadlineMs: rel.DeadlineMs, Env: rel.Env, EnvPlain: rel.EnvPlain, Healthcheck: rel.Healthcheck, Volumes: rel.Volumes, Routes: rel.Routes}
		mod(c)
		return c
	}
	for name, p := range map[string]*agentv1.DeployReleaseParams{
		"тег вместо дайджеста": clone(func(p *agentv1.DeployReleaseParams) { p.ImageRef = "registry.example.com/team/app:latest" }),
		"секрет и открытая":    clone(func(p *agentv1.DeployReleaseParams) { p.EnvPlain = map[string]string{"DB_PASSWORD": "x"} }),
		"срок дальше 15 мин":   clone(func(p *agentv1.DeployReleaseParams) { p.DeadlineMs = issued + 16*60_000 }),
		"том /":                clone(func(p *agentv1.DeployReleaseParams) { p.Volumes = []*agentv1.AppVolume{{Name: "d", MountPath: "/"}} }),
		"чужой маршрут": clone(func(p *agentv1.DeployReleaseParams) {
			p.Routes = []*agentv1.ProxyRoute{{AppId: "01a1f4b6-f2f2-7e66-85b4-8ff5645600a2", Hosts: []string{"x.example.com"}}}
		}),
		"compose и образ": clone(func(p *agentv1.DeployReleaseParams) {
			p.Kind, p.Compose = agentv1.ReleaseKind_RELEASE_KIND_COMPOSE, "services: {}"
		}),
	} {
		if ValidateRelease(p, issued) == nil {
			t.Errorf("%s принят", name)
		}
	}
	b := &agentv1.DeployBuildParams{AppId: app1, ReleaseId: app1, BuildKind: agentv1.BuildKind_BUILD_KIND_DOCKERFILE,
		Source:        &agentv1.GitSource{RepoUrl: "https://github.com/org/app.git", CommitSha: strings.Repeat("c", 40), Username: "x-access-token", Token: sec},
		MemoryLimitMb: 2048, PushTo: &agentv1.RegistryAuth{Server: "registry.example.com", Username: "builder", Password: sec},
		ImageRepo: "registry.example.com/team/app", DeadlineMs: issued + 30*60_000,
		BuildSecrets: map[string]*agentv1.SealedSecret{"NPM_TOKEN": sec}, BuildArgs: map[string]string{"NODE_ENV": "production"}}
	if err := ValidateBuild(b, issued); err != nil {
		t.Fatal(err)
	}
	b.Source.RepoUrl = "https://user:pass@github.com/org/app.git"
	if ValidateBuild(b, issued) == nil {
		t.Fatal("учётные данные в адресе приняты")
	}
	b.Source.RepoUrl = "https://github.com/org/app.git"
	b.ImageRepo = "other.example.com/team/app"
	if ValidateBuild(b, issued) == nil {
		t.Fatal("образ в чужой реестр принят")
	}
	b.ImageRepo, b.Source.RootDir = "registry.example.com/team/app", "../etc"
	if ValidateBuild(b, issued) == nil {
		t.Fatal("root_dir с .. принят")
	}
	if ValidateControl(&agentv1.DeployControlParams{AppId: app1, Action: agentv1.ControlAction_CONTROL_ACTION_RESTART, DeadlineMs: issued + 60_000}, issued) != nil ||
		ValidateImagesPrune(&agentv1.DeployImagesPruneParams{AppId: app1, KeepImages: []string{"app:latest"}}) == nil {
		t.Fatal("control или prune")
	}
}
