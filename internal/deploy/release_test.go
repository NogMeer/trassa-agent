// SPDX-License-Identifier: AGPL-3.0-only

package deploy

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	secretkey "github.com/NogMeer/trassa-agent/internal/sealed"
)

// fakeDocker — Engine API на Unix-сокете: контейнер при start слушает свой порт 127.0.0.1 (ответ health).
type fakeDocker struct {
	mu         sync.Mutex
	t          *testing.T
	containers map[string]*fakeContainer
	images     map[string]int64
	auth       []string
	pulls      []string
	n          int
	health     func(image string) int // код ответа контейнера образа
	pullErr    string
	waitCode   int
}

type fakeContainer struct {
	ID, Name, Image, State string
	Labels                 map[string]string
	Port                   string
	Env                    []string
	Spec                   map[string]any
	srv                    *http.Server
}

func startDocker(t *testing.T, root string) (*fakeDocker, string) {
	t.Helper()
	sock := filepath.Join(root, "docker.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Skipf("unix-сокет: %v", err)
	}
	fd := &fakeDocker{t: t, containers: map[string]*fakeContainer{}, images: map[string]int64{}, health: func(string) int { return 200 }}
	srv := &http.Server{Handler: http.HandlerFunc(fd.serve)}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() {
		_ = srv.Close()
		fd.mu.Lock()
		defer fd.mu.Unlock()
		for _, c := range fd.containers {
			if c.srv != nil {
				_ = c.srv.Close()
			}
		}
	})
	return fd, sock
}

func (fd *fakeDocker) serve(w http.ResponseWriter, r *http.Request) {
	fd.mu.Lock()
	defer fd.mu.Unlock()
	w.Header().Set("Api-Version", "1.44")
	p := strings.TrimPrefix(r.URL.Path, "/v1.44")
	parts := strings.Split(strings.Trim(p, "/"), "/")
	switch {
	case p == "/_ping":
		_, _ = w.Write([]byte("OK"))
	case p == "/version":
		_, _ = w.Write([]byte(`{"Version":"29.9.3","ApiVersion":"1.52"}`))
	case p == "/images/create":
		fd.auth = append(fd.auth, r.Header.Get("X-Registry-Auth"))
		ref := r.URL.Query().Get("fromImage") + "@" + r.URL.Query().Get("tag")
		fd.pulls = append(fd.pulls, ref)
		if fd.pullErr != "" {
			_, _ = fmt.Fprintf(w, "{\"status\":\"Pulling\"}\n{\"error\":%q}\n", fd.pullErr)
			return
		}
		fd.images[ref] = 1000
		_, _ = w.Write([]byte("{\"status\":\"Downloaded\"}\n"))
	case p == "/networks/create":
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"Id":"net1"}`))
	case strings.HasPrefix(p, "/networks"):
		_, _ = w.Write([]byte(`[]`))
	case strings.HasPrefix(p, "/volumes"):
		_, _ = w.Write([]byte(`{"Volumes":[]}`))
	case p == "/containers/json":
		var f map[string][]string
		_ = json.Unmarshal([]byte(r.URL.Query().Get("filters")), &f)
		type port struct {
			IP         string `json:"IP"`
			PublicPort uint16 `json:"PublicPort"`
		}
		var out []map[string]any
		for _, c := range fd.containers {
			if lf := f["label"]; len(lf) > 0 {
				k, v, has := strings.Cut(lf[0], "=")
				if _, ok := c.Labels[k]; !ok || (has && c.Labels[k] != v) {
					continue
				}
			}
			var ports []port
			if c.Port != "" && c.State == "running" {
				var n uint16
				_, _ = fmt.Sscan(c.Port, &n)
				ports = append(ports, port{IP: "127.0.0.1", PublicPort: n})
			}
			out = append(out, map[string]any{"Id": c.ID, "Names": []string{"/" + c.Name}, "Image": c.Image, "ImageID": "sha256:" + c.Image,
				"State": c.State, "Labels": c.Labels, "Ports": ports})
		}
		_ = json.NewEncoder(w).Encode(out)
	case p == "/containers/create":
		var spec map[string]any
		_ = json.NewDecoder(r.Body).Decode(&spec)
		fd.n++
		c := &fakeContainer{ID: fmt.Sprintf("c%d", fd.n), Name: r.URL.Query().Get("name"), Image: spec["Image"].(string), State: "created", Spec: spec}
		c.Labels = map[string]string{}
		for k, v := range spec["Labels"].(map[string]any) {
			c.Labels[k] = v.(string)
		}
		for _, e := range spec["Env"].([]any) {
			c.Env = append(c.Env, e.(string))
		}
		if hc, ok := spec["HostConfig"].(map[string]any); ok {
			if pb, ok := hc["PortBindings"].(map[string]any); ok {
				for _, b := range pb {
					c.Port = b.([]any)[0].(map[string]any)["HostPort"].(string)
				}
			}
		}
		fd.containers[c.ID] = c
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{"Id": c.ID})
	case len(parts) == 3 && parts[0] == "containers":
		c := fd.containers[parts[1]]
		if c == nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		switch parts[2] {
		case "start":
			c.State = "running"
			if c.Port != "" {
				code := fd.health(c.Image)
				l, err := net.Listen("tcp", "127.0.0.1:"+c.Port)
				if err != nil {
					fd.t.Errorf("порт контейнера: %v", err)
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				c.srv = &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(code) })}
				go func() { _ = c.srv.Serve(l) }()
			}
			w.WriteHeader(http.StatusNoContent)
		case "stop", "restart":
			if c.srv != nil {
				_ = c.srv.Close()
				c.srv = nil
			}
			c.State = "exited"
			w.WriteHeader(http.StatusNoContent)
		case "wait":
			_ = json.NewEncoder(w).Encode(map[string]int{"StatusCode": fd.waitCode})
		case "logs":
			msg := []byte("boot failed: password=hunter2-secret\n")
			var hdr [8]byte
			hdr[0] = 2
			binary.BigEndian.PutUint32(hdr[4:], uint32(len(msg)))
			_, _ = w.Write(append(hdr[:], msg...))
		}
	case len(parts) == 2 && parts[0] == "containers" && r.Method == http.MethodDelete:
		if c := fd.containers[parts[1]]; c != nil {
			if c.srv != nil {
				_ = c.srv.Close()
			}
			delete(fd.containers, parts[1])
		}
		w.WriteHeader(http.StatusNoContent)
	case strings.HasPrefix(p, "/images/") && strings.HasSuffix(p, "/push"):
		fd.auth = append(fd.auth, r.Header.Get("X-Registry-Auth"))
		if fd.pullErr != "" {
			_, _ = fmt.Fprintf(w, "{\"error\":%q}\n", fd.pullErr)
			return
		}
		_, _ = w.Write([]byte("{\"status\":\"Pushed\"}\n{\"aux\":{\"Tag\":\"x\",\"Digest\":\"sha256:" + strings.Repeat("f", 64) + "\",\"Size\":10}}\n"))
	case strings.HasPrefix(p, "/containers/buildx_buildkit_"):
		_, _ = w.Write([]byte(`{"State":{"OOMKilled":false}}`))
	case strings.HasPrefix(p, "/images/") && strings.HasSuffix(p, "/json"):
		ref := strings.TrimSuffix(strings.TrimPrefix(p, "/images/"), "/json")
		if _, ok := fd.images[ref]; !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"Id": "sha256:" + ref, "Size": fd.images[ref]})
	case strings.HasPrefix(p, "/images/") && r.Method == http.MethodDelete:
		delete(fd.images, strings.TrimPrefix(p, "/images/"))
		_, _ = w.Write([]byte(`[]`))
	default:
		fd.t.Errorf("неожиданный вызов %s %s", r.Method, p)
		w.WriteHeader(http.StatusNotImplemented)
	}
}

// reset — все контейнеры убраны (их порты освобождены).
func (fd *fakeDocker) reset() {
	fd.mu.Lock()
	defer fd.mu.Unlock()
	for _, c := range fd.containers {
		if c.srv != nil {
			_ = c.srv.Close()
		}
	}
	fd.containers = map[string]*fakeContainer{}
}

func (fd *fakeDocker) running(app string) []*fakeContainer {
	fd.mu.Lock()
	defer fd.mu.Unlock()
	var out []*fakeContainer
	for _, c := range fd.containers {
		if c.Labels[LabelApp] == app && c.State == "running" {
			out = append(out, c)
		}
	}
	return out
}

type deployFixture struct {
	e    *Env
	d    *fakeDocker
	c    *fakeCaddy
	key  *secretkey.Key
	body *agentv1.OperationBody
}

func newDeployFixture(t *testing.T) *deployFixture {
	t.Helper()
	root, err := os.MkdirTemp("/tmp", "trd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	if root, err = filepath.EvalSymlinks(root); err != nil { // /tmp на macOS — ссылка, а пути проходятся без ссылок
		t.Fatal(err)
	}
	d, sock := startDocker(t, root)
	c := startCaddy(t, root)
	e := &Env{Root: root, Docker: &dockerapi.Client{Socket: sock}, StateDir: filepath.Join(root, "state"), AppsDir: filepath.Join(root, "apps")}
	if err := e.saveProxy(&ProxyState{Version: "2.11.9", ACMEEmail: "ops@example.com", Apps: map[string][]RouteRec{}}); err != nil {
		t.Fatal(err)
	}
	k, err := secretkey.LoadOrCreate(filepath.Join(root, "k.key"))
	if err != nil {
		t.Fatal(err)
	}
	body := &agentv1.OperationBody{ServerId: app1, OperationId: "01a1f4b6-f2f2-7e66-85b4-8ff5645600ff", Type: "deploy.release"}
	return &deployFixture{e: e, d: d, c: c, key: k, body: body}
}

func (f *deployFixture) seal(t *testing.T, field, v string) *agentv1.SealedSecret {
	t.Helper()
	s, err := secretkey.Seal(f.key.Public(), secretkey.Info(f.body.GetServerId(), secretkey.KeyID(f.key.Public()), f.body.GetOperationId(), f.body.GetType(), app1, field), []byte(v))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func digest(c byte) string {
	return "registry.example.com/team/app@sha256:" + strings.Repeat(string(c), 64)
}

func (f *deployFixture) release(t *testing.T, rel string, img string) *agentv1.DeployReleaseParams {
	return &agentv1.DeployReleaseParams{AppId: app1, ReleaseId: rel, Kind: agentv1.ReleaseKind_RELEASE_KIND_CONTAINER, ImageRef: img,
		ContainerPort: 8080, Strategy: agentv1.ReleaseStrategy_RELEASE_STRATEGY_ROLLING,
		Env:         map[string]*agentv1.SealedSecret{"DB_PASSWORD": f.seal(t, FieldEnv+"DB_PASSWORD", "hunter2-secret")},
		EnvPlain:    map[string]string{"PORT": "8080"},
		PullFrom:    &agentv1.RegistryAuth{Server: "registry.example.com", Username: "puller", Password: f.seal(t, FieldRegistry, "pull-pass-1")},
		Healthcheck: &agentv1.HealthCheck{Path: "/health", TimeoutSec: 5, IntervalMs: 100, Successes: 2},
		Routes:      []*agentv1.ProxyRoute{{AppId: app1, Hosts: []string{"app.example.com"}}}}
}

func (f *deployFixture) run(p *agentv1.DeployReleaseParams) (*agentv1.DeployReleaseResult, bool, error) {
	return f.e.Release(context.Background(), ReleaseJob{Params: p, Open: &Opener{Key: f.key, Body: f.body, App: app1}})
}

const rel1, rel2 = "01a1f4b6-f2f2-7e66-85b4-8ff5645600b1", "01a1f4b6-f2f2-7e66-85b4-8ff5645600b2"

func TestReleaseContainer(t *testing.T) {
	f := newDeployFixture(t)
	res, rolled, err := f.run(f.release(t, rel1, digest('a')))
	if err != nil || rolled {
		t.Fatalf("первый релиз: %v %+v", err, res)
	}
	run := f.d.running(app1)
	if len(run) != 1 || run[0].Name != ContainerName(app1, rel1) {
		t.Fatalf("контейнеры: %+v", run)
	}
	c := run[0]
	// Секрет расшифрован в окружение; учётные данные только на pull, в X-Registry-Auth.
	if strings.Join(c.Env, ",") != "DB_PASSWORD=hunter2-secret,PORT=8080" {
		t.Errorf("окружение %v", c.Env)
	}
	raw, _ := base64.URLEncoding.DecodeString(f.d.auth[0])
	if !strings.Contains(string(raw), `"password":"pull-pass-1"`) || !strings.Contains(string(raw), `"serveraddress":"registry.example.com"`) {
		t.Errorf("X-Registry-Auth %s", raw)
	}
	hc, _ := json.Marshal(c.Spec["HostConfig"])
	for _, want := range []string{`"HostIp":"127.0.0.1"`, `"no-new-privileges"`, `"Type":"local"`, `"max-file":"5"`} {
		if !strings.Contains(string(hc), want) {
			t.Errorf("нет %s в %s", want, hc)
		}
	}
	st, _ := f.e.LoadProxy()
	if got := st.Apps[app1][0].Dial; got != "127.0.0.1:"+c.Port || res.GetRoutesHash() != RoutesHash(st) {
		t.Fatalf("маршрут %q, порт %s", got, c.Port)
	}

	// Второй релиз: новый контейнер, маршрут на него, старый остановлен и удалён.
	res2, _, err := f.run(f.release(t, rel2, digest('b')))
	if err != nil || res2.GetPreviousReleaseId() != rel1 {
		t.Fatalf("второй релиз: %v %+v", err, res2)
	}
	run = f.d.running(app1)
	if len(run) != 1 || run[0].Labels[LabelRelease] != rel2 || len(f.d.containers) != 1 {
		t.Fatalf("после второго релиза: %+v", f.d.containers)
	}
	st, _ = f.e.LoadProxy()
	if st.Apps[app1][0].Dial != "127.0.0.1:"+run[0].Port || run[0].Port == c.Port {
		t.Fatalf("маршрут не переключён: %+v", st.Apps[app1])
	}
	app, _ := f.e.loadApp(app1)
	if len(app.Images) != 2 {
		t.Fatalf("образы приложения %v", app.Images)
	}

	// Провал проверки здоровья: новый удалён, маршрут и прежний контейнер на месте, журнал без секрета.
	f.d.health = func(img string) int { return 503 }
	before := RoutesHash(st)
	res3, rolled, err := f.run(f.release(t, "01a1f4b6-f2f2-7e66-85b4-8ff5645600b3", digest('c')))
	if !errors.Is(err, ErrHealthcheck) || !rolled || res3.GetFailedStep() != agentv1.DeployStep_DEPLOY_STEP_HEALTHCHECK {
		t.Fatalf("провал проверки: %v %v %+v", err, rolled, res3)
	}
	if strings.Contains(res3.GetLogTail(), "hunter2-secret") || !strings.Contains(res3.GetLogTail(), "boot failed") {
		t.Errorf("журнал %q", res3.GetLogTail())
	}
	if run := f.d.running(app1); len(run) != 1 || run[0].Labels[LabelRelease] != rel2 || len(f.d.containers) != 1 {
		t.Fatalf("прежний релиз не сохранён: %+v", f.d.containers)
	}
	if st, _ := f.e.LoadProxy(); RoutesHash(st) != before {
		t.Fatal("маршрут изменён при провале")
	}

	// Повтор работающего релиза — отказ, ничего не трогается.
	if _, _, err := f.run(f.release(t, rel2, digest('b'))); err == nil {
		t.Fatal("работающий релиз пересоздан")
	}

	// Чистка: образ работающего и из keep остаются, прочие удаляются по списку.
	removed, _, err := f.e.pruneImages(context.Background(), app1, nil)
	if err != nil || len(removed) != 1 || removed[0] != digest('a') {
		t.Fatalf("чистка: %v %v", removed, err)
	}
}

func TestReleasePullAndPreDeploy(t *testing.T) {
	f := newDeployFixture(t)
	f.d.pullErr = "unauthorized: authentication required for pull-pass-1"
	res, rolled, err := f.run(f.release(t, rel1, digest('a')))
	if !errors.Is(err, ErrRegistryAuth) || rolled || res.GetFailedStep() != agentv1.DeployStep_DEPLOY_STEP_PULL || strings.Contains(err.Error(), "pull-pass-1") {
		t.Fatalf("pull: %v %+v", err, res)
	}
	f.d.pullErr = ""
	p := f.release(t, rel1, digest('a'))
	p.PreDeployCommand, p.PreDeployTimeoutSec = []string{"./migrate"}, 30
	f.d.waitCode = 3
	res, _, err = f.run(p)
	if !errors.Is(err, ErrPreDeploy) || strings.Contains(err.Error(), "hunter2-secret") || len(f.d.containers) != 0 {
		t.Fatalf("pre_deploy: %v %+v %v", err, res, f.d.containers)
	}
	if _, err := f.e.LoadProxy(); err != nil {
		t.Fatal(err)
	}
	if len(f.c.docs) != 0 {
		t.Fatal("маршрут загружен до проверки")
	}
	// Секрет, переложенный в другое поле, не открывается.
	p = f.release(t, rel1, digest('a'))
	p.Env = map[string]*agentv1.SealedSecret{"OTHER": p.GetEnv()["DB_PASSWORD"]}
	f.d.waitCode = 0
	if _, _, err := f.run(p); err == nil {
		t.Fatal("секрет из другого поля открыт")
	}
}

func TestRemoveAndControl(t *testing.T) {
	f := newDeployFixture(t)
	if _, _, err := f.run(f.release(t, rel1, digest('a'))); err != nil {
		t.Fatal(err)
	}
	if _, err := f.e.Control(context.Background(), &agentv1.DeployControlParams{AppId: app1, Action: agentv1.ControlAction_CONTROL_ACTION_STOP}); err != nil {
		t.Fatal(err)
	}
	if len(f.d.running(app1)) != 0 {
		t.Fatal("не остановлен")
	}
	if _, err := f.e.Control(context.Background(), &agentv1.DeployControlParams{AppId: "01a1f4b6-f2f2-7e66-85b4-8ff5645600cc",
		Action: agentv1.ControlAction_CONTROL_ACTION_START}); !errors.Is(err, ErrAppMissing) {
		t.Fatalf("чужое приложение: %v", err)
	}
	res, err := f.e.Remove(context.Background(), &agentv1.DeployRemoveParams{AppId: app1})
	if err != nil || res.GetRemovedContainers() != 1 || res.GetRemovedImages() != 1 || len(f.d.containers) != 0 {
		t.Fatalf("удаление: %v %+v", err, res)
	}
	if st, _ := f.e.LoadProxy(); len(st.Apps) != 0 {
		t.Fatal("маршрут остался")
	}
	if _, err := os.Lstat(f.e.appDir(app1)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("каталог приложения: %v", err)
	}
}

// fakeCompose — docker compose: config печатает записанный документ (как нормализованный вид), up запускает
// сервисы в подделке Docker.
func (f *deployFixture) fakeCompose(t *testing.T, normalize func([]byte) []byte, upErr error) *[][]string {
	var calls [][]string
	f.e.Exec = func(_ context.Context, env []string, name string, args ...string) ([]byte, error) {
		calls = append(calls, append([]string{name}, args...))
		for _, want := range []string{"COMPOSE_EXPERIMENTAL_GIT_REMOTE=false", "COMPOSE_EXPERIMENTAL_OCI_REMOTE=false"} {
			if !strings.Contains(strings.Join(env, "\n"), want) {
				t.Errorf("нет %s", want)
			}
		}
		dir := ""
		for i, a := range args {
			if a == "--project-directory" {
				dir = args[i+1]
			}
		}
		raw, err := os.ReadFile(filepath.Join(dir, composeFile))
		if err != nil {
			return nil, err
		}
		verb := ""
		for _, a := range args {
			if a == "config" || a == "up" || a == "down" {
				verb = a
				break
			}
		}
		switch verb {
		case "config":
			return normalize(raw), nil
		case "up":
			if upErr != nil {
				return nil, upErr
			}
			var doc map[string]any
			_ = json.Unmarshal(raw, &doc)
			f.d.mu.Lock()
			for name, s := range doc["services"].(map[string]any) {
				svc := s.(map[string]any)
				labels := map[string]string{}
				for k, v := range svc["labels"].(map[string]any) {
					labels[k] = v.(string)
				}
				f.d.n++
				c := &fakeContainer{ID: fmt.Sprintf("c%d", f.d.n), Name: name, Image: svc["image"].(string), State: "running", Labels: labels}
				if ps, ok := svc["ports"].([]any); ok {
					c.Port = ps[0].(map[string]any)["published"].(string)
					l, err := net.Listen("tcp", "127.0.0.1:"+c.Port)
					if err != nil {
						f.d.mu.Unlock()
						return nil, err
					}
					c.srv = &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {})}
					go func() { _ = c.srv.Serve(l) }()
				}
				f.d.containers[c.ID] = c
			}
			f.d.mu.Unlock()
		}
		return nil, nil
	}
	return &calls
}

const composeDoc = `{"services":{"web":{"image":"registry.example.com/team/web@sha256:` + "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd" + `",
 "environment":{"DB_URL":"postgres://app:${DB_PASSWORD}@db/app","MODE":"prod"},"depends_on":{"db":{"condition":"service_healthy"}},
 "volumes":["uploads:/srv/uploads"],"deploy":{"resources":{"limits":{"memory":"512m","cpus":"0.5"}}}},
 "db":{"image":"docker.io/library/postgres@sha256:` + "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" + `",
 "environment":["POSTGRES_PASSWORD=${DB_PASSWORD}"],"volumes":[{"type":"volume","source":"pg","target":"/var/lib/postgresql/data"}],
 "healthcheck":{"test":["CMD","pg_isready"],"interval":"5s","retries":5}}},
 "volumes":{"uploads":{},"pg":null}}`

func (f *deployFixture) composeRelease(t *testing.T, doc string) *agentv1.DeployReleaseParams {
	return &agentv1.DeployReleaseParams{AppId: app1, ReleaseId: rel1, Kind: agentv1.ReleaseKind_RELEASE_KIND_COMPOSE, Compose: doc,
		ContainerPort: 80, Strategy: agentv1.ReleaseStrategy_RELEASE_STRATEGY_RECREATE,
		Env:         map[string]*agentv1.SealedSecret{"DB_PASSWORD": f.seal(t, FieldEnv+"DB_PASSWORD", "pg-secret-1")},
		Healthcheck: &agentv1.HealthCheck{Path: "/", TimeoutSec: 5, IntervalMs: 100, Successes: 1},
		Routes:      []*agentv1.ProxyRoute{{AppId: app1, Hosts: []string{"web.example.com"}, Service: "web"}}}
}

func TestReleaseCompose(t *testing.T) {
	f := newDeployFixture(t)
	calls := f.fakeCompose(t, func(b []byte) []byte { return b }, nil)
	res, rolled, err := f.e.Release(context.Background(), ReleaseJob{Params: f.composeRelease(t, composeDoc), Open: &Opener{Key: f.key, Body: f.body, App: app1}})
	if err != nil || rolled {
		t.Fatalf("compose: %v %+v", err, res)
	}
	if len(f.d.pulls) != 2 {
		t.Fatalf("образы: %v", f.d.pulls)
	}
	raw, _ := os.ReadFile(filepath.Join(f.e.appDir(app1), "compose", composeFile))
	s := string(raw)
	for _, want := range []string{`"host_ip": "127.0.0.1"`, `"no-new-privileges:true"`, `"pull_policy": "never"`, `"name": "trassa-01a1f4b6f2f2-uploads"`,
		`${DB_PASSWORD}`, `"trassa.app_id": "` + app1 + `"`} {
		if !strings.Contains(s, want) {
			t.Errorf("нет %s в compose.json", want)
		}
	}
	if strings.Contains(s, "pg-secret-1") {
		t.Fatal("секрет записан в compose.json")
	}
	if fi, _ := os.Stat(filepath.Join(f.e.appDir(app1), "compose", composeFile)); fi.Mode().Perm() != 0o600 {
		t.Errorf("права %v", fi.Mode())
	}
	var up []string
	for _, c := range *calls {
		if strings.Contains(strings.Join(c, " "), " up ") {
			up = c
		}
	}
	if !strings.Contains(strings.Join(up, " "), "--project-name trassa-01a1f4b6f2f2") || !strings.Contains(strings.Join(up, " "), "--pull never") {
		t.Errorf("up: %v", up)
	}
	st, _ := f.e.LoadProxy()
	if st.Apps[app1][0].Service != "web" || !strings.HasPrefix(st.Apps[app1][0].Dial, "127.0.0.1:") {
		t.Fatalf("маршрут %+v", st.Apps[app1])
	}

	// Повторный релиз: тот же порт сервиса (маршрут не меняется), compose пересоздаёт сервисы на месте.
	dial := st.Apps[app1][0].Dial
	f.d.reset()
	p := f.composeRelease(t, composeDoc)
	p.ReleaseId = rel2
	if _, _, err := f.e.Release(context.Background(), ReleaseJob{Params: p, Open: &Opener{Key: f.key, Body: f.body, App: app1}}); err != nil {
		t.Fatalf("повторный compose: %v", err)
	}
	if st, _ := f.e.LoadProxy(); st.Apps[app1][0].Dial != dial {
		t.Fatalf("порт сменился: %s → %s", dial, st.Apps[app1][0].Dial)
	}
	s, _ = func() (string, error) {
		b, err := os.ReadFile(filepath.Join(f.e.appDir(app1), "compose", composeFile))
		return string(b), err
	}()

	// Нормализованный вид с запрещённым ключом — отказ до up, файл возвращается прежним.
	f.d.reset()
	*calls = nil
	f.fakeCompose(t, func(b []byte) []byte {
		return []byte(strings.Replace(string(b), `"image": `, `"privileged": true, "image": `, 1))
	}, nil)
	p = f.composeRelease(t, composeDoc)
	p.ReleaseId = "01a1f4b6-f2f2-7e66-85b4-8ff5645600b3"
	if _, _, err := f.e.Release(context.Background(), ReleaseJob{Params: p, Open: &Opener{Key: f.key, Body: f.body, App: app1}}); !errors.Is(err, ErrComposeDenied) || !strings.Contains(err.Error(), "privileged") {
		t.Fatalf("нормализованный вид: %v", err)
	}
	if now, _ := os.ReadFile(filepath.Join(f.e.appDir(app1), "compose", composeFile)); string(now) != s {
		t.Fatal("compose.json не возвращён")
	}
}

func composeSpecFor(vars ...string) *composeSpec {
	v := map[string]bool{}
	for _, n := range vars {
		v[n] = true
	}
	return &composeSpec{App: app1, Release: rel1, Vars: v, Ports: map[string]int{"web": 20001}, ContainerPort: 80, LogOpts: map[string]string{"max-size": "20m"}}
}

func TestComposeWhitelist(t *testing.T) {
	img := `"image":"registry.example.com/team/web@sha256:` + strings.Repeat("d", 64) + `"`
	if _, _, err := ComposeDoc(`{"services":{"web":{`+img+`}}}`, composeSpecFor()); err != nil {
		t.Fatalf("простой документ: %v", err)
	}
	if _, _, err := ComposeDoc(composeDoc, composeSpecFor("DB_PASSWORD")); err != nil {
		t.Fatalf("полный документ: %v", err)
	}
	for name, doc := range map[string]string{
		"YAML":                 "services:\n  web:\n    image: x\n",
		"повтор ключа":         `{"services":{"web":{` + img + `,` + img + `}}}`,
		"тег":                  `{"services":{"web":{"image":"nginx:latest"}}}`,
		"privileged":           `{"services":{"web":{` + img + `,"privileged":true}}}`,
		"cap_add":              `{"services":{"web":{` + img + `,"cap_add":["SYS_ADMIN"]}}}`,
		"network_mode host":    `{"services":{"web":{` + img + `,"network_mode":"host"}}}`,
		"pid host":             `{"services":{"web":{` + img + `,"pid":"host"}}}`,
		"bind сокета Docker":   `{"services":{"web":{` + img + `,"volumes":["/var/run/docker.sock:/var/run/docker.sock"]}}}`,
		"bind длинный":         `{"services":{"web":{` + img + `,"volumes":[{"type":"bind","source":"/","target":"/host"}]}}}`,
		"том с driver_opts":    `{"services":{"web":{` + img + `,"volumes":["d:/d"]}},"volumes":{"d":{"driver_opts":{"type":"none","o":"bind","device":"/etc"}}}}`,
		"внешний том":          `{"services":{"web":{` + img + `}},"volumes":{"d":{"external":true}}}`,
		"порт наружу":          `{"services":{"web":{` + img + `,"ports":["0.0.0.0:80:80"]}}}`,
		"env_file":             `{"services":{"web":{` + img + `,"env_file":"/etc/shadow"}}}`,
		"include":              `{"include":["https://example.com/x.yml"],"services":{"web":{` + img + `}}}`,
		"extends":              `{"services":{"web":{` + img + `,"extends":{"file":"/etc/x.yml","service":"a"}}}}`,
		"build":                `{"services":{"web":{"build":"."}}}`,
		"secrets file":         `{"services":{"web":{` + img + `}},"secrets":{"s":{"file":"/root/.ssh/id_ed25519"}}}`,
		"x-расширение":         `{"x-a":{},"services":{"web":{` + img + `}}}`,
		"devices":              `{"services":{"web":{` + img + `,"devices":["/dev/sda"]}}}`,
		"security_opt":         `{"services":{"web":{` + img + `,"security_opt":["seccomp=unconfined"]}}}`,
		"метка trassa":         `{"services":{"web":{` + img + `,"labels":{"trassa.app_id":"other"}}}}`,
		"чужая подстановка":    `{"services":{"web":{` + img + `,"environment":{"A":"${HOME}"}}}}`,
		"подстановка по умолч": `{"services":{"web":{` + img + `,"environment":{"A":"${DB_PASSWORD:-x}"}}}}`,
		"подстановка в image":  `{"services":{"web":{"image":"${DB_PASSWORD}"}}}`,
		"нет сервиса маршрута": `{"services":{"api":{` + img + `}}}`,
		"глубина":              `{"services":{"web":{` + img + `,"command":` + strings.Repeat("[", 40) + strings.Repeat("]", 40) + `}}}`,
		"хвост":                `{"services":{"web":{` + img + `}}} {}`,
	} {
		if _, _, err := ComposeDoc(doc, composeSpecFor("DB_PASSWORD")); !errors.Is(err, ErrComposeDenied) && !errors.Is(err, ErrImageNotPinned) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// $$ — буквальный знак, подстановки нет.
	if _, _, err := ComposeDoc(`{"services":{"web":{`+img+`,"command":"echo $$HOME"}}}`, composeSpecFor()); err != nil {
		t.Errorf("$$: %v", err)
	}
	// Нормализованный вид: порт ровно тот, что назначил агент.
	out, _, _ := ComposeDoc(`{"services":{"web":{`+img+`}}}`, composeSpecFor())
	if err := CheckNormalized(out, composeSpecFor()); err != nil {
		t.Fatalf("свой вид: %v", err)
	}
	other := strings.Replace(string(out), `"published": "20001"`, `"published": "8080"`, 1)
	if err := CheckNormalized([]byte(other), composeSpecFor()); !errors.Is(err, ErrComposeDenied) {
		t.Fatalf("чужой порт: %v", err)
	}
	wide := strings.Replace(string(out), `"host_ip": "127.0.0.1"`, `"host_ip": "0.0.0.0"`, 1)
	if err := CheckNormalized([]byte(wide), composeSpecFor()); !errors.Is(err, ErrComposeDenied) {
		t.Fatalf("0.0.0.0: %v", err)
	}
}

func TestReadFrame(t *testing.T) {
	var b strings.Builder
	w := bufio.NewWriter(&b)
	hdr := []byte{1, 0, 0, 0, 0, 0, 0, 3}
	_, _ = w.Write(append(hdr, 'a', 'b', 'c'))
	_ = w.Flush()
	_, p, err := readFrame(strings.NewReader(b.String()))
	if err != nil || string(p) != "abc" {
		t.Fatal(p, err)
	}
	big := []byte{1, 0, 0, 0, 0x7f, 0, 0, 0}
	if _, _, err := readFrame(strings.NewReader(string(big))); err == nil {
		t.Fatal("огромный кадр принят")
	}
	if _, _, err := readFrame(strings.NewReader("")); !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
	_ = time.Second
}
