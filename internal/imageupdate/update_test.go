// SPDX-License-Identifier: AGPL-3.0-only

package imageupdate

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
)

func validParams() *agentv1.ContainerUpdateParams {
	return &agentv1.ContainerUpdateParams{Container: "shop-web-1", Project: "shop", Service: "web",
		CurrentImage: "nginx:1.28", TargetTag: "1.30", WaitSec: 30}
}

// fakeDocker — контейнер сервиса web; после up образ контейнера — тот, что даёт текущий compose-файл.
type fakeDocker struct {
	c       Container
	running func() []Container
	tagged  []string
}

func (d *fakeDocker) Inspect(_ context.Context, name string) (*Container, error) {
	if name != d.c.Name {
		return nil, ErrNotFound
	}
	c := d.c
	return &c, nil
}

func (d *fakeDocker) Service(context.Context, string, string) ([]Container, error) {
	return d.running(), nil
}

func (d *fakeDocker) Tag(_ context.Context, id, repo, tag string) error {
	d.tagged = append(d.tagged, id+"→"+repo+":"+tag)
	return nil
}

type world struct {
	t       *testing.T
	root    string
	env     *Env
	docker  *fakeDocker
	calls   []string
	upImage string // образ, с которым поднят сервис последним up
	failOn  string // подкоманда compose, которая падает
	health  func(image string) (string, string)
	extra   map[string]any // лишнее изменение конфигурации после правки (проверка сверки)
	stderr  string
	backups [][]byte
	saved   string
}

const composeYML = `services:
  web:
    image: nginx:1.28
  db:
    image: postgres:17.6
`

func newWorld(t *testing.T, compose, env string) *world {
	t.Helper()
	w := &world{t: t, root: t.TempDir(), health: func(string) (string, string) { return "running", "" }}
	dir := filepath.Join(w.root, "srv/shop")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	must(t, os.WriteFile(filepath.Join(dir, "compose.yml"), []byte(compose), 0o640))
	if env != "" {
		must(t, os.WriteFile(filepath.Join(dir, ".env"), []byte(env), 0o600))
	}
	w.upImage = "nginx:1.28"
	w.docker = &fakeDocker{c: Container{ID: "c1", Name: "shop-web-1", ImageID: "sha256:old", Image: "nginx:1.28", Status: "running",
		Labels: map[string]string{LabelProject: "shop", LabelService: "web", LabelWorkingDir: "/srv/shop", LabelConfigFiles: "/srv/shop/compose.yml"}}}
	w.docker.running = func() []Container {
		st, h := w.health(w.upImage)
		return []Container{{ID: "c-" + w.upImage, Name: "shop-web-1", Image: w.upImage, Status: st, Health: h}}
	}
	w.env = &Env{Docker: w.docker, Root: w.root, Poll: time.Millisecond, Stable: 0, PullTimeout: time.Second, UpTimeout: time.Second, Run: w.run}
	WriteFile = func(p string, data []byte, mode os.FileMode) error { return os.WriteFile(p, data, mode) }
	t.Cleanup(func() { WriteFile = writeKeepOwner })
	return w
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// resolved — что дал бы compose config: образ web из файла (с подстановкой из .env), db — как есть.
func (w *world) resolved() string {
	b, _ := os.ReadFile(filepath.Join(w.root, "srv/shop/compose.yml"))
	s, err := FindImage(b, "web")
	if err != nil || s == nil {
		w.t.Fatalf("тестовый compose: %v", err)
	}
	v, _ := ParseVar(s.Value)
	if v == nil {
		return s.Value
	}
	e, _ := os.ReadFile(filepath.Join(w.root, "srv/shop/.env"))
	es, err := FindEnv(e, v.Name)
	if err != nil {
		return "nginx:1.28" // значение по умолчанию ${NGINX_TAG:-1.28}
	}
	if v.Whole {
		return es.Value
	}
	return v.Repo + ":" + es.Value
}

func (w *world) run(_ context.Context, env []string, name string, args ...string) ([]byte, []byte, error) {
	if name != "docker" || args[0] != "compose" {
		w.t.Fatalf("команда %s %v", name, args)
	}
	for _, e := range env {
		if strings.HasPrefix(e, "SECRET") {
			w.t.Fatal("окружение помощника ушло в compose")
		}
	}
	// После общих аргументов: --project-name shop --project-directory <dir> -f <file>.
	if args[1] != "--project-name" || args[2] != "shop" || args[5] != "-f" {
		w.t.Fatalf("аргументы %v", args)
	}
	sub := args[7:]
	w.calls = append(w.calls, strings.Join(sub, " "))
	if w.failOn != "" && sub[0] == w.failOn {
		return nil, []byte("Error: boom"), errors.New("exit status 1")
	}
	switch sub[0] {
	case "config":
		doc := map[string]any{"name": "shop", "services": map[string]any{
			"web": map[string]any{"image": w.resolved()}, "db": map[string]any{"image": "postgres:17.6"}}}
		if w.extra != nil && w.resolved() != "nginx:1.28" {
			for k, v := range w.extra {
				doc[k] = v
			}
		}
		out, _ := json.Marshal(doc)
		return out, []byte(w.stderr), nil
	case "pull":
		return nil, nil, nil
	case "up":
		if sub[len(sub)-1] != "web" || !strings.Contains(strings.Join(sub, " "), "--no-deps") {
			w.t.Fatalf("up не одного сервиса: %v", sub)
		}
		w.upImage = w.resolved()
		if len(w.docker.tagged) > 0 {
			w.upImage = "nginx:1.28"
		}
		return nil, nil, nil
	}
	w.t.Fatalf("подкоманда %v", sub)
	return nil, nil, nil
}

func (w *world) hooks() Hooks {
	return Hooks{
		Log: func(string, ...any) {},
		Backup: func(paths []string) error {
			if len(paths) != 1 {
				w.t.Fatalf("копия: %v", paths)
			}
			w.saved = paths[0]
			b, err := os.ReadFile(paths[0])
			w.backups = append(w.backups, b)
			return err
		},
		Restore: func() error { return os.WriteFile(w.saved, w.backups[0], 0o640) },
	}
}

func (w *world) file(name string) string {
	b, _ := os.ReadFile(filepath.Join(w.root, "srv/shop", name))
	return string(b)
}

func TestUpdateComposeFile(t *testing.T) {
	w := newWorld(t, composeYML, "")
	res, err := w.env.Update(context.Background(), validParams(), w.hooks())
	if err != nil {
		t.Fatal(err)
	}
	if res.GetSource() != agentv1.ContainerUpdateSource_CONTAINER_UPDATE_SOURCE_COMPOSE_FILE || res.GetNewImage() != "nginx:1.30" ||
		res.GetFile() != "/srv/shop/compose.yml" || res.GetRolledBack() {
		t.Fatalf("итог %+v", res)
	}
	if got := w.file("compose.yml"); got != strings.Replace(composeYML, "nginx:1.28", "nginx:1.30", 1) {
		t.Fatalf("файл:\n%s", got)
	}
	if strings.Join(w.calls, "|") != "config --format json|config --format json|pull --quiet web|up -d --no-deps --no-build web" {
		t.Fatalf("команды %v", w.calls)
	}
}

func TestUpdateEnvVariable(t *testing.T) {
	w := newWorld(t, "services:\n  web:\n    image: nginx:${NGINX_TAG}\n  db:\n    image: postgres:17.6\n", "NGINX_TAG=1.28\nOTHER=1\n")
	res, err := w.env.Update(context.Background(), validParams(), w.hooks())
	if err != nil || res.GetSource() != agentv1.ContainerUpdateSource_CONTAINER_UPDATE_SOURCE_ENV_FILE || res.GetFile() != "/srv/shop/.env" {
		t.Fatalf("%+v %v", res, err)
	}
	if w.file(".env") != "NGINX_TAG=1.30\nOTHER=1\n" || !strings.Contains(w.file("compose.yml"), "${NGINX_TAG}") {
		t.Fatalf("меняется переменная, а не compose: %q", w.file(".env"))
	}
}

func TestUpdatePullOnly(t *testing.T) {
	w := newWorld(t, composeYML, "")
	p := validParams()
	p.TargetTag = "1.28"
	res, err := w.env.Update(context.Background(), p, w.hooks())
	if err != nil || res.GetSource() != agentv1.ContainerUpdateSource_CONTAINER_UPDATE_SOURCE_PULL_ONLY || len(w.backups) != 0 {
		t.Fatalf("%+v %v", res, err)
	}
	if w.file("compose.yml") != composeYML {
		t.Fatal("файл изменён при том же теге")
	}
}

func TestUpdateRefusals(t *testing.T) {
	cases := map[string]struct {
		prep func(w *world, p *agentv1.ContainerUpdateParams)
		want error
	}{
		"не compose": {func(w *world, _ *agentv1.ContainerUpdateParams) {
			w.docker.c.Labels = map[string]string{}
		}, ErrNotCompose},
		"приложение Trassa": {func(w *world, _ *agentv1.ContainerUpdateParams) {
			w.docker.c.Labels[labelTrassaApp] = "x"
		}, ErrManaged},
		"образ уже другой": {func(w *world, p *agentv1.ContainerUpdateParams) { p.CurrentImage = "nginx:1.27" }, ErrImageChanged},
		"не тот сервис":    {func(w *world, p *agentv1.ContainerUpdateParams) { p.Service = "db" }, ErrImageChanged},
		"дайджест": {func(w *world, _ *agentv1.ContainerUpdateParams) {
			w.docker.c.Image = "nginx:1.28@sha256:" + strings.Repeat("a", 64)
		}, ErrPinned},
		"файл Trassa": {func(w *world, _ *agentv1.ContainerUpdateParams) {
			w.docker.c.Labels[LabelConfigFiles] = "/etc/trassa/x.yml"
		}, ErrFileForbidden},
		"путь с ..": {func(w *world, _ *agentv1.ContainerUpdateParams) {
			w.docker.c.Labels[LabelConfigFiles] = "/srv/shop/../../etc/shadow"
		}, ErrFileForbidden},
		"переменная не задана": {func(w *world, _ *agentv1.ContainerUpdateParams) {
			w.stderr = `level=warning msg="The \"DB_PASSWORD\" variable is not set. Defaulting to a blank string."`
		}, ErrConfig},
		"правка задела другое": {func(w *world, _ *agentv1.ContainerUpdateParams) {
			w.extra = map[string]any{"volumes": map[string]any{"x": 1}}
		}, ErrEditMismatch},
		"скачать не удалось": {func(w *world, _ *agentv1.ContainerUpdateParams) { w.failOn = "pull" }, ErrPull},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			w := newWorld(t, composeYML, "")
			p := validParams()
			tc.prep(w, p)
			res, err := w.env.Update(context.Background(), p, w.hooks())
			if !errors.Is(err, tc.want) || res.GetRolledBack() {
				t.Fatalf("ждали %v, получили %v (%+v)", tc.want, err, res)
			}
			if w.file("compose.yml") != composeYML {
				t.Fatalf("файл не возвращён:\n%s", w.file("compose.yml"))
			}
			for _, c := range w.calls {
				if strings.HasPrefix(c, "up") {
					t.Fatalf("сервис пересоздан при отказе: %v", w.calls)
				}
			}
		})
	}
}

func TestUpdateTagFromUnknownVariable(t *testing.T) {
	w := newWorld(t, "services:\n  web:\n    image: nginx:${NGINX_TAG:-1.28}\n", "OTHER=1\n")
	if _, err := w.env.Update(context.Background(), validParams(), w.hooks()); !errors.Is(err, ErrNotEditable) {
		t.Fatalf("тег из переменной без .env: %v", err)
	}
}

// Новый контейнер не стал healthy — прежний файл, up прежнего образа, итог «возвращено».
func TestUpdateRollsBackUnhealthy(t *testing.T) {
	w := newWorld(t, composeYML, "")
	w.health = func(image string) (string, string) {
		if image == "nginx:1.30" {
			return "running", "unhealthy"
		}
		return "running", "healthy"
	}
	res, err := w.env.Update(context.Background(), validParams(), w.hooks())
	if !errors.Is(err, ErrNotHealthy) || !res.GetRolledBack() || res.GetHealth() != "healthy" {
		t.Fatalf("%+v %v", res, err)
	}
	if w.file("compose.yml") != composeYML || w.upImage != "nginx:1.28" {
		t.Fatalf("не возвращено: %s %s", w.upImage, w.file("compose.yml"))
	}
	if n := strings.Count(strings.Join(w.calls, "|"), "up -d --no-deps --no-build web"); n != 2 {
		t.Fatalf("up: %d (%v)", n, w.calls)
	}
}

// Плавающий тег: возврат — прежний id образа под тем же тегом.
func TestUpdatePullOnlyRollsBackByRetag(t *testing.T) {
	w := newWorld(t, composeYML, "")
	calls := 0
	w.health = func(string) (string, string) {
		calls++
		if len(w.docker.tagged) == 0 {
			return "exited", ""
		}
		return "running", ""
	}
	p := validParams()
	p.TargetTag = "1.28"
	res, err := w.env.Update(context.Background(), p, w.hooks())
	if !errors.Is(err, ErrNotHealthy) || !res.GetRolledBack() || len(w.docker.tagged) != 1 || w.docker.tagged[0] != "sha256:old→nginx:1.28" {
		t.Fatalf("%+v %v %v", res, err, w.docker.tagged)
	}
}

func TestUpdateRollbackFailed(t *testing.T) {
	w := newWorld(t, composeYML, "")
	w.health = func(string) (string, string) { return "exited", "" }
	res, err := w.env.Update(context.Background(), validParams(), w.hooks())
	if !errors.Is(err, ErrRollbackFailed) || res.GetRolledBack() {
		t.Fatalf("%+v %v", res, err)
	}
}
