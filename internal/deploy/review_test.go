// SPDX-License-Identifier: AGPL-3.0-only

package deploy

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
)

// Переменные приложения не попадают в окружение root-процесса compose под своими именами (подмена плагина CLI
// через DOCKER_CONFIG), подстановки переписаны на TRASSA_V_.
func TestComposeEnvNotOverridable(t *testing.T) {
	f := newDeployFixture(t)
	var envs [][]string
	f.fakeCompose(t, func(b []byte) []byte { return b }, nil)
	wrapped := f.e.Exec
	f.e.Exec = func(ctx context.Context, env []string, name string, args ...string) ([]byte, error) {
		envs = append(envs, env)
		return wrapped(ctx, env, name, args...)
	}
	p := f.composeRelease(t, composeDoc)
	p.EnvPlain = map[string]string{"DOCKER_CONFIG": "/var/lib/docker/volumes/x/_data", "PATH": "/tmp/evil"}
	if _, _, err := f.e.Release(context.Background(), ReleaseJob{Params: p, Open: &Opener{Key: f.key, Body: f.body, App: app1}}); err != nil {
		t.Fatal(err)
	}
	for _, env := range envs {
		got := map[string]string{}
		for _, kv := range env {
			k, v, _ := strings.Cut(kv, "=")
			got[k] = v // последнее значение — то, что увидит процесс
		}
		if strings.Contains(got["DOCKER_CONFIG"], "volumes") || got["PATH"] == "/tmp/evil" || got["TRASSA_V_DB_PASSWORD"] != "pg-secret-1" {
			t.Fatalf("окружение compose: %v", env)
		}
	}
	raw, _ := os.ReadFile(filepath.Join(f.e.appDir(app1), "compose", composeFile))
	if !strings.Contains(string(raw), "${TRASSA_V_DB_PASSWORD}") || strings.Contains(string(raw), "${DB_PASSWORD}") {
		t.Fatalf("подстановки не переписаны: %s", raw)
	}
	// В нормализованном виде непереписанная подстановка — отказ.
	img := `"image":"registry.example.com/team/web@sha256:` + strings.Repeat("d", 64) + `"`
	if err := CheckNormalized([]byte(`{"services":{"web":{`+img+`,"command":"echo ${DB_PASSWORD}"}}}`), composeSpecFor("DB_PASSWORD")); !errors.Is(err, ErrComposeDenied) {
		t.Fatalf("непереписанная подстановка: %v", err)
	}
	out, _, err := ComposeDoc(`{"services":{"web":{`+img+`,"command":["sh","-c","echo $DB_PASSWORD $$HOME"],"environment":["DB_PASSWORD"]}}}`, composeSpecFor("DB_PASSWORD"))
	if err != nil || !strings.Contains(string(out), `"echo ${TRASSA_V_DB_PASSWORD} $$HOME"`) || !strings.Contains(string(out), `"DB_PASSWORD": "${TRASSA_V_DB_PASSWORD}"`) {
		t.Fatalf("переписывание: %v %s", err, out)
	}
	if _, _, err := ComposeDoc(`{"services":{"web":{`+img+`,"environment":["HOME"]}}}`, composeSpecFor()); !errors.Is(err, ErrComposeDenied) {
		t.Fatalf("переменная процесса без значения: %v", err)
	}
	if err := CheckNormalized(out, composeSpecFor("DB_PASSWORD")); err != nil {
		t.Fatalf("свой вид: %v", err)
	}
}

// Учётные данные pull_from — только реестру pull_from.
func TestPullAuthOnlyOwnRegistry(t *testing.T) {
	f := newDeployFixture(t)
	f.fakeCompose(t, func(b []byte) []byte { return b }, nil)
	doc := strings.Replace(composeDoc, "docker.io/library/postgres", "attacker.example/x", 1)
	p := f.composeRelease(t, doc)
	p.PullFrom = &agentv1.RegistryAuth{Server: "registry.example.com", Username: "puller", Password: f.seal(t, FieldRegistry, "pull-pass-1")}
	if _, _, err := f.e.Release(context.Background(), ReleaseJob{Params: p, Open: &Opener{Key: f.key, Body: f.body, App: app1}}); err != nil {
		t.Fatal(err)
	}
	for i, ref := range f.d.pulls {
		raw, _ := base64.URLEncoding.DecodeString(f.d.auth[i])
		has := strings.Contains(string(raw), "pull-pass-1")
		if strings.HasPrefix(ref, "attacker.example/") == has {
			t.Fatalf("%s: учётные данные %v", ref, has)
		}
	}
	for ref, want := range map[string]string{"nginx@sha256:x": "docker.io", "library/nginx": "docker.io", "Registry-1.Docker.io/a/b": "docker.io",
		"localhost/a": "localhost", "reg.example.com:5000/a": "reg.example.com:5000"} {
		if got := registryOf(ref); got != want {
			t.Errorf("%s: %s", ref, got)
		}
	}
	rel := f.release(t, rel1, "other.example.com/team/app@sha256:"+strings.Repeat("a", 64))
	rel.DeadlineMs, rel.Env = 1_800_000_600_000, nil
	if err := ValidateRelease(rel, 1_800_000_000_000); err == nil {
		t.Fatal("образ чужого реестра с pull_from принят")
	}
}

// Релиз приложения не забирает имя другого (точно или wildcard).
func TestReleaseHostTaken(t *testing.T) {
	f := newDeployFixture(t)
	other := "01a1f4b6-f2f2-7e66-85b4-8ff5645600a9"
	if err := f.e.saveProxy(&ProxyState{Version: "2.11.9", Apps: map[string][]RouteRec{other: {{Hosts: []string{"shop.example.com"}, Dial: "127.0.0.1:20500"}}}}); err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{"shop.example.com", "*.example.com"} {
		p := f.release(t, rel1, digest('a'))
		p.Routes = []*agentv1.ProxyRoute{{AppId: app1, Hosts: []string{h}}}
		if _, _, err := f.run(p); !errors.Is(err, ErrHostTaken) {
			t.Fatalf("%s: %v", h, err)
		}
		if run := f.d.running(app1); len(run) != 0 {
			t.Fatalf("%s: новый контейнер остался", h)
		}
	}
	if st, _ := f.e.LoadProxy(); len(st.Apps) != 1 || st.Apps[other][0].Dial != "127.0.0.1:20500" {
		t.Fatalf("чужой маршрут изменён: %+v", st.Apps)
	}
	if hostsOverlap("*.example.com", "a.b.example.com") || !hostsOverlap("a.example.com", "*.example.com") {
		t.Fatal("hostsOverlap")
	}
	if checkRoutes([]*agentv1.ProxyRoute{{AppId: app1, Hosts: []string{"*.example.com"}}, {AppId: other, Hosts: []string{"a.example.com"}}}, "") == nil {
		t.Fatal("route.apply: wildcard накрыл чужое имя")
	}
}
