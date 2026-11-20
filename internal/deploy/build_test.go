// SPDX-License-Identifier: AGPL-3.0-only

package deploy

import (
	"context"
	"encoding/base64"
	"errors"
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
)

const commit = "cccccccccccccccccccccccccccccccccccccccc"

type buildCall struct {
	c   Cmd
	env string
}

func (f *deployFixture) fakeBuild(t *testing.T, dockerfile func(src string)) *[]buildCall {
	var calls []buildCall
	me, _ := user.Current()
	f.e.LookupUser = func(string) (*user.User, error) { return me, nil }
	f.e.Resolve = func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("140.82.112.3")}, nil
	}
	f.e.Run = func(context.Context, string, ...string) ([]byte, error) { return nil, nil }
	f.e.BuildDir = filepath.Join(f.e.Root, "build")
	f.e.ExecAs = func(_ context.Context, c Cmd) ([]byte, error) {
		calls = append(calls, buildCall{c: c, env: strings.Join(c.Env, "\n")})
		switch {
		case c.Name == "git" && c.Args[len(c.Args)-1] == "FETCH_HEAD":
			dockerfile(c.Dir)
		case c.Name == "git" && c.Args[0] == "rev-parse":
			return []byte(commit + "\n"), nil
		case c.Name == "docker" && c.Args[1] == "build":
			f.d.mu.Lock()
			f.d.images["registry.example.com/team/app:"+rel1] = 4096
			f.d.mu.Unlock()
			return []byte("#5 RUN npm ci\n#5 token npm-secret-1 leaked\n#6 DONE\n"), nil
		}
		return nil, nil
	}
	return &calls
}

func (f *deployFixture) buildParams(t *testing.T) *agentv1.DeployBuildParams {
	return &agentv1.DeployBuildParams{AppId: app1, ReleaseId: rel1, BuildKind: agentv1.BuildKind_BUILD_KIND_DOCKERFILE,
		Source: &agentv1.GitSource{RepoUrl: "https://github.com/org/app.git", CommitSha: commit, Username: "x-access-token",
			Token: f.seal(t, FieldGit, "ghs_gittoken1")},
		BuildSecrets:  map[string]*agentv1.SealedSecret{"NPM_TOKEN": f.seal(t, FieldBuildEnv+"NPM_TOKEN", "npm-secret-1")},
		BuildArgs:     map[string]string{"NODE_ENV": "production"},
		MemoryLimitMb: 2048, ImageRepo: "registry.example.com/team/app",
		PushTo: &agentv1.RegistryAuth{Server: "registry.example.com", Username: "builder", Password: f.seal(t, FieldRegistry, "push-pass-1")}}
}

func TestBuild(t *testing.T) {
	f := newDeployFixture(t)
	calls := f.fakeBuild(t, func(src string) { _ = os.WriteFile(filepath.Join(src, "Dockerfile"), []byte("FROM scratch\n"), 0o644) })
	var logged []string
	res, err := f.e.Build(context.Background(), BuildJob{Params: f.buildParams(t), Open: &Opener{Key: f.key, Body: f.body, App: app1},
		Log: func(s string) { logged = append(logged, s) }})
	if err != nil {
		t.Fatal(err)
	}
	if res.GetImageRef() != "registry.example.com/team/app@sha256:"+strings.Repeat("f", 64) || !res.GetPushed() {
		t.Fatalf("итог %+v", res)
	}
	me, _ := user.Current()
	uid, _ := strconv.Atoi(me.Uid)
	var gitFetch, build *buildCall
	for i := range *calls {
		c := &(*calls)[i]
		if c.c.Name == "git" && c.c.Args[0] == "fetch" {
			gitFetch = c
		}
		if c.c.Name == "docker" && c.c.Args[1] == "build" {
			build = c
		}
	}
	// git — от trassa-build, токен только в окружении и только для хоста репозитория.
	auth := base64.StdEncoding.EncodeToString([]byte("x-access-token:ghs_gittoken1"))
	if gitFetch == nil || gitFetch.c.UID != uid || !strings.Contains(gitFetch.env, "GIT_CONFIG_KEY_2=http.https://github.com/.extraHeader") ||
		!strings.Contains(gitFetch.env, "GIT_CONFIG_VALUE_2=Authorization: Basic "+auth) || strings.Contains(strings.Join(gitFetch.c.Args, " "), "ghs_") ||
		!strings.Contains(gitFetch.env, "GIT_ALLOW_PROTOCOL=https") || !strings.Contains(gitFetch.env, "GIT_CONFIG_GLOBAL=/dev/null") {
		t.Fatalf("git: %+v", gitFetch)
	}
	// buildx — секрет только --secret и в окружении; Dockerfile — копия root, не из дерева кода.
	args := strings.Join(build.c.Args, " ")
	if build.c.UID != -1 || strings.Contains(args, "npm-secret-1") || !strings.Contains(args, "--secret id=NPM_TOKEN,env=NPM_TOKEN") ||
		!strings.Contains(build.env, "NPM_TOKEN=npm-secret-1") || !strings.Contains(args, "--build-arg NODE_ENV=production") ||
		!strings.Contains(args, "-f "+filepath.Join(f.e.BuildDir, rel1, "Dockerfile")) || strings.Contains(build.env, "ghs_gittoken1") {
		t.Fatalf("buildx: %s\n%s", args, build.env)
	}
	if strings.Contains(strings.Join(logged, "\n"), "npm-secret-1") || len(logged) == 0 {
		t.Fatalf("журнал сборки: %v", logged)
	}
	raw, _ := base64.URLEncoding.DecodeString(f.d.auth[len(f.d.auth)-1])
	if !strings.Contains(string(raw), `"password":"push-pass-1"`) {
		t.Fatalf("push auth %s", raw)
	}
	if _, err := os.Lstat(filepath.Join(f.e.BuildDir, rel1)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("каталог сборки остался: %v", err)
	}
}

func TestBuildRejects(t *testing.T) {
	f := newDeployFixture(t)
	// Dockerfile — ссылка на файл root: buildx его не прочтёт.
	f.fakeBuild(t, func(src string) { _ = os.Symlink("/etc/passwd", filepath.Join(src, "Dockerfile")) })
	_, err := f.e.Build(context.Background(), BuildJob{Params: f.buildParams(t), Open: &Opener{Key: f.key, Body: f.body, App: app1}})
	if !errors.Is(err, ErrBuildUnsupported) {
		t.Fatalf("ссылка: %v", err)
	}
	// Адрес метаданных хостера — SSRF_BLOCKED до любого git.
	calls := f.fakeBuild(t, func(string) {})
	f.e.Resolve = func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("169.254.169.254")}, nil
	}
	_, err = f.e.Build(context.Background(), BuildJob{Params: f.buildParams(t), Open: &Opener{Key: f.key, Body: f.body, App: app1}})
	if !errors.Is(err, ErrRepoAddress) {
		t.Fatalf("метаданные: %v", err)
	}
	for _, c := range *calls {
		if c.c.Name == "git" && c.c.Args[0] == "fetch" {
			t.Fatal("fetch на адрес метаданных")
		}
	}
	if ValidateBuild(func() *agentv1.DeployBuildParams {
		p := f.buildParams(t)
		p.DeadlineMs, p.BuildArgs = 1_800_000_600_000, map[string]string{"BUILDKIT_SYNTAX": "evil/frontend"}
		return p
	}(), 1_800_000_000_000) == nil {
		t.Fatal("BUILDKIT_SYNTAX принят")
	}
	if gitCode("remote: Repository not found.") != ErrGitDenied || gitCode("error: Server does not allow request for unadvertised object") != ErrGitCommit {
		t.Fatal("коды git")
	}
}
