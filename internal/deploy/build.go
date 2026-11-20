// SPDX-License-Identifier: AGPL-3.0-only

package deploy

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/fsutil"
	"golang.org/x/sys/unix"
)

// Сборка (решения E17 3.1–3.3, 6.1, 6.2): код получает git под непривилегированным trassa-build с учётными
// данными только в окружении процесса, собирает buildx отдельным сборщиком с пределом памяти, образ уходит в
// реестр через Engine API с учётными данными сборщика. Секреты сборки — только --secret id=…,env=….
const (
	BuildUser = "trassa-build"
	// BuildKitImage — moby/buildkit v0.34.2 (решение E17 3.1).
	BuildKitImage = "moby/buildkit@sha256:c5f8862f52499773af85bc07695b2379ef08e8002352b0df2c4864c91d78dabe"
	// RailpackFrontend — фронтенд той же версии, что CLI 0.43.0 (решение E17 3.3).
	RailpackFrontend = "ghcr.io/railwayapp/railpack-frontend:v0.43.0@sha256:355ef61fae6f2551103cd8b10c710cb07167dd353d561f15c69b8d7ac1c676cc"
	maxBuildLog      = 4 << 20
)

var (
	ErrBuildOOM         = errors.New("BUILD_OOM")
	ErrBuildUnsupported = errors.New("BUILD_UNSUPPORTED")
	ErrGitDenied        = errors.New("GIT_ACCESS_DENIED")
	ErrGitCommit        = errors.New("GIT_COMMIT_MISMATCH")
	ErrRepoAddress      = errors.New("SSRF_BLOCKED")
	ErrBuildFailed      = errors.New("BUILD_FAILED")
)

// Cmd — программа от имени пользователя (UID < 0 — от root) с окружением только Env.
type Cmd struct {
	Name     string
	Args     []string
	Env      []string
	Dir      string
	UID, GID int
}

// RunCmd — Cmd с выводом stdout и stderr вместе (до 4 МиБ); по сроку — SIGTERM, через 10 с SIGKILL.
func RunCmd(ctx context.Context, c Cmd) ([]byte, error) {
	bin := c.Name
	if !filepath.IsAbs(bin) {
		p, err := lookPath(bin)
		if err != nil {
			return nil, err
		}
		bin = p
	}
	cmd := exec.CommandContext(ctx, bin, c.Args...)
	cmd.Env, cmd.Dir = c.Env, c.Dir
	if cmd.Dir == "" {
		cmd.Dir = "/"
	}
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = 10 * time.Second
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if c.UID >= 0 {
		// Пустой список групп снимает дополнительные группы root.
		cmd.SysProcAttr.Credential = &syscall.Credential{Uid: uint32(c.UID), Gid: uint32(c.GID), Groups: []uint32{}}
	}
	buf := new(strings.Builder)
	w := &builderWriter{b: buf, n: maxBuildLog}
	cmd.Stdout, cmd.Stderr = w, w
	err := cmd.Run()
	if err != nil {
		return []byte(buf.String()), fmt.Errorf("%s: %w", c.Name, err)
	}
	return []byte(buf.String()), nil
}

type builderWriter struct {
	b *strings.Builder
	n int
}

func (w *builderWriter) Write(p []byte) (int, error) {
	if room := w.n - w.b.Len(); room > 0 {
		if len(p) > room {
			w.b.Write(p[:room])
		} else {
			w.b.Write(p)
		}
	}
	return len(p), nil
}

// BuildJob — сборка релиза.
type BuildJob struct {
	Params *agentv1.DeployBuildParams
	Open   *Opener
	OpID   string
	Step   Step
	Log    func(string)
}

func (e *Env) execAs(ctx context.Context, c Cmd) ([]byte, error) {
	if e.ExecAs != nil {
		return e.ExecAs(ctx, c)
	}
	return RunCmd(ctx, c)
}

// buildUser — uid и gid trassa-build; нет — создаётся системным пользователем без входа.
func (e *Env) buildUser(ctx context.Context) (int, int, error) {
	look := e.LookupUser
	if look == nil {
		look = user.Lookup
	}
	u, err := look(BuildUser)
	if err != nil {
		var unknown user.UnknownUserError
		if !errors.As(err, &unknown) {
			return 0, 0, err
		}
		if _, err := e.Run(ctx, "useradd", "--system", "--user-group", "--no-create-home", "--home-dir", "/nonexistent",
			"--shell", "/usr/sbin/nologin", BuildUser); err != nil {
			return 0, 0, fmt.Errorf("пользователь %s: %w", BuildUser, err)
		}
		if u, err = look(BuildUser); err != nil {
			return 0, 0, err
		}
	}
	uid, err1 := strconv.Atoi(u.Uid)
	gid, err2 := strconv.Atoi(u.Gid)
	if err1 != nil || err2 != nil || uid <= 0 || gid <= 0 {
		return 0, 0, fmt.Errorf("%s: uid %s, gid %s", BuildUser, u.Uid, u.Gid)
	}
	return uid, gid, nil
}

// checkRepoHost — адрес репозитория не ведёт на сам сервер, link-local и адрес метаданных хостера (решение 6.1).
// Повторное разрешение имени git-ом остаётся (подмена DNS между проверкой и fetch) — остаточный риск.
func (e *Env) checkRepoHost(ctx context.Context, host string) error {
	resolve := e.Resolve
	if resolve == nil {
		resolve = net.DefaultResolver.LookupNetIP
	}
	var addrs []netip.Addr
	if a, err := netip.ParseAddr(host); err == nil {
		addrs = []netip.Addr{a}
	} else {
		if addrs, err = resolve(ctx, "ip", host); err != nil || len(addrs) == 0 {
			return fmt.Errorf("%w: %s не разрешается: %v", ErrGitDenied, host, err)
		}
	}
	metadata6 := netip.MustParseAddr("fd00:ec2::254")
	for _, a := range addrs {
		a = a.Unmap()
		if a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || a.IsUnspecified() || a.IsMulticast() || a == metadata6 {
			return fmt.Errorf("%w: %s → %s", ErrRepoAddress, host, a)
		}
	}
	return nil
}

// gitEnv — окружение git (решение 6.1): без системных и пользовательских настроек, без запросов, только https,
// заголовок с токеном привязан к хосту репозитория, без подмодулей и переходов.
func gitEnv(repo *url.URL, user, token string) []string {
	env := []string{"PATH=/usr/bin:/bin", "LANG=C", "HOME=/nonexistent", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_TERMINAL_PROMPT=0", "GIT_ASKPASS=/bin/false", "GIT_ALLOW_PROTOCOL=https"}
	kv := [][2]string{{"submodule.recurse", "false"}, {"http.followRedirects", "false"}}
	if token != "" {
		auth := base64.StdEncoding.EncodeToString([]byte(user + ":" + token))
		kv = append(kv, [2]string{"http.https://" + repo.Host + "/.extraHeader", "Authorization: Basic " + auth})
	}
	env = append(env, "GIT_CONFIG_COUNT="+strconv.Itoa(len(kv)))
	for i, p := range kv {
		env = append(env, fmt.Sprintf("GIT_CONFIG_KEY_%d=%s", i, p[0]), fmt.Sprintf("GIT_CONFIG_VALUE_%d=%s", i, p[1]))
	}
	return env
}

func gitCode(out string) error {
	l := strings.ToLower(out)
	switch {
	case strings.Contains(l, "authentication failed"), strings.Contains(l, "403"), strings.Contains(l, "401"),
		strings.Contains(l, "could not read username"), strings.Contains(l, "repository not found"):
		return ErrGitDenied
	case strings.Contains(l, "not our ref"), strings.Contains(l, "couldn't find remote ref"), strings.Contains(l, "no such remote ref"),
		strings.Contains(l, "unadvertised object"):
		return ErrGitCommit
	}
	return ErrGitDenied
}

// killUser — процессы trassa-build после шага: код из репозитория не остаётся работать на сервере.
func (e *Env) killUser(ctx context.Context) {
	_, _ = e.Run(context.WithoutCancel(ctx), "pkill", "-KILL", "-u", BuildUser)
}

// fetch — код по коммиту в src (пустой каталог trassa-build, 0700).
func (e *Env) fetch(ctx context.Context, j BuildJob, uid, gid int, src string, secrets []string) error {
	g := j.Params.GetSource()
	repo, _ := url.Parse(g.GetRepoUrl())
	if err := e.checkRepoHost(ctx, repo.Hostname()); err != nil {
		return err
	}
	token := ""
	if g.GetToken() != nil {
		var err error
		if token, err = j.Open.Open(g.GetToken(), FieldGit); err != nil {
			return err
		}
	}
	env := gitEnv(repo, g.GetUsername(), token)
	sec := append(append([]string{}, secrets...), token, base64.StdEncoding.EncodeToString([]byte(g.GetUsername()+":"+token)))
	run := func(args ...string) (string, error) {
		out, err := e.execAs(ctx, Cmd{Name: "git", Args: args, Env: env, Dir: src, UID: uid, GID: gid})
		return clean(string(out), sec), err
	}
	defer e.killUser(ctx)
	initArgs := []string{"init", "-q"}
	if len(g.GetCommitSha()) == 64 {
		initArgs = append(initArgs, "--object-format=sha256")
	}
	if out, err := run(append(initArgs, ".")...); err != nil {
		return fmt.Errorf("git init: %v: %s", err, lastLine([]byte(out)))
	}
	if out, err := run("fetch", "--depth=1", "--no-tags", "--no-recurse-submodules", "--", g.GetRepoUrl(), g.GetCommitSha()); err != nil {
		return fmt.Errorf("%w: %s", gitCode(out), lastLine([]byte(out)))
	}
	if out, err := run("-c", "advice.detachedHead=false", "checkout", "-q", "FETCH_HEAD"); err != nil {
		return fmt.Errorf("git checkout: %v: %s", err, lastLine([]byte(out)))
	}
	out, err := run("rev-parse", "HEAD")
	if err != nil || strings.TrimSpace(out) != strings.ToLower(g.GetCommitSha()) {
		return fmt.Errorf("%w: HEAD %s", ErrGitCommit, strings.TrimSpace(out))
	}
	return nil
}

// copyIn — файл из дерева trassa-build в каталог root (без ссылок ни в одном компоненте): buildx от root
// не читает подставленную ссылку вида Dockerfile → /etc/shadow.
func copyIn(from, to string, max int64) error {
	f, err := fsutil.OpenNoFollow(from, unix.O_RDONLY)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() || st.Size() > max {
		return fmt.Errorf("%s: не обычный файл или больше %d байт", filepath.Base(from), max)
	}
	return fsutil.WriteAtomicNoFollow(to, 0o600, fsutil.Keep, func(w io.Writer) error {
		_, err := io.Copy(w, io.LimitReader(f, max))
		return err
	})
}

// ensureBuilder — сборщик trassa-<M>: docker-container, BuildKit по дайджесту, память без свопа (решение 3.1).
func (e *Env) ensureBuilder(ctx context.Context, env []string, mb uint32) (string, error) {
	name := fmt.Sprintf("trassa-%d", mb)
	if _, err := e.execAs(ctx, Cmd{Name: "docker", Args: []string{"buildx", "inspect", name}, Env: env, UID: -1}); err == nil {
		return name, nil
	}
	opts := fmt.Sprintf("image=%s,memory=%dm,memory-swap=%dm,network=bridge", BuildKitImage, mb, mb)
	out, err := e.execAs(ctx, Cmd{Name: "docker", Args: []string{"buildx", "create", "--name", name, "--driver", "docker-container",
		"--driver-opt", opts}, Env: env, UID: -1})
	if err != nil {
		return "", fmt.Errorf("сборщик %s: %v: %s", name, err, lastLine(out))
	}
	return name, nil
}

// builderOOM — контейнер BuildKit сборщика убит по памяти.
func (e *Env) builderOOM(ctx context.Context, builder string) bool {
	var st struct {
		State struct {
			OOMKilled bool `json:"OOMKilled"`
		} `json:"State"`
	}
	if err := e.dockerJSON(ctx, http.MethodGet, "/containers/buildx_buildkit_"+builder+"0/json", nil, &st); err != nil {
		return false
	}
	return st.State.OOMKilled
}

// push — POST /images/{repo}/push?tag= с X-Registry-Auth; дайджест — из aux итога.
func (e *Env) push(ctx context.Context, repo, tag, auth string, secrets []string) (string, uint64, error) {
	resp, err := e.Docker.Do(ctx, http.MethodPost, "/images/"+repo+"/push?tag="+url.QueryEscape(tag), nil, map[string]string{"X-Registry-Auth": auth})
	if err != nil {
		return "", 0, fmt.Errorf("%w: %v", ErrRegistry, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return "", 0, fmt.Errorf("%w: HTTP %d %s", ErrRegistry, resp.StatusCode, clean(string(b), secrets))
	}
	var digest string
	var size uint64
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		var m struct {
			Error string `json:"error"`
			Aux   struct {
				Digest string `json:"Digest"`
				Size   uint64 `json:"Size"`
			} `json:"aux"`
		}
		if json.Unmarshal(sc.Bytes(), &m) != nil {
			continue
		}
		if m.Error != "" {
			msg := clean(m.Error, secrets)
			if strings.Contains(msg, "unauthorized") || strings.Contains(msg, "denied") {
				return "", 0, fmt.Errorf("%w: %s", ErrRegistryAuth, msg)
			}
			return "", 0, fmt.Errorf("%w: %s", ErrRegistry, msg)
		}
		if m.Aux.Digest != "" {
			digest, size = m.Aux.Digest, m.Aux.Size
		}
	}
	if err := sc.Err(); err != nil {
		return "", 0, err
	}
	if !strings.HasPrefix(digest, "sha256:") || len(digest) != 71 {
		return "", 0, fmt.Errorf("%w: реестр не вернул дайджест", ErrRegistry)
	}
	return digest, size, nil
}

// Build — deploy.build. Каталог /var/lib/trassa/build/<release_id> удаляется в конце при любом исходе.
func (e *Env) Build(ctx context.Context, j BuildJob) (*agentv1.DeployBuildResult, error) {
	p := j.Params
	start := time.Now()
	step := j.Step
	if step == nil {
		step = func(agentv1.DeployStep, uint32) {}
	}
	log := j.Log
	if log == nil {
		log = func(string) {}
	}
	res := &agentv1.DeployBuildResult{}
	uid, gid, err := e.buildUser(ctx)
	if err != nil {
		return nil, err
	}
	// Секреты сборки и учётные данные push — до любых действий: ошибка ключа ничего не оставляет.
	names := make([]string, 0, len(p.GetBuildSecrets()))
	for k := range p.GetBuildSecrets() {
		names = append(names, k)
	}
	sort.Strings(names)
	var secretEnv, secrets []string
	for _, k := range names {
		v, err := j.Open.Open(p.GetBuildSecrets()[k], FieldBuildEnv+k)
		if err != nil {
			return nil, err
		}
		secretEnv, secrets = append(secretEnv, k+"="+v), append(secrets, v)
	}
	auth, pw, err := j.Open.RegistryAuth(p.GetPushTo())
	if err != nil {
		return nil, err
	}
	secrets = append(secrets, pw)

	if e.BuildDir == "" {
		return nil, errors.New("каталог сборки не задан")
	}
	buildRoot := e.BuildDir
	work := filepath.Join(buildRoot, p.GetReleaseId())
	// buildRoot и work — помощника (root), 0711: trassa-build проходит до своих src и out, но не видит список сборок.
	for _, d := range []string{buildRoot, work} {
		fd, err := fsutil.MkdirAllNoFollow(d, 0o711)
		if err != nil {
			return nil, err
		}
		_ = closeFD(fd)
		if err := fsutil.ChmodChownNoFollow(d, fsutil.FileID{}, 0o711, os.Geteuid(), os.Getegid()); err != nil {
			return nil, err
		}
	}
	defer func() {
		e.killUser(ctx)
		if fd, err := fsutil.OpenDirNoFollow(buildRoot); err == nil {
			if err := fsutil.RemoveAllAt(fd, p.GetReleaseId()); err != nil {
				log("каталог сборки не удалён: " + err.Error())
			}
			_ = closeFD(fd)
		}
	}()
	src, out := filepath.Join(work, "src"), filepath.Join(work, "out")
	for _, d := range []string{src, out} {
		fd, err := fsutil.MkdirAllNoFollow(d, 0o700)
		if err != nil {
			return nil, err
		}
		_ = closeFD(fd)
		if err := fsutil.ChmodChownNoFollow(d, fsutil.FileID{}, 0o700, uid, gid); err != nil {
			return nil, err
		}
	}
	cfg := filepath.Join(work, "docker")
	if fd, err := fsutil.MkdirAllNoFollow(cfg, 0o700); err != nil {
		return nil, err
	} else {
		_ = closeFD(fd)
	}

	step(agentv1.DeployStep_DEPLOY_STEP_FETCH, 0)
	if err := e.fetch(ctx, j, uid, gid, src, secrets); err != nil {
		return nil, err
	}
	ctxDir := src
	if r := p.GetSource().GetRootDir(); r != "" {
		ctxDir = filepath.Join(src, r)
		fd, err := fsutil.OpenDirNoFollow(ctxDir)
		if err != nil {
			return nil, fmt.Errorf("root_dir: %w", err)
		}
		_ = closeFD(fd)
	}
	// Окружение buildx: свой DOCKER_CONFIG без config.json (решение 6.2), сборщики — в постоянном каталоге.
	benv := []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "HOME=" + cfg, "DOCKER_CONFIG=" + filepath.Join(buildRoot, ".buildx-config"),
		"BUILDX_NO_DEFAULT_ATTESTATIONS=1"}
	if fd, err := fsutil.MkdirAllNoFollow(filepath.Join(buildRoot, ".buildx-config"), 0o700); err != nil {
		return nil, err
	} else {
		_ = closeFD(fd)
	}
	builder, err := e.ensureBuilder(ctx, benv, p.GetMemoryLimitMb())
	if err != nil {
		return nil, err
	}
	tag := p.GetReleaseId()
	local := p.GetImageRepo() + ":" + tag
	args := []string{"buildx", "build", "--builder", builder, "--load", "--progress=plain", "--provenance=false", "-t", local}
	for _, k := range names {
		args = append(args, "--secret", "id="+k+",env="+k)
	}
	argNames := make([]string, 0, len(p.GetBuildArgs()))
	for k := range p.GetBuildArgs() {
		argNames = append(argNames, k)
	}
	sort.Strings(argNames)
	for _, k := range argNames {
		args = append(args, "--build-arg", k+"="+p.GetBuildArgs()[k])
	}
	switch p.GetBuildKind() {
	case agentv1.BuildKind_BUILD_KIND_RAILPACK:
		bin, err := e.railpack(ctx, p.GetRailpack(), j.OpID)
		if err != nil {
			return nil, err
		}
		pargs := []string{"prepare", ctxDir, "--plan-out", filepath.Join(out, "railpack-plan.json"), "--info-out", filepath.Join(out, "railpack-info.json")}
		for _, k := range names {
			pargs = append(pargs, "--env", k)
		}
		o, err := e.execAs(ctx, Cmd{Name: bin, Args: pargs, Env: []string{"PATH=/usr/bin:/bin", "LANG=C", "HOME=/nonexistent"}, Dir: src, UID: uid, GID: gid})
		e.killUser(ctx)
		if err != nil {
			return nil, fmt.Errorf("%w: %s", ErrBuildUnsupported, lastLine([]byte(clean(string(o), secrets))))
		}
		plan := filepath.Join(work, "railpack-plan.json")
		if err := copyIn(filepath.Join(out, "railpack-plan.json"), plan, 4<<20); err != nil {
			return nil, fmt.Errorf("%w: план: %v", ErrBuildUnsupported, err)
		}
		h := sha256.New()
		for _, s := range secretEnv {
			h.Write([]byte(s + "\x00"))
		}
		args = append(args, "--build-arg", "BUILDKIT_SYNTAX="+RailpackFrontend, "-f", plan,
			"--build-arg", "secrets-hash="+hex.EncodeToString(h.Sum(nil)), "--build-arg", "cache-key="+p.GetAppId())
	default:
		df := p.GetDockerfilePath()
		if df == "" {
			df = "Dockerfile"
		}
		copyTo := filepath.Join(work, "Dockerfile")
		if err := copyIn(filepath.Join(ctxDir, df), copyTo, 1<<20); err != nil {
			return nil, fmt.Errorf("%w: Dockerfile: %v", ErrBuildUnsupported, err)
		}
		args = append(args, "-f", copyTo)
	}
	args = append(args, ctxDir)

	step(agentv1.DeployStep_DEPLOY_STEP_BUILD, 0)
	o, err := e.execAs(ctx, Cmd{Name: "docker", Args: args, Env: append(benv, secretEnv...), UID: -1})
	text := clean(string(o), secrets)
	for _, l := range tailLines(text, 200) {
		log(l)
	}
	if err != nil {
		switch {
		case errors.Is(ctx.Err(), context.DeadlineExceeded):
			return res, fmt.Errorf("%w: сборка дольше срока", ErrDeadline)
		case e.builderOOM(context.WithoutCancel(ctx), builder) || strings.Contains(text, "exit code: 137"):
			res.Oom = true
			return res, fmt.Errorf("%w: предел %d МБ", ErrBuildOOM, p.GetMemoryLimitMb())
		}
		return res, fmt.Errorf("%w: %s", ErrBuildFailed, lastLine([]byte(text)))
	}
	ii, err := e.imageInspect(ctx, local)
	if err != nil {
		return res, err
	}
	res.ImageId, res.SizeBytes = ii.ID, uint64(ii.Size)

	step(agentv1.DeployStep_DEPLOY_STEP_PUSH, 0)
	digest, _, err := e.push(ctx, p.GetImageRepo(), tag, auth, secrets)
	// Локальный тег сборщику не нужен: образ берут рабочие серверы из реестра.
	_ = e.dockerJSON(context.WithoutCancel(ctx), http.MethodDelete, "/images/"+local, nil, nil)
	if err != nil {
		return res, err
	}
	res.ImageRef, res.Pushed = p.GetImageRepo()+"@"+digest, true
	res.DurationSec = uint32(time.Since(start) / time.Second)
	return res, nil
}

// railpack — бинарник railpack из архива, скачанного агентом (сумма сверяется с таблицей помощника).
func (e *Env) railpack(_ context.Context, t *agentv1.DeployTool, op string) (string, error) {
	dir := filepath.Join(e.BuildDir, ".tools")
	fd, err := fsutil.MkdirAllNoFollow(dir, 0o755)
	if err != nil {
		return "", err
	}
	_ = closeFD(fd)
	path := filepath.Join(dir, "railpack-"+t.GetVersion())
	if st, err := os.Lstat(path); err == nil && st.Mode().IsRegular() {
		return path, nil
	}
	if e.Stage == nil {
		return "", fmt.Errorf("%w: railpack не скачан", ErrToolUnknown)
	}
	raw, err := readTool(e.Stage(op), t)
	if err != nil {
		return "", err
	}
	bin, err := untarOne(raw, "railpack")
	if err != nil {
		return "", err
	}
	if err := fsutil.WriteAtomicNoFollow(path, 0o755, fsutil.Keep, func(w io.Writer) error {
		_, err := w.Write(bin)
		return err
	}); err != nil {
		return "", err
	}
	return path, nil
}

func tailLines(s string, n int) []string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return lines
}
