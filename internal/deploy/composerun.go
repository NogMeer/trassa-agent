// SPDX-License-Identifier: AGPL-3.0-only

package deploy

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/fsutil"
)

func closeFD(fd int) error { return syscall.Close(fd) }

const (
	composeFile     = "compose.json"
	composePrevFile = "compose.prev.json"
)

// composeEnv — окружение вызова compose (решение E17 п. 4): удалённые ресурсы выключены, пустой HOME и
// DOCKER_CONFIG (нет config.json — нет чужих учётных данных и помощников входа), плюс переменные приложения.
func (e *Env) composeEnv(home string, vars []string) []string {
	return append([]string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C", "HOME=" + home, "DOCKER_CONFIG=" + home,
		"COMPOSE_EXPERIMENTAL_GIT_REMOTE=false", "COMPOSE_EXPERIMENTAL_OCI_REMOTE=false"}, vars...)
}

func (e *Env) compose(ctx context.Context, s *composeSpec, dir string, env []string, args ...string) ([]byte, error) {
	exec := e.Exec
	if exec == nil {
		exec = RunEnv
	}
	base := []string{"compose", "--project-name", s.project(), "--project-directory", dir, "-f", filepath.Join(dir, composeFile)}
	return exec(ctx, env, "docker", append(base, args...)...)
}

func writeFileNoFollow(p string, data []byte) error {
	return fsutil.WriteAtomicNoFollow(p, 0o600, fsutil.Keep, func(w io.Writer) error {
		_, err := w.Write(data)
		return err
	})
}

// composePorts — порт на 127.0.0.1 каждому сервису с маршрутом: прежний из состояния прокси, иначе свободный.
func (e *Env) composePorts(ctx context.Context, p *agentv1.DeployReleaseParams) (map[string]int, error) {
	ports := map[string]int{}
	var prev map[string]int
	if st, err := e.LoadProxy(); err == nil {
		prev = map[string]int{}
		for _, r := range st.Apps[p.GetAppId()] {
			if _, port, ok := strings.Cut(r.Dial, "127.0.0.1:"); ok && r.Service != "" {
				if n, err := strconv.Atoi(port); err == nil {
					prev[r.Service] = n
				}
			}
		}
	}
	taken := map[int]bool{}
	for _, r := range p.GetRoutes() {
		if r.GetRedirectTo() != "" {
			continue
		}
		svc := r.GetService()
		if svc == "" {
			return nil, forbidden("маршрут compose без service")
		}
		if _, ok := ports[svc]; ok {
			continue
		}
		if n, ok := prev[svc]; ok && n >= portFirst && n <= portLast && !taken[n] {
			ports[svc], taken[n] = n, true
			continue
		}
		n, err := e.freePortExcept(ctx, taken)
		if err != nil {
			return nil, err
		}
		ports[svc], taken[n] = n, true
	}
	return ports, nil
}

// releaseCompose — deploy.release с kind = COMPOSE: проверка → образы через Engine API → compose.json →
// повторная проверка нормализованного вида → up --wait → проверка здоровья → маршруты. Сбой после up —
// возврат прежнего compose.json (откат RELEASE); первого релиза — down без томов.
func (e *Env) releaseCompose(ctx context.Context, j ReleaseJob) (*agentv1.DeployReleaseResult, bool, error) {
	p := j.Params
	step := j.Step
	if step == nil {
		step = func(agentv1.DeployStep, uint32) {}
	}
	res := &agentv1.DeployReleaseResult{}
	vars := map[string]bool{}
	for k := range p.GetEnv() {
		vars[k] = true
	}
	for k := range p.GetEnvPlain() {
		vars[k] = true
	}
	ports, err := e.composePorts(ctx, p)
	if err != nil {
		return nil, false, err
	}
	spec := &composeSpec{App: p.GetAppId(), Release: p.GetReleaseId(), Vars: vars, Ports: ports,
		ContainerPort: p.GetContainerPort(), LogOpts: e.logOpts()}
	doc, images, err := ComposeDoc(p.GetCompose(), spec)
	if err != nil {
		return nil, false, err
	}
	env, secrets, err := j.Open.Env(p.GetEnv(), p.GetEnvPlain(), FieldEnv)
	if err != nil {
		return nil, false, err
	}
	auth, pw, err := j.Open.RegistryAuth(p.GetPullFrom())
	if err != nil {
		return nil, false, err
	}
	secrets = append(secrets, pw)
	if old, err := e.appContainers(ctx, p.GetAppId()); err == nil {
		for _, c := range old {
			if c.State == "running" {
				res.PreviousReleaseId = c.Labels[LabelRelease]
			}
		}
	}
	step(agentv1.DeployStep_DEPLOY_STEP_PULL, 0)
	for _, img := range images {
		if err := e.pull(ctx, img, auth, secrets); err != nil {
			res.FailedStep = agentv1.DeployStep_DEPLOY_STEP_PULL
			return res, false, err
		}
	}
	dir, err := e.ensureAppDir(p.GetAppId(), "compose")
	if err != nil {
		return res, false, err
	}
	home, err := e.ensureAppDir(p.GetAppId(), "home")
	if err != nil {
		return res, false, err
	}
	penv := e.composeEnv(home, env)
	cur := filepath.Join(dir, composeFile)
	prev, err := fsutil.ReadLimited(cur, 1<<20)
	hadPrev := err == nil
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return res, false, err
	}
	if hadPrev {
		if err := writeFileNoFollow(filepath.Join(dir, composePrevFile), prev); err != nil {
			return res, false, err
		}
	}
	if err := writeFileNoFollow(cur, doc); err != nil {
		return res, false, err
	}
	restore := func() bool {
		bg := context.WithoutCancel(ctx)
		if !hadPrev {
			_, _ = e.compose(bg, spec, dir, penv, "down", "--remove-orphans")
			_ = os.Remove(cur)
			return false
		}
		if err := writeFileNoFollow(cur, prev); err != nil {
			return false
		}
		_, err := e.compose(bg, spec, dir, penv, "up", "-d", "--wait", "--no-build", "--pull", "never", "--remove-orphans")
		return err == nil
	}
	norm, err := e.compose(ctx, spec, dir, penv, "config", "--format", "json", "--no-interpolate", "--no-env-resolution")
	if err != nil {
		err = errors.New(clean(err.Error(), secrets))
	} else {
		err = CheckNormalized(norm, spec)
	}
	if err != nil {
		// До up ничего не запущено: возвращается только файл.
		if hadPrev {
			_ = writeFileNoFollow(cur, prev)
		} else {
			_ = os.Remove(cur)
		}
		return res, false, err
	}
	step(agentv1.DeployStep_DEPLOY_STEP_START, 0)
	wait := uint32(120)
	if h := p.GetHealthcheck(); h != nil {
		wait = h.GetTimeoutSec()
	}
	if _, err := e.compose(ctx, spec, dir, penv, "up", "-d", "--wait", "--wait-timeout", strconv.Itoa(int(wait)),
		"--no-build", "--pull", "never", "--remove-orphans"); err != nil {
		res.FailedStep = agentv1.DeployStep_DEPLOY_STEP_START
		return res, restore(), errors.New(clean(err.Error(), secrets))
	}
	for _, r := range p.GetRoutes() {
		port, ok := ports[r.GetService()]
		if !ok {
			continue
		}
		attempts, err := healthy(ctx, port, p.GetHealthcheck(), step)
		res.HealthAttempts += attempts
		if err != nil {
			res.FailedStep = agentv1.DeployStep_DEPLOY_STEP_HEALTHCHECK
			return res, restore(), err
		}
		break
	}
	step(agentv1.DeployStep_DEPLOY_STEP_SWITCH, 0)
	if err := ctx.Err(); err != nil {
		res.FailedStep = agentv1.DeployStep_DEPLOY_STEP_SWITCH
		return res, restore(), err
	}
	hash, err := e.composeRoutes(ctx, p, ports)
	if err != nil {
		res.FailedStep = agentv1.DeployStep_DEPLOY_STEP_SWITCH
		return res, restore(), err
	}
	res.RoutesHash = hash
	if cs, err := e.appContainers(ctx, p.GetAppId()); err == nil {
		for _, c := range cs {
			res.ContainerIds = append(res.ContainerIds, c.ID)
		}
	}
	for _, port := range ports {
		res.HostPort = uint32(port)
		break
	}
	if err := e.recordImages(p.GetAppId(), "compose", images...); err != nil && j.Log != nil {
		j.Log("список образов приложения не обновлён: " + err.Error())
	}
	return res, false, nil
}

// composeRoutes — маршруты приложения на порты его сервисов.
func (e *Env) composeRoutes(ctx context.Context, p *agentv1.DeployReleaseParams, ports map[string]int) (string, error) {
	if len(p.GetRoutes()) == 0 {
		return "", nil
	}
	_, _, hash, err := e.setAppRoutes(ctx, p.GetAppId(), appRoutes(p, func(svc string) string {
		return "127.0.0.1:" + strconv.Itoa(ports[svc])
	}))
	return hash, err
}

// composeDown — при удалении приложения: down без томов (тома убирает Remove по метке и remove_data).
func (e *Env) composeDown(ctx context.Context, app string) error {
	dir := filepath.Join(e.appDir(app), "compose")
	if _, err := os.Lstat(filepath.Join(dir, composeFile)); err != nil {
		return nil
	}
	home, err := e.ensureAppDir(app, "home")
	if err != nil {
		return err
	}
	_, err = e.compose(ctx, &composeSpec{App: app}, dir, e.composeEnv(home, nil), "down", "--remove-orphans")
	return err
}
