// SPDX-License-Identifier: AGPL-3.0-only

package deploy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/redact"
)

// Ошибки релиза.
var (
	ErrRegistry       = errors.New("REGISTRY_UNAVAILABLE")
	ErrRegistryAuth   = errors.New("REGISTRY_AUTH_FAILED")
	ErrPreDeploy      = errors.New("PRE_DEPLOY_FAILED")
	ErrHealthcheck    = errors.New("HEALTHCHECK_FAILED")
	ErrNoFreePort     = errors.New("DEPLOY_PORTS_EXHAUSTED")
	ErrDeadline       = errors.New("BUILD_TIMEOUT")
	ErrReleaseTimeout = errors.New("DEPLOY_TIMEOUT")
	ErrImageGone      = errors.New("RELEASE_IMAGE_GONE")
	ErrAppMissing     = errors.New("DEPLOY_APP_NOT_FOUND")
	ErrHostTaken      = errors.New("DOMAIN_TAKEN")
	ErrComposeDenied  = errors.New("DEPLOY_COMPOSE_FORBIDDEN")
)

// Порты приложений на 127.0.0.1 (их видит только Caddy на этом сервере).
const (
	portFirst = 20000
	portLast  = 29999
)

// Step — ход релиза для OperationProgress.deploy.
type Step func(step agentv1.DeployStep, attempt uint32)

// ReleaseJob — релиз контейнера.
type ReleaseJob struct {
	Params *agentv1.DeployReleaseParams
	Open   *Opener
	Step   Step
	Log    func(string)
}

func shortID(id string) string { return strings.ReplaceAll(id, "-", "")[:12] }

// ContainerName — trassa-<app>-<release> (по 12 знаков id).
func ContainerName(app, release string) string {
	return "trassa-" + shortID(app) + "-" + shortID(release)
}

func networkName(app string) string { return "trassa-" + shortID(app) }

func volumeName(app, v string) string { return "trassa-" + shortID(app) + "-" + v }

// registryOf — реестр образа по правилам Docker: первый компонент с точкой, двоеточием или localhost — хост
// реестра, иначе Docker Hub.
func registryOf(ref string) string {
	first, _, found := strings.Cut(ref, "/")
	if !found || (!strings.ContainsAny(first, ".:") && first != "localhost") {
		return "docker.io"
	}
	return canonRegistry(first)
}

func canonRegistry(h string) string {
	switch h = strings.ToLower(h); h {
	case "index.docker.io", "registry-1.docker.io", "registry.hub.docker.com":
		return "docker.io"
	}
	return h
}

// pull — образ по дайджесту с учётными данными только на скачивание; поток хода Docker разбирается до конца.
// Учётные данные уходят только реестру pull_from: dockerd не сверяет serveraddress с хостом образа, и образ
// из чужого реестра получил бы логин и пароль реестра пространства.
func (e *Env) pull(ctx context.Context, ref string, from *agentv1.RegistryAuth, auth string, secrets []string) error {
	repo, digest, _ := strings.Cut(ref, "@")
	hdr := map[string]string{}
	if auth != "" && from != nil && registryOf(ref) == canonRegistry(from.GetServer()) {
		hdr["X-Registry-Auth"] = auth
	}
	resp, err := e.Docker.Do(ctx, http.MethodPost, "/images/create?fromImage="+url.QueryEscape(repo)+"&tag="+url.QueryEscape(digest), nil, hdr)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrRegistry, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		msg := clean(string(b), secrets)
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden || strings.Contains(msg, "unauthorized") {
			return fmt.Errorf("%w: %s", ErrRegistryAuth, msg)
		}
		if resp.StatusCode == http.StatusNotFound {
			return fmt.Errorf("%w: %s", ErrImageGone, msg)
		}
		return fmt.Errorf("%w: HTTP %d %s", ErrRegistry, resp.StatusCode, msg)
	}
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		var m struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(sc.Bytes(), &m) == nil && m.Error != "" {
			msg := clean(m.Error, secrets)
			if strings.Contains(msg, "unauthorized") || strings.Contains(msg, "denied") {
				return fmt.Errorf("%w: %s", ErrRegistryAuth, msg)
			}
			if strings.Contains(msg, "manifest unknown") || strings.Contains(msg, "not found") {
				return fmt.Errorf("%w: %s", ErrImageGone, msg)
			}
			return fmt.Errorf("%w: %s", ErrRegistry, msg)
		}
	}
	return sc.Err()
}

func clean(s string, secrets []string) string {
	for _, v := range secrets {
		if len(v) >= 4 {
			s = strings.ReplaceAll(s, v, redact.Mask)
		}
	}
	s = redact.Text(s)
	if len(s) > 2000 {
		s = s[:2000]
	}
	return strings.ToValidUTF8(s, "")
}

// freePort — свободный порт на 127.0.0.1 из диапазона приложений (и не занятый контейнерами Trassa).
func (e *Env) freePort(ctx context.Context) (int, error) { return e.freePortExcept(ctx, nil) }

func (e *Env) freePortExcept(ctx context.Context, taken map[int]bool) (int, error) {
	used := map[int]bool{}
	for p := range taken {
		used[p] = true
	}
	if st, err := e.LoadProxy(); err == nil {
		for _, recs := range st.Apps {
			for _, r := range recs {
				if _, port, ok := strings.Cut(r.Dial, "127.0.0.1:"); ok {
					if n, err := strconv.Atoi(port); err == nil {
						used[n] = true
					}
				}
			}
		}
	}
	if cs, err := e.appContainers(ctx, ""); err == nil {
		for _, c := range cs {
			for _, p := range c.Ports {
				used[int(p.PublicPort)] = true
			}
		}
	}
	for p := portFirst; p <= portLast; p++ {
		if used[p] {
			continue
		}
		l, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(p))
		if err != nil {
			continue
		}
		l.Close()
		return p, nil
	}
	return 0, ErrNoFreePort
}

func (e *Env) ensureNetwork(ctx context.Context, app string) error {
	body, _ := json.Marshal(map[string]any{"Name": networkName(app), "Driver": "bridge", "CheckDuplicate": true,
		"Labels": map[string]string{LabelApp: app}})
	err := e.dockerJSON(ctx, http.MethodPost, "/networks/create", bytes.NewReader(body), nil)
	if err != nil && strings.Contains(err.Error(), "HTTP 409") {
		return nil
	}
	return err
}

// logOpts — ротация журналов контейнеров Trassa (docker.ensure).
func (e *Env) logOpts() map[string]string {
	return map[string]string{"max-size": "20m", "max-file": "5"}
}

// containerSpec — параметры create из типизированных полей: порт только на 127.0.0.1, именованные тома,
// no-new-privileges, журнал local с ротацией, метки Trassa.
func (e *Env) containerSpec(p *agentv1.DeployReleaseParams, env []string, hostPort int, cmd []string) map[string]any {
	type m = map[string]any
	var mounts []any
	for _, v := range p.GetVolumes() {
		mounts = append(mounts, m{"Type": "volume", "Source": volumeName(p.GetAppId(), v.GetName()), "Target": v.GetMountPath(),
			"VolumeOptions": m{"Labels": map[string]string{LabelApp: p.GetAppId()}}})
	}
	hc := m{
		"RestartPolicy": m{"Name": "unless-stopped"}, "Init": true, "SecurityOpt": []string{"no-new-privileges"},
		"LogConfig": m{"Type": "local", "Config": e.logOpts()}, "Mounts": mounts,
		"Memory": int64(p.GetLimits().GetMemoryMb()) << 20, "NanoCpus": int64(p.GetLimits().GetMilliCpus()) * 1_000_000,
	}
	spec := m{
		"Image": p.GetImageRef(), "Env": env,
		"Labels":           map[string]string{LabelApp: p.GetAppId(), LabelRelease: p.GetReleaseId()},
		"NetworkingConfig": m{"EndpointsConfig": m{networkName(p.GetAppId()): m{}}},
	}
	if cmd != nil {
		spec["Cmd"] = cmd
		spec["Labels"] = map[string]string{LabelApp: p.GetAppId(), LabelRelease: p.GetReleaseId(), "trassa.role": "pre-deploy"}
		hc["RestartPolicy"] = m{"Name": "no"}
	} else {
		port := fmt.Sprintf("%d/tcp", p.GetContainerPort())
		spec["ExposedPorts"] = m{port: m{}}
		hc["PortBindings"] = m{port: []any{m{"HostIp": "127.0.0.1", "HostPort": strconv.Itoa(hostPort)}}}
	}
	spec["HostConfig"] = hc
	return spec
}

func (e *Env) create(ctx context.Context, name string, spec map[string]any) (string, error) {
	body, _ := json.Marshal(spec)
	var out struct {
		ID string `json:"Id"`
	}
	if err := e.dockerJSON(ctx, http.MethodPost, "/containers/create?name="+url.QueryEscape(name), bytes.NewReader(body), &out); err != nil {
		return "", err
	}
	return out.ID, nil
}

func (e *Env) start(ctx context.Context, id string) error {
	return e.dockerJSON(ctx, http.MethodPost, "/containers/"+id+"/start", nil, nil)
}

func (e *Env) stop(ctx context.Context, id string, t uint32) error {
	err := e.dockerJSON(ctx, http.MethodPost, "/containers/"+id+"/stop?t="+strconv.Itoa(int(t)), nil, nil)
	if err != nil && strings.Contains(err.Error(), "HTTP 304") {
		return nil
	}
	return err
}

func (e *Env) remove(ctx context.Context, id string) error {
	err := e.dockerJSON(ctx, http.MethodDelete, "/containers/"+id+"?force=1", nil, nil)
	if err != nil && strings.Contains(err.Error(), "HTTP 404") {
		return nil
	}
	return err
}

// logTail — последние строки журнала контейнера (до 100, секреты вырезаны).
func (e *Env) logTail(ctx context.Context, id string, secrets []string) string {
	resp, err := e.Docker.Do(ctx, http.MethodGet, "/containers/"+id+"/logs?stdout=1&stderr=1&tail=100", nil, nil)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	var b strings.Builder
	for {
		_, payload, err := readFrame(resp.Body)
		if err != nil {
			break
		}
		b.Write(payload)
		if b.Len() > 64<<10 {
			break
		}
	}
	return clean(b.String(), secrets)
}

// preDeploy — команда перед переключением в одноразовом контейнере из нового образа (R7), с её сроком.
func (e *Env) preDeploy(ctx context.Context, p *agentv1.DeployReleaseParams, env []string, secrets []string) error {
	if len(p.GetPreDeployCommand()) == 0 {
		return nil
	}
	timeout := time.Duration(p.GetPreDeployTimeoutSec()) * time.Second
	if timeout == 0 {
		timeout = 10 * time.Minute
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	id, err := e.create(cctx, ContainerName(p.GetAppId(), p.GetReleaseId())+"-pre", e.containerSpec(p, env, 0, p.GetPreDeployCommand()))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrPreDeploy, err)
	}
	defer func() { _ = e.remove(context.WithoutCancel(ctx), id) }()
	if err := e.start(cctx, id); err != nil {
		return fmt.Errorf("%w: %v", ErrPreDeploy, err)
	}
	var w struct {
		StatusCode int `json:"StatusCode"`
	}
	if err := e.dockerJSON(cctx, http.MethodPost, "/containers/"+id+"/wait", nil, &w); err != nil {
		return fmt.Errorf("%w: %v", ErrPreDeploy, err)
	}
	if w.StatusCode != 0 {
		return fmt.Errorf("%w: код %d: %s", ErrPreDeploy, w.StatusCode, e.logTail(context.WithoutCancel(ctx), id, secrets))
	}
	return nil
}

// healthy — 2xx подряд successes раз до timeout (план: 3 подряд за 120 с).
func healthy(ctx context.Context, port int, h *agentv1.HealthCheck, step Step) (uint32, error) {
	path, timeout, interval, need := "/", 120*time.Second, time.Second, uint32(3)
	if h != nil {
		path, timeout = h.GetPath(), time.Duration(h.GetTimeoutSec())*time.Second
		interval, need = time.Duration(h.GetIntervalMs())*time.Millisecond, h.GetSuccesses()
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	hc := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	var attempts, ok uint32
	for {
		attempts++
		if step != nil {
			step(agentv1.DeployStep_DEPLOY_STEP_HEALTHCHECK, attempts)
		}
		req, _ := http.NewRequestWithContext(cctx, http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d%s", port, path), nil)
		if resp, err := hc.Do(req); err == nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
			resp.Body.Close()
			if resp.StatusCode/100 == 2 {
				ok++
			} else {
				ok = 0
			}
		} else {
			ok = 0
		}
		if ok >= need {
			return attempts, nil
		}
		select {
		case <-cctx.Done():
			return attempts, fmt.Errorf("%w: %d успехов подряд из %d за %s", ErrHealthcheck, ok, need, timeout)
		case <-time.After(interval):
		}
	}
}

// setAppRoutes — маршруты приложения app в состоянии прокси и в Caddy (recs == nil — убрать); возвращает
// прежние записи. Долгие операции деплоя идут без общей блокировки, поэтому чтение-изменение-запись состояния
// прокси берёт её здесь (RouteLock), иначе правка proxy.route.apply или откат потерялись бы.
func (e *Env) setAppRoutes(ctx context.Context, app string, recs []RouteRec) ([]RouteRec, bool, string, error) {
	if e.RouteLock != nil {
		unlock, err := e.RouteLock(ctx)
		if err != nil {
			return nil, false, "", err
		}
		defer unlock()
	}
	st, err := e.LoadProxy()
	if err != nil {
		return nil, false, "", err
	}
	if err := hostsFree(st, app, recs); err != nil {
		return nil, false, "", err
	}
	prev, had := st.Apps[app]
	if recs == nil {
		delete(st.Apps, app)
	} else {
		st.Apps[app] = recs
	}
	if err := e.loadRoutes(ctx, st); err != nil {
		return nil, false, "", err
	}
	if err := e.saveProxy(st); err != nil {
		return nil, false, "", err
	}
	return prev, had, RoutesHash(st), nil
}

// appRoutes — записи маршрутов релиза; dial — адрес сервиса на 127.0.0.1.
func appRoutes(p *agentv1.DeployReleaseParams, dial func(service string) string) []RouteRec {
	var recs []RouteRec
	for _, r := range p.GetRoutes() {
		rec := RouteRec{Hosts: r.GetHosts(), Service: r.GetService(), RedirectTo: r.GetRedirectTo()}
		if rec.RedirectTo == "" {
			rec.Dial = dial(r.GetService())
		}
		recs = append(recs, rec)
	}
	return recs
}

// switchRoutes — маршруты приложения на новый адрес.
func (e *Env) switchRoutes(ctx context.Context, p *agentv1.DeployReleaseParams, dial string) (string, error) {
	if len(p.GetRoutes()) == 0 {
		return "", nil
	}
	_, _, hash, err := e.setAppRoutes(ctx, p.GetAppId(), appRoutes(p, func(string) string { return dial }))
	return hash, err
}

// Release — deploy.release (контейнер): образ → команда перед переключением → новый контейнер → проверка
// здоровья → переключение маршрута → пауза → остановка старых. До переключения сбой удаляет новый контейнер
// (откат RELEASE: прежний релиз продолжает работать); после переключения релиз доводится до конца.
// RECREATE останавливает старые до запуска нового — его сбой оставляет приложение остановленным.
func (e *Env) Release(ctx context.Context, j ReleaseJob) (*agentv1.DeployReleaseResult, bool, error) {
	p := j.Params
	if p.GetKind() != agentv1.ReleaseKind_RELEASE_KIND_CONTAINER {
		return e.releaseCompose(ctx, j)
	}
	step := j.Step
	if step == nil {
		step = func(agentv1.DeployStep, uint32) {}
	}
	res := &agentv1.DeployReleaseResult{ImageRef: p.GetImageRef()}
	env, secrets, err := j.Open.Env(p.GetEnv(), p.GetEnvPlain(), FieldEnv)
	if err != nil {
		return nil, false, err
	}
	auth, pw, err := j.Open.RegistryAuth(p.GetPullFrom())
	if err != nil {
		return nil, false, err
	}
	secrets = append(secrets, pw)
	old, err := e.appContainers(ctx, p.GetAppId())
	if err != nil {
		return nil, false, err
	}
	for _, c := range old {
		if c.State == "running" && c.Labels["trassa.role"] == "" {
			res.PreviousReleaseId = c.Labels[LabelRelease]
		}
	}
	for _, c := range old {
		if c.Labels[LabelRelease] != p.GetReleaseId() {
			continue
		}
		// Остаток прерванной попытки того же релиза убирается; работающий релиз не пересоздаётся.
		if c.State == "running" && c.Labels["trassa.role"] == "" {
			return res, false, fmt.Errorf("релиз %s уже работает", p.GetReleaseId())
		}
		_ = e.remove(ctx, c.ID)
	}
	step(agentv1.DeployStep_DEPLOY_STEP_PULL, 0)
	if err := e.pull(ctx, p.GetImageRef(), p.GetPullFrom(), auth, secrets); err != nil {
		res.FailedStep = agentv1.DeployStep_DEPLOY_STEP_PULL
		return res, false, err
	}
	if err := e.ensureNetwork(ctx, p.GetAppId()); err != nil {
		return res, false, err
	}
	step(agentv1.DeployStep_DEPLOY_STEP_PRE_DEPLOY, 0)
	if err := e.preDeploy(ctx, p, env, secrets); err != nil {
		res.FailedStep = agentv1.DeployStep_DEPLOY_STEP_PRE_DEPLOY
		return res, false, err
	}
	stopOld := func() {
		for _, c := range old {
			if c.Labels[LabelRelease] == p.GetReleaseId() {
				continue
			}
			step(agentv1.DeployStep_DEPLOY_STEP_STOP_OLD, 0)
			if err := e.stop(context.WithoutCancel(ctx), c.ID, p.GetDrainSeconds()); err != nil && j.Log != nil {
				j.Log("старый контейнер не остановлен: " + err.Error())
			}
			_ = e.remove(context.WithoutCancel(ctx), c.ID)
		}
	}
	if p.GetStrategy() == agentv1.ReleaseStrategy_RELEASE_STRATEGY_RECREATE {
		stopOld()
	}
	port, err := e.freePort(ctx)
	if err != nil {
		res.FailedStep = agentv1.DeployStep_DEPLOY_STEP_START
		return res, false, err
	}
	name := ContainerName(p.GetAppId(), p.GetReleaseId())
	step(agentv1.DeployStep_DEPLOY_STEP_START, 0)
	id, err := e.create(ctx, name, e.containerSpec(p, env, port, nil))
	if err != nil {
		res.FailedStep = agentv1.DeployStep_DEPLOY_STEP_START
		return res, false, err
	}
	// Сбой после создания: новый контейнер убирается — при ROLLING прежний релиз так и работает (откат),
	// при RECREATE прежний уже остановлен, вернуть нечего.
	fail := func(stepAt agentv1.DeployStep, err error) (*agentv1.DeployReleaseResult, bool, error) {
		res.FailedStep, res.LogTail = stepAt, e.logTail(context.WithoutCancel(ctx), id, secrets)
		_ = e.remove(context.WithoutCancel(ctx), id)
		return res, p.GetStrategy() != agentv1.ReleaseStrategy_RELEASE_STRATEGY_RECREATE, err
	}
	if err := e.start(ctx, id); err != nil {
		return fail(agentv1.DeployStep_DEPLOY_STEP_START, err)
	}
	attempts, err := healthy(ctx, port, p.GetHealthcheck(), step)
	res.HealthAttempts = attempts
	if err != nil {
		return fail(agentv1.DeployStep_DEPLOY_STEP_HEALTHCHECK, err)
	}
	step(agentv1.DeployStep_DEPLOY_STEP_SWITCH, 0)
	// Отмена, пришедшая до SWITCH, видна здесь; после отметки SWITCH помощник её уже не принимает.
	if err := ctx.Err(); err != nil {
		return fail(agentv1.DeployStep_DEPLOY_STEP_SWITCH, err)
	}
	hash, err := e.switchRoutes(ctx, p, fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return fail(agentv1.DeployStep_DEPLOY_STEP_SWITCH, err)
	}
	res.RoutesHash, res.ContainerIds, res.HostPort = hash, []string{id}, uint32(port)
	// После переключения релиз не отменяется (CANCEL_TOO_LATE): срок во время паузы лишь укорачивает её.
	step(agentv1.DeployStep_DEPLOY_STEP_DRAIN, 0)
	select {
	case <-ctx.Done():
	case <-time.After(time.Duration(p.GetDrainSeconds()) * time.Second):
	}
	stopOld()
	if err := e.recordImages(p.GetAppId(), "container", p.GetImageRef()); err != nil && j.Log != nil {
		j.Log("список образов приложения не обновлён: " + err.Error())
	}
	return res, false, nil
}

// hostsOverlap — Caddy отдаёт запрос обоим: одно имя или wildcard на один уровень (*.example.com и a.example.com).
func hostsOverlap(a, b string) bool {
	if a == b {
		return true
	}
	under := func(w, h string) bool {
		if !strings.HasPrefix(w, "*.") {
			return false
		}
		label, rest, ok := strings.Cut(h, ".")
		return ok && label != "" && label != "*" && rest == w[2:]
	}
	return under(a, b) || under(b, a)
}

// hostsFree — имена релиза не заняты другим приложением: иначе релиз A перехватил бы трафик и сертификат B.
func hostsFree(st *ProxyState, app string, recs []RouteRec) error {
	for other, theirs := range st.Apps {
		if other == app {
			continue
		}
		for _, r := range recs {
			for _, h := range r.Hosts {
				for _, t := range theirs {
					for _, o := range t.Hosts {
						if hostsOverlap(h, o) {
							return fmt.Errorf("%w: %s пересекается с %s другого приложения", ErrHostTaken, h, o)
						}
					}
				}
			}
		}
	}
	return nil
}
