// SPDX-License-Identifier: AGPL-3.0-only

// Package deploy — деплой приложений (E17): Docker, прокси Caddy, релизы и сборка. Решения —
// decisions/E17-deploy.md. Помощник проверяет параметры заново (R10): панель — не единственный рубеж.
package deploy

import (
	"errors"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"strings"
	"unicode/utf8"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/config"
	"github.com/NogMeer/trassa-agent/internal/tools"
)

// Коды отказа проверки 6.
var (
	ErrImageNotPinned = errors.New("DEPLOY_IMAGE_NOT_PINNED")
	ErrToolUnknown    = errors.New("DEPLOY_TOOL_UNKNOWN")
)

var (
	repoRe     = `[a-z0-9]+(?:[._-][a-z0-9]+)*(?::[0-9]{1,5})?(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*`
	imageRepo  = regexp.MustCompile(`^` + repoRe + `$`)
	pinnedRe   = regexp.MustCompile(`^` + repoRe + `@sha256:[0-9a-f]{64}$`)
	hostPortRe = regexp.MustCompile(`^[a-z0-9]+(?:[.-][a-z0-9]+)*(?::[0-9]{1,5})?$`)
	hostRe     = regexp.MustCompile(`^(?:\*\.)?[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)
	envNameRe  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)
	shaRe      = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`)
	hash64Re   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	volumeRe   = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}$`)
	serviceRe  = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)
	versionRe  = regexp.MustCompile(`^\d+\.\d+\.\d+$`)
	logSizeRe  = regexp.MustCompile(`^[1-9][0-9]{0,3}[kmg]$`)
	emailRe    = regexp.MustCompile(`^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,}$`)
)

func printable(s string, max int) bool {
	if len(s) > max || !utf8.ValidString(s) {
		return false
	}
	for _, c := range s {
		if c < 0x20 || c == 0x7f {
			return false
		}
	}
	return true
}

// PinnedImage — образ только по дайджесту (@sha256:): тег можно перезаписать в реестре.
func PinnedImage(ref string) error {
	if !pinnedRe.MatchString(ref) || len(ref) > 512 {
		return fmt.Errorf("%w: %q", ErrImageNotPinned, ref)
	}
	return nil
}

func checkApp(id string) error {
	if !config.IsUUID(id) {
		return errors.New("app_id")
	}
	return nil
}

// checkTool — программа из таблицы помощника: имя, версия, сумма для архитектуры сервера, адрес https.
func checkTool(t *agentv1.DeployTool, allowed ...string) error {
	ok := false
	for _, a := range allowed {
		ok = ok || t.GetName() == a
	}
	if t == nil || !ok || !versionRe.MatchString(t.GetVersion()) {
		return fmt.Errorf("%w: %s", ErrToolUnknown, t.GetName())
	}
	if u, err := url.Parse(t.GetUrl()); err != nil || u.Scheme != "https" || u.User != nil || u.Hostname() == "" {
		return errors.New("адрес программы: только https")
	}
	if err := tools.Check(t.GetName(), t.GetVersion(), t.GetSha256()); err != nil {
		return fmt.Errorf("%w: %v", ErrToolUnknown, err)
	}
	return nil
}

func checkRegistry(r *agentv1.RegistryAuth, what string) error {
	if r == nil {
		return nil
	}
	if !hostPortRe.MatchString(r.GetServer()) || !printable(r.GetUsername(), 256) || r.GetUsername() == "" {
		return fmt.Errorf("%s: server, username", what)
	}
	return checkSealed(r.GetPassword(), what+".password")
}

func checkSealed(s *agentv1.SealedSecret, what string) error {
	if s == nil || len(s.GetKid()) != 16 || len(s.GetEncCt()) < 49 || len(s.GetEncCt()) > 48<<10 {
		return fmt.Errorf("%s: секрет", what)
	}
	return nil
}

func checkEnv(secret map[string]*agentv1.SealedSecret, plain map[string]string) error {
	if len(secret)+len(plain) > 200 {
		return errors.New("переменных больше 200")
	}
	for k, v := range secret {
		if !envNameRe.MatchString(k) {
			return fmt.Errorf("имя переменной %q", k)
		}
		if _, dup := plain[k]; dup {
			return fmt.Errorf("переменная %s и секретная, и открытая", k)
		}
		if err := checkSealed(v, "env:"+k); err != nil {
			return err
		}
	}
	for k, v := range plain {
		if !envNameRe.MatchString(k) || len(v) > 32<<10 || strings.ContainsRune(v, 0) {
			return fmt.Errorf("переменная %q", k)
		}
	}
	return nil
}

// relPath — относительный путь внутри каталога: без «..», абсолютных частей и управляющих символов.
func relPath(p string, allowEmpty bool) error {
	if p == "" {
		if allowEmpty {
			return nil
		}
		return errors.New("пустой путь")
	}
	if !printable(p, 512) || strings.HasPrefix(p, "/") || path.Clean(p) != p || p == ".." || strings.HasPrefix(p, "../") {
		return fmt.Errorf("путь %q", p)
	}
	return nil
}

func checkRoutes(routes []*agentv1.ProxyRoute, app string) error {
	if len(routes) > 500 {
		return errors.New("маршрутов больше 500")
	}
	seen := map[string]bool{}
	for _, r := range routes {
		if err := checkApp(r.GetAppId()); err != nil {
			return err
		}
		if app != "" && r.GetAppId() != app {
			return errors.New("маршрут чужого приложения")
		}
		if n := len(r.GetHosts()); n < 1 || n > 50 {
			return errors.New("hosts: от 1 до 50")
		}
		for _, h := range r.GetHosts() {
			if !hostRe.MatchString(h) || len(h) > 253 {
				return fmt.Errorf("имя %q", h)
			}
			if seen[h] {
				return fmt.Errorf("имя %s в двух маршрутах", h)
			}
			seen[h] = true
		}
		if s := r.GetService(); s != "" && !serviceRe.MatchString(s) {
			return errors.New("service")
		}
		if t := r.GetRedirectTo(); t != "" && !hostRe.MatchString(t) {
			return errors.New("redirect_to: имя хоста")
		}
	}
	return nil
}

// ValidateDockerEnsure — docker.ensure.
func ValidateDockerEnsure(p *agentv1.DockerEnsureParams) error {
	if !versionRe.MatchString(p.GetDockerVersion()) || !supportedDocker[p.GetDockerVersion()] {
		return fmt.Errorf("%w: docker %s", ErrToolUnknown, p.GetDockerVersion())
	}
	if !logSizeRe.MatchString(p.GetLogMaxSize()) || p.GetLogMaxFiles() < 1 || p.GetLogMaxFiles() > 100 {
		return errors.New("log_max_size, log_max_files")
	}
	if len(p.GetAptKey()) > 64<<10 {
		return errors.New("apt_key")
	}
	names := map[string]bool{}
	for _, t := range p.GetPlugins() {
		if err := checkTool(t, "docker-compose", "docker-buildx"); err != nil {
			return err
		}
		if names[t.GetName()] {
			return errors.New("плагин дважды")
		}
		names[t.GetName()] = true
	}
	if !names["docker-compose"] || !names["docker-buildx"] {
		return errors.New("plugins: нужны docker-compose и docker-buildx")
	}
	return nil
}

// ValidateProxyEnsure — proxy.ensure.
func ValidateProxyEnsure(p *agentv1.ProxyEnsureParams) error {
	if err := checkTool(p.GetCaddy(), "caddy"); err != nil {
		return err
	}
	if !emailRe.MatchString(p.GetAcmeEmail()) {
		return errors.New("acme_email")
	}
	return nil
}

// ValidateRouteApply — proxy.route.apply: полное состояние, пустое — отказ (R1).
func ValidateRouteApply(p *agentv1.ProxyRouteApplyParams) error {
	if len(p.GetRoutes()) == 0 {
		return errors.New("routes: пустое состояние (R1)")
	}
	if b := p.GetBaseHash(); b != "" && !hash64Re.MatchString(b) {
		return errors.New("base_hash")
	}
	return checkRoutes(p.GetRoutes(), "")
}

// ValidateInspect — deploy.inspect (пусто — все приложения).
func ValidateInspect(p *agentv1.DeployInspectParams) error {
	if p.GetAppId() == "" {
		return nil
	}
	return checkApp(p.GetAppId())
}

// Пределы сроков исполнения от выдачи операции (decisions E17, часть 7).
const (
	MaxBuildRun   = 35 * 60 * 1000
	MaxReleaseRun = 15 * 60 * 1000
)

func checkDeadline(deadline, issued, max int64) error {
	if issued <= 0 || deadline <= issued || deadline-issued > max {
		return fmt.Errorf("deadline_ms: от выдачи операции до %d мин", max/60000)
	}
	return nil
}

// ValidateRelease — deploy.release и тело deploy.rollback.
func ValidateRelease(p *agentv1.DeployReleaseParams, issuedAtMs int64) error {
	if err := checkApp(p.GetAppId()); err != nil {
		return err
	}
	if !config.IsUUID(p.GetReleaseId()) {
		return errors.New("release_id")
	}
	switch p.GetKind() {
	case agentv1.ReleaseKind_RELEASE_KIND_CONTAINER:
		if err := PinnedImage(p.GetImageRef()); err != nil {
			return err
		}
		if p.GetCompose() != "" {
			return errors.New("compose у контейнера")
		}
		if p.GetContainerPort() < 1 || p.GetContainerPort() > 65535 {
			return errors.New("container_port")
		}
	case agentv1.ReleaseKind_RELEASE_KIND_COMPOSE:
		if p.GetImageRef() != "" || p.GetCompose() == "" || len(p.GetCompose()) > 256<<10 {
			return errors.New("compose: только compose, без image_ref")
		}
		// Команда перед переключением у compose не исполняется (сервисы обновляются на месте): отказ, а не пропуск.
		if len(p.GetPreDeployCommand()) > 0 || len(p.GetVolumes()) > 0 {
			return errors.New("compose: pre_deploy_command и volumes задаются в документе")
		}
		for _, r := range p.GetRoutes() {
			if r.GetRedirectTo() == "" && (r.GetService() == "" || p.GetContainerPort() < 1 || p.GetContainerPort() > 65535) {
				return errors.New("compose: маршруту нужны service и container_port")
			}
		}
	default:
		return errors.New("kind")
	}
	if err := checkRegistry(p.GetPullFrom(), "pull_from"); err != nil {
		return err
	}
	if err := checkEnv(p.GetEnv(), p.GetEnvPlain()); err != nil {
		return err
	}
	if h := p.GetHealthcheck(); h != nil {
		if !strings.HasPrefix(h.GetPath(), "/") || !printable(h.GetPath(), 512) || strings.ContainsAny(h.GetPath(), " \t") ||
			h.GetTimeoutSec() < 5 || h.GetTimeoutSec() > 600 || h.GetIntervalMs() < 100 || h.GetIntervalMs() > 60000 ||
			h.GetSuccesses() < 1 || h.GetSuccesses() > 10 {
			return errors.New("healthcheck")
		}
	}
	if len(p.GetPreDeployCommand()) > 64 || p.GetPreDeployTimeoutSec() > 3600 {
		return errors.New("pre_deploy")
	}
	for _, a := range p.GetPreDeployCommand() {
		if len(a) > 4096 || strings.ContainsRune(a, 0) {
			return errors.New("pre_deploy_command")
		}
	}
	switch p.GetStrategy() {
	case agentv1.ReleaseStrategy_RELEASE_STRATEGY_ROLLING, agentv1.ReleaseStrategy_RELEASE_STRATEGY_RECREATE:
	default:
		return errors.New("strategy")
	}
	if l := p.GetLimits(); l.GetMemoryMb() > 1<<20 || l.GetMilliCpus() > 1024000 {
		return errors.New("limits")
	}
	for _, v := range p.GetVolumes() {
		mp := v.GetMountPath()
		if !volumeRe.MatchString(v.GetName()) || !strings.HasPrefix(mp, "/") || path.Clean(mp) != mp || mp == "/" || !printable(mp, 512) {
			return fmt.Errorf("том %q", v.GetName())
		}
	}
	if err := checkRoutes(p.GetRoutes(), p.GetAppId()); err != nil {
		return err
	}
	if p.GetDrainSeconds() > 600 {
		return errors.New("drain_seconds")
	}
	if len(p.GetKeepImages()) > 20 {
		return errors.New("keep_images")
	}
	for _, k := range p.GetKeepImages() {
		if err := PinnedImage(k); err != nil {
			return err
		}
	}
	return checkDeadline(p.GetDeadlineMs(), issuedAtMs, MaxReleaseRun)
}

// ValidateRollback — deploy.rollback.
func ValidateRollback(p *agentv1.DeployRollbackParams, issuedAtMs int64) error {
	if !config.IsUUID(p.GetTargetReleaseId()) {
		return errors.New("target_release_id")
	}
	return ValidateRelease(p.GetRelease(), issuedAtMs)
}

// ValidateBuild — deploy.build: git по https без учётных данных в адресе, коммит, секреты сборки отдельно от
// аргументов, push — учётными данными сборщика.
func ValidateBuild(p *agentv1.DeployBuildParams, issuedAtMs int64) error {
	if err := checkApp(p.GetAppId()); err != nil {
		return err
	}
	if !config.IsUUID(p.GetReleaseId()) {
		return errors.New("release_id")
	}
	g := p.GetSource()
	u, err := url.Parse(g.GetRepoUrl())
	if err != nil || u.Scheme != "https" || u.User != nil || u.Hostname() == "" || u.RawQuery != "" || u.Fragment != "" || len(g.GetRepoUrl()) > 2048 {
		return errors.New("repo_url: https без учётных данных")
	}
	if !shaRe.MatchString(g.GetCommitSha()) {
		return errors.New("commit_sha")
	}
	if g.GetToken() != nil {
		if !printable(g.GetUsername(), 256) || g.GetUsername() == "" {
			return errors.New("username")
		}
		if err := checkSealed(g.GetToken(), "git_credential"); err != nil {
			return err
		}
	}
	if err := relPath(g.GetRootDir(), true); err != nil {
		return err
	}
	switch p.GetBuildKind() {
	case agentv1.BuildKind_BUILD_KIND_DOCKERFILE:
		if err := relPath(p.GetDockerfilePath(), true); err != nil {
			return err
		}
		if p.GetRailpack() != nil {
			return errors.New("railpack у Dockerfile")
		}
	case agentv1.BuildKind_BUILD_KIND_RAILPACK:
		if err := checkTool(p.GetRailpack(), "railpack"); err != nil {
			return err
		}
	default:
		return errors.New("build_kind")
	}
	if len(p.GetBuildSecrets())+len(p.GetBuildArgs()) > 100 {
		return errors.New("секретов и аргументов больше 100")
	}
	if err := checkEnv(p.GetBuildSecrets(), p.GetBuildArgs()); err != nil {
		return err
	}
	// BUILDKIT_* меняют фронтенд и поведение BuildKit (BUILDKIT_SYNTAX — чужой образ фронтенда): только агент.
	for k := range p.GetBuildArgs() {
		if strings.HasPrefix(strings.ToUpper(k), "BUILDKIT_") {
			return fmt.Errorf("build_args: %s задаёт агент", k)
		}
	}
	if m := p.GetMemoryLimitMb(); m < 256 || m > 65536 {
		return errors.New("memory_limit_mb: 256–65536")
	}
	if p.GetPushTo() == nil {
		return errors.New("push_to")
	}
	if err := checkRegistry(p.GetPushTo(), "push_to"); err != nil {
		return err
	}
	if !imageRepo.MatchString(p.GetImageRepo()) || !strings.HasPrefix(p.GetImageRepo(), p.GetPushTo().GetServer()+"/") {
		return errors.New("image_repo: в реестре push_to, без тега")
	}
	return checkDeadline(p.GetDeadlineMs(), issuedAtMs, MaxBuildRun)
}

// ValidateControl — deploy.control.
func ValidateControl(p *agentv1.DeployControlParams, issuedAtMs int64) error {
	if err := checkApp(p.GetAppId()); err != nil {
		return err
	}
	switch p.GetAction() {
	case agentv1.ControlAction_CONTROL_ACTION_RESTART, agentv1.ControlAction_CONTROL_ACTION_STOP, agentv1.ControlAction_CONTROL_ACTION_START:
	default:
		return errors.New("action")
	}
	return checkDeadline(p.GetDeadlineMs(), issuedAtMs, MaxReleaseRun)
}

// ValidateRemove — deploy.remove.
func ValidateRemove(p *agentv1.DeployRemoveParams) error { return checkApp(p.GetAppId()) }

// ValidateImagesPrune — deploy.images_prune: образы точек отката — только закреплённые.
func ValidateImagesPrune(p *agentv1.DeployImagesPruneParams) error {
	if err := checkApp(p.GetAppId()); err != nil {
		return err
	}
	if len(p.GetKeepImages()) > 20 {
		return errors.New("keep_images")
	}
	for _, k := range p.GetKeepImages() {
		if err := PinnedImage(k); err != nil {
			return err
		}
	}
	return nil
}
