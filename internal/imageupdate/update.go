// SPDX-License-Identifier: AGPL-3.0-only

package imageupdate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"time"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
)

// Метки compose на контейнере (docker compose v2).
const (
	LabelProject     = "com.docker.compose.project"
	LabelService     = "com.docker.compose.service"
	LabelWorkingDir  = "com.docker.compose.project.working_dir"
	LabelConfigFiles = "com.docker.compose.project.config_files"
	LabelEnvFile     = "com.docker.compose.project.environment_file"
	LabelOneOff      = "com.docker.compose.oneoff"
	labelTrassaApp   = "trassa.app_id"
)

// Пределы.
const (
	MinWait    = 30
	MaxWait    = 600
	maxFile    = 1 << 20
	maxConfigs = 8
)

var (
	reContainer = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
	reProject   = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)
	reService   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)
	reTag       = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)
	// [домен[:порт]/]путь:тег — без дайджеста (закреплённый дайджестом образ не меняется тегом).
	reImage = regexp.MustCompile(`^(?:[A-Za-z0-9.-]+(?::[0-9]{1,5})?/)?[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)
	// Каталоги, где compose-файл проекта пользователя быть не может (свои файлы Trassa, системные псевдо-ФС).
	forbiddenPrefixes = []string{"/proc", "/sys", "/dev", "/run/trassa", "/etc/trassa", "/var/lib/trassa"}
)

// Validate — проверка параметров до исполнения (ops, проверка 6). Образ с дайджестом — отдельный код при работе.
func Validate(p *agentv1.ContainerUpdateParams) error {
	switch {
	case !reContainer.MatchString(p.GetContainer()):
		return errors.New("container")
	case !reProject.MatchString(p.GetProject()):
		return errors.New("project")
	case !reService.MatchString(p.GetService()):
		return errors.New("service")
	case len(p.GetCurrentImage()) > 255 || !reImage.MatchString(p.GetCurrentImage()):
		return errors.New("current_image")
	case !reTag.MatchString(p.GetTargetTag()):
		return errors.New("target_tag")
	case p.GetWaitSec() < MinWait || p.GetWaitSec() > MaxWait:
		return fmt.Errorf("wait_sec: от %d до %d", MinWait, MaxWait)
	}
	return nil
}

// SplitImage — «репозиторий» и тег ссылки repo:tag (последнее «:» после последнего «/»).
func SplitImage(ref string) (repo, tag string, ok bool) {
	i := strings.LastIndex(ref, ":")
	if i <= strings.LastIndex(ref, "/") || strings.Contains(ref, "@") {
		return "", "", false
	}
	return ref[:i], ref[i+1:], true
}

// Container — нужное из Engine API.
type Container struct {
	ID           string
	Name         string
	ImageID      string
	Image        string // Config.Image — как записано в compose
	Labels       map[string]string
	Status       string // running, exited…
	Health       string // healthy, unhealthy, starting или пусто
	RestartCount int
}

// Docker — то, что пакету нужно от Engine API (dockerapi в помощнике, подделка в тестах).
type Docker interface {
	Inspect(ctx context.Context, name string) (*Container, error)
	// Service — контейнеры сервиса проекта (без одноразовых `compose run`).
	Service(ctx context.Context, project, service string) ([]Container, error)
	// Tag — повесить тег repo:tag на образ id (возврат прежнего образа под плавающим тегом).
	Tag(ctx context.Context, id, repo, tag string) error
}

// Runner запускает программу без оболочки: аргументы — отдельными строками, окружение — только env.
type Runner func(ctx context.Context, env []string, name string, args ...string) (stdout, stderr []byte, err error)

// Hooks — точка отката помощника: копия файлов до правки и их возврат.
type Hooks struct {
	Log     func(format string, a ...any)
	Backup  func(paths []string) error
	Restore func() error
}

// Env — окружение операции.
type Env struct {
	Docker Docker
	Run    Runner
	// Root — префикс путей (тесты); на сервере "".
	Root string
	// Poll — шаг опроса, Stable — сколько контейнер обязан работать подряд.
	Poll, Stable time.Duration
	// PullTimeout, UpTimeout — сроки команд compose.
	PullTimeout, UpTimeout time.Duration
}

// ErrRollbackFailed — возврат прежнего образа не удался: сервер в промежуточном состоянии.
var ErrRollbackFailed = errors.New("ROLLBACK_FAILED")

// composeEnv — без переменных окружения помощника: подстановки compose берутся только из .env проекта, как при
// обычном запуске из каталога проекта. HOME=/root — вход в реестры (docker login) того же root, что запускал compose.
var composeEnv = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/root", "LANG=C", "LC_ALL=C",
	"COMPOSE_EXPERIMENTAL_GIT_REMOTE=false", "COMPOSE_EXPERIMENTAL_OCI_REMOTE=false"}

type project struct {
	name, service, dir string
	files, envFiles    []string
}

func (e *Env) path(p string) string { return filepath.Join(e.Root, p) }

func checkPath(p string) error {
	if !filepath.IsAbs(p) || filepath.Clean(p) != p || strings.ContainsRune(p, 0) || len(p) > 1024 {
		return fmt.Errorf("%w: путь %q", ErrFileForbidden, p)
	}
	for _, f := range forbiddenPrefixes {
		if p == f || strings.HasPrefix(p, f+"/") {
			return fmt.Errorf("%w: %s", ErrFileForbidden, p)
		}
	}
	return nil
}

func splitList(v string) []string {
	var out []string
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// target — контейнер из параметров и проект compose по его меткам.
func (e *Env) target(ctx context.Context, p *agentv1.ContainerUpdateParams) (*Container, *project, error) {
	if e.Docker == nil {
		return nil, nil, ErrDocker
	}
	c, err := e.Docker.Inspect(ctx, p.GetContainer())
	if err != nil {
		return nil, nil, err
	}
	if c.Labels[labelTrassaApp] != "" {
		return nil, nil, fmt.Errorf("%w: обновление — через деплой приложения", ErrManaged)
	}
	pr := &project{name: c.Labels[LabelProject], service: c.Labels[LabelService], dir: c.Labels[LabelWorkingDir]}
	if pr.name == "" || pr.service == "" || pr.dir == "" || c.Labels[LabelConfigFiles] == "" {
		return nil, nil, fmt.Errorf("%w: у контейнера нет меток docker compose", ErrNotCompose)
	}
	if pr.name != p.GetProject() || pr.service != p.GetService() {
		return nil, nil, fmt.Errorf("%w: проект или сервис compose не те, что в инвентаре", ErrImageChanged)
	}
	if strings.Contains(c.Image, "@") {
		return nil, nil, fmt.Errorf("%w: %s", ErrPinned, c.Image)
	}
	if c.Image != p.GetCurrentImage() {
		return nil, nil, fmt.Errorf("%w: сейчас %s", ErrImageChanged, c.Image)
	}
	if err := checkPath(pr.dir); err != nil {
		return nil, nil, err
	}
	pr.files = splitList(c.Labels[LabelConfigFiles])
	pr.envFiles = splitList(c.Labels[LabelEnvFile])
	if len(pr.files) > maxConfigs || len(pr.envFiles) > maxConfigs {
		return nil, nil, fmt.Errorf("%w: слишком много файлов проекта", ErrNotEditable)
	}
	for _, f := range append(append([]string{}, pr.files...), pr.envFiles...) {
		if err := checkPath(f); err != nil {
			return nil, nil, err
		}
	}
	return c, pr, nil
}

func (e *Env) base(pr *project) []string {
	args := []string{"compose", "--project-name", pr.name, "--project-directory", e.path(pr.dir)}
	for _, f := range pr.files {
		args = append(args, "-f", e.path(f))
	}
	for _, f := range pr.envFiles {
		args = append(args, "--env-file", e.path(f))
	}
	return args
}

func (e *Env) compose(ctx context.Context, timeout time.Duration, pr *project, args ...string) ([]byte, []byte, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return e.Run(ctx, composeEnv, "docker", append(e.base(pr), args...)...)
}

// Предупреждение compose: `The "X" variable is not set` (в журнале logfmt кавычки экранированы: \"X\").
var reUnset = regexp.MustCompile(`The \\?"?([A-Za-z_][A-Za-z0-9_]*)\\?"? variable is not set`)

// config — разрешённая конфигурация проекта. Переменная без значения — отказ: при обычном запуске её, видимо,
// давала оболочка человека, и пересоздание сервиса без неё сломало бы его.
func (e *Env) config(ctx context.Context, pr *project) (map[string]any, error) {
	out, stderr, err := e.compose(ctx, time.Minute, pr, "config", "--format", "json")
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrConfig, err)
	}
	if m := reUnset.FindAllStringSubmatch(string(stderr), 5); len(m) > 0 {
		names := make([]string, 0, len(m))
		for _, x := range m {
			names = append(names, x[1])
		}
		return nil, fmt.Errorf("%w: переменные не заданы в .env проекта: %s", ErrConfig, strings.Join(names, ", "))
	}
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		return nil, fmt.Errorf("%w: вывод config: %v", ErrConfig, err)
	}
	return doc, nil
}

func serviceImage(doc map[string]any, svc string) string {
	services, _ := doc["services"].(map[string]any)
	s, _ := services[svc].(map[string]any)
	img, _ := s["image"].(string)
	return img
}

// sameExceptImage — конфигурации проекта равны, если у after образ сервиса вернуть на прежний.
func sameExceptImage(before, after map[string]any, svc, oldImage string) bool {
	services, _ := after["services"].(map[string]any)
	s, _ := services[svc].(map[string]any)
	if s == nil {
		return false
	}
	s["image"] = oldImage
	defer func() { s["image"] = serviceImage(after, svc) }()
	return reflect.DeepEqual(before, after)
}

func readFile(p string) ([]byte, os.FileInfo, error) {
	st, err := os.Lstat(p)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrFileForbidden, err)
	}
	if !st.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("%w: %s — не обычный файл", ErrFileForbidden, p)
	}
	if st.Size() > maxFile {
		return nil, nil, fmt.Errorf("%w: %s больше 1 МиБ", ErrNotEditable, p)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrFileForbidden, err)
	}
	return b, st, nil
}

// edit — какой файл и как меняется.
type edit struct {
	path    string
	content []byte
	mode    os.FileMode
	source  agentv1.ContainerUpdateSource
}

// plan — правка тега: в compose-файле (последний файл проекта, где у сервиса есть image — он и действует) или в
// переменной .env, из которой image берётся.
func (e *Env) plan(pr *project, current, newImage, newTag string) (*edit, error) {
	repo, curTag, _ := SplitImage(current)
	for i := len(pr.files) - 1; i >= 0; i-- {
		f := e.path(pr.files[i])
		content, st, err := readFile(f)
		if err != nil {
			return nil, err
		}
		span, err := FindImage(content, pr.service)
		if err != nil {
			return nil, err
		}
		if span == nil {
			continue
		}
		v, err := ParseVar(span.Value)
		if err != nil {
			return nil, err
		}
		if v == nil {
			if span.Value != current {
				return nil, notEditable("в %s у сервиса образ %s, а запущен %s", pr.files[i], span.Value, current)
			}
			return &edit{path: f, content: Replace(content, span, newImage), mode: st.Mode().Perm(),
				source: agentv1.ContainerUpdateSource_CONTAINER_UPDATE_SOURCE_COMPOSE_FILE}, nil
		}
		want, value := current, newImage
		if !v.Whole {
			if v.Repo != repo {
				return nil, notEditable("образ в файле %s, а запущен %s", v.Repo, repo)
			}
			want, value = curTag, newTag
		}
		envs := pr.envFiles
		if len(envs) == 0 {
			envs = []string{filepath.Join(pr.dir, ".env")}
		}
		if len(envs) != 1 {
			return nil, notEditable("у проекта несколько файлов переменных")
		}
		ep := e.path(envs[0])
		econtent, est, err := readFile(ep)
		if err != nil {
			return nil, notEditable("тег из переменной %s, файла %s нет", v.Name, envs[0])
		}
		es, err := FindEnv(econtent, v.Name)
		if err != nil {
			return nil, err
		}
		if es.Value != want {
			return nil, notEditable("%s в .env = %s, ожидалось %s", v.Name, es.Value, want)
		}
		return &edit{path: ep, content: Replace(econtent, es, value), mode: est.Mode().Perm(),
			source: agentv1.ContainerUpdateSource_CONTAINER_UPDATE_SOURCE_ENV_FILE}, nil
	}
	return nil, notEditable("образ сервиса %s не задан в compose-файлах проекта", pr.service)
}

// WriteFile — запись правки с прежними правами и владельцем (подменяется в тестах не root).
var WriteFile = writeKeepOwner

// wait — все контейнеры сервиса на образе image работают Stable подряд (и healthy, если есть проверка здоровья).
func (e *Env) wait(ctx context.Context, pr *project, image string, limit time.Duration) (string, string, error) {
	deadline := time.Now().Add(limit)
	var since time.Time
	state, health := "", ""
	ids := ""
	for {
		cs, err := e.Docker.Service(ctx, pr.name, pr.service)
		if err != nil {
			return state, health, err
		}
		ok := len(cs) > 0
		cur := ""
		for _, c := range cs {
			state, health = c.Status, c.Health
			cur += fmt.Sprintf("%s/%d,", c.ID, c.RestartCount)
			if c.Image != image || c.Status != "running" || c.Health != "" && c.Health != "healthy" {
				ok = false
			}
			if c.Health == "unhealthy" || c.Status == "exited" || c.Status == "dead" {
				return state, health, fmt.Errorf("%w: %s %s %s", ErrNotHealthy, c.Name, c.Status, c.Health)
			}
		}
		switch {
		case !ok:
			since = time.Time{}
		case since.IsZero() || cur != ids:
			since, ids = time.Now(), cur
		case time.Since(since) >= e.Stable:
			return state, health, nil
		}
		if time.Now().After(deadline) {
			return state, health, fmt.Errorf("%w: за %s не вышел в running%s", ErrNotHealthy, limit, map[bool]string{true: "/healthy"}[health != ""])
		}
		select {
		case <-ctx.Done():
			return state, health, ctx.Err()
		case <-time.After(e.Poll):
		}
	}
}

// Update — container.update целиком. Итог заполнен и при ошибке; res.RolledBack — прежний образ возвращён.
func (e *Env) Update(ctx context.Context, p *agentv1.ContainerUpdateParams, h Hooks) (*agentv1.ContainerUpdateResult, error) {
	log := h.Log
	if log == nil {
		log = func(string, ...any) {}
	}
	res := &agentv1.ContainerUpdateResult{PreviousImage: p.GetCurrentImage()}
	c, pr, err := e.target(ctx, p)
	if err != nil {
		return res, err
	}
	repo, curTag, ok := SplitImage(c.Image)
	if !ok {
		return res, fmt.Errorf("%w: образ %s без тега", ErrNotEditable, c.Image)
	}
	newImage := repo + ":" + p.GetTargetTag()
	res.NewImage = newImage
	log("Проект %s, сервис %s: %s → %s", pr.name, pr.service, c.Image, newImage)
	before, err := e.config(ctx, pr)
	if err != nil {
		return res, err
	}
	if got := serviceImage(before, pr.service); got != c.Image {
		return res, fmt.Errorf("%w: compose сейчас даёт образ %q, а запущен %s", ErrEditMismatch, got, c.Image)
	}
	var ed *edit
	if p.GetTargetTag() == curTag {
		res.Source = agentv1.ContainerUpdateSource_CONTAINER_UPDATE_SOURCE_PULL_ONLY
		log("Тег тот же: скачиваю его заново и пересоздаю сервис")
	} else {
		if ed, err = e.plan(pr, c.Image, newImage, p.GetTargetTag()); err != nil {
			return res, err
		}
		res.Source, res.File = ed.source, strings.TrimPrefix(ed.path, e.Root)
		if err := h.Backup([]string{ed.path}); err != nil {
			return res, err
		}
		log("Сохранена копия %s", res.File)
		if err := WriteFile(ed.path, ed.content, ed.mode); err != nil {
			return res, e.undoFile(h, log, fmt.Errorf("%w: запись %s: %v", ErrFileForbidden, res.File, err))
		}
		log("Записан новый тег в %s", res.File)
		after, err := e.config(ctx, pr)
		if err != nil {
			return res, e.undoFile(h, log, err)
		}
		if serviceImage(after, pr.service) != newImage || !sameExceptImage(before, after, pr.service, c.Image) {
			return res, e.undoFile(h, log, fmt.Errorf("%w: правка изменила не только образ сервиса", ErrEditMismatch))
		}
		log("Проверено: изменился только образ сервиса %s", pr.service)
	}
	if _, stderr, err := e.compose(ctx, e.PullTimeout, pr, "pull", "--quiet", pr.service); err != nil {
		err = fmt.Errorf("%w: %v %s", ErrPull, err, lastLine(stderr))
		if ed == nil {
			return res, err
		}
		return res, e.undoFile(h, log, err)
	}
	log("Образ %s скачан", newImage)
	if _, stderr, err := e.compose(ctx, e.UpTimeout, pr, "up", "-d", "--no-deps", "--no-build", pr.service); err != nil {
		return res, e.rollback(ctx, res, pr, c, ed != nil, h, log, fmt.Errorf("%w: up: %v %s", ErrNotHealthy, err, lastLine(stderr)), time.Duration(p.GetWaitSec())*time.Second)
	}
	log("Сервис %s пересоздан, жду работы %d с подряд", pr.service, int(e.Stable.Seconds()))
	state, health, err := e.wait(ctx, pr, newImage, time.Duration(p.GetWaitSec())*time.Second)
	res.State, res.Health = state, health
	if err != nil {
		return res, e.rollback(ctx, res, pr, c, ed != nil, h, log, err, time.Duration(p.GetWaitSec())*time.Second)
	}
	log("Сервис %s работает на %s", pr.service, newImage)
	return res, nil
}

func (e *Env) undoFile(h Hooks, log func(string, ...any), cause error) error {
	if rerr := h.Restore(); rerr != nil {
		return fmt.Errorf("%w: %v; возврат файла: %v", ErrRollbackFailed, cause, rerr)
	}
	log("Прежний файл возвращён")
	return cause
}

// rollback — прежний файл (или прежний образ под тем же тегом) и `up -d` того же сервиса.
func (e *Env) rollback(ctx context.Context, res *agentv1.ContainerUpdateResult, pr *project, c *Container, edited bool, h Hooks, log func(string, ...any), cause error, limit time.Duration) error {
	ctx = context.WithoutCancel(ctx)
	log("Не удалось: %v; возвращаю %s", cause, c.Image)
	if edited {
		if err := h.Restore(); err != nil {
			return fmt.Errorf("%w: %v; возврат файла: %v", ErrRollbackFailed, cause, err)
		}
	} else {
		repo, tag, _ := SplitImage(c.Image)
		if err := e.Docker.Tag(ctx, c.ImageID, repo, tag); err != nil {
			return fmt.Errorf("%w: %v; прежний образ: %v", ErrRollbackFailed, cause, err)
		}
	}
	if _, stderr, err := e.compose(ctx, e.UpTimeout, pr, "up", "-d", "--no-deps", "--no-build", pr.service); err != nil {
		return fmt.Errorf("%w: %v; up прежнего: %v %s", ErrRollbackFailed, cause, err, lastLine(stderr))
	}
	state, health, err := e.wait(ctx, pr, c.Image, limit)
	res.State, res.Health = state, health
	if err != nil {
		return fmt.Errorf("%w: %v; прежний образ не поднялся: %v", ErrRollbackFailed, cause, err)
	}
	res.RolledBack = true
	log("Прежний образ %s работает", c.Image)
	return cause
}

func lastLine(b []byte) string {
	b = bytes.TrimSpace(b)
	if i := bytes.LastIndexByte(b, '\n'); i >= 0 {
		b = b[i+1:]
	}
	if len(b) > 300 {
		b = b[:300]
	}
	return string(b)
}
