// SPDX-License-Identifier: AGPL-3.0-only

package deploy

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/fsutil"
)

// appState — /var/lib/trassa/apps/<app_id>/state.json: образы релизов Trassa (решение E17 п. 6), без секретов.
type appState struct {
	Kind   string   `json:"kind"`
	Images []string `json:"images"`
}

func (e *Env) appDir(app string) string { return filepath.Join(e.AppsDir, app) }

// ensureAppDir — каталог приложения (root, 0700) без перехода по ссылкам.
func (e *Env) ensureAppDir(app string, sub ...string) (string, error) {
	p := filepath.Join(append([]string{e.appDir(app)}, sub...)...)
	fd, err := fsutil.MkdirAllNoFollow(p, 0o700)
	if err != nil {
		return "", err
	}
	_ = closeFD(fd)
	return p, nil
}

func (e *Env) loadApp(app string) (*appState, error) {
	raw, err := fsutil.ReadLimited(filepath.Join(e.appDir(app), "state.json"), 1<<20)
	if errors.Is(err, os.ErrNotExist) {
		return &appState{}, nil
	}
	if err != nil {
		return nil, err
	}
	var st appState
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, fmt.Errorf("состояние приложения повреждено: %w", err)
	}
	return &st, nil
}

func (e *Env) saveApp(app string, st *appState) error {
	dir, err := e.ensureAppDir(app)
	if err != nil {
		return err
	}
	raw, _ := json.Marshal(st)
	return fsutil.WriteAtomicNoFollow(filepath.Join(dir, "state.json"), 0o600, fsutil.Keep, func(w io.Writer) error {
		_, err := w.Write(raw)
		return err
	})
}

// recordImages — образы релиза в списке приложения (для deploy.images.prune).
func (e *Env) recordImages(app, kind string, images ...string) error {
	st, err := e.loadApp(app)
	if err != nil {
		return err
	}
	st.Kind = kind
	for _, img := range images {
		found := false
		for _, have := range st.Images {
			found = found || have == img
		}
		if !found {
			st.Images = append(st.Images, img)
		}
	}
	return e.saveApp(app, st)
}

// readFrame — кадр мультиплексированного потока Docker (журнал без TTY): 8 байт заголовка и данные.
func readFrame(r io.Reader) (byte, []byte, error) {
	var hdr [8]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(hdr[4:])
	if n > 1<<20 {
		return 0, nil, errors.New("кадр журнала больше 1 МиБ")
	}
	b := make([]byte, n)
	_, err := io.ReadFull(r, b)
	return hdr[0], b, err
}

// RunEnv — программа с окружением env (только оно); вывод до 4 МиБ, ошибка с последней строкой stderr.
func RunEnv(ctx context.Context, env []string, name string, args ...string) ([]byte, error) {
	bin := name
	if !filepath.IsAbs(name) {
		p, err := lookPath(name)
		if err != nil {
			return nil, err
		}
		bin = p
	}
	c := exec.CommandContext(ctx, bin, args...)
	c.Env, c.Dir = env, "/"
	c.WaitDelay = 10 * time.Second
	var out, stderr bytes.Buffer
	c.Stdout, c.Stderr = &capped{b: &out, n: 4 << 20}, &capped{b: &stderr, n: 64 << 10}
	if err := c.Run(); err != nil {
		return out.Bytes(), fmt.Errorf("%s: %v: %s", name, err, lastLine(stderr.Bytes()))
	}
	return out.Bytes(), nil
}

var systemPath = []string{"/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"}

func lookPath(name string) (string, error) {
	for _, d := range systemPath {
		p := filepath.Join(d, name)
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() && st.Mode().Perm()&0o111 != 0 {
			return p, nil
		}
	}
	return "", fmt.Errorf("%s: не найден", name)
}

type capped struct {
	b *bytes.Buffer
	n int
}

func (c *capped) Write(p []byte) (int, error) {
	if room := c.n - c.b.Len(); room > 0 {
		if len(p) > room {
			c.b.Write(p[:room])
		} else {
			c.b.Write(p)
		}
	}
	return len(p), nil
}

func lastLine(b []byte) string {
	b = bytes.TrimRight(b, "\n")
	if i := bytes.LastIndexByte(b, '\n'); i >= 0 {
		b = b[i+1:]
	}
	if len(b) > 300 {
		b = b[:300]
	}
	return string(b)
}

// Control — deploy.control: перезапуск, остановка или запуск контейнеров приложения; итог — Inspect.
func (e *Env) Control(ctx context.Context, p *agentv1.DeployControlParams) (*agentv1.DeployInspectResult, error) {
	cs, err := e.appContainers(ctx, p.GetAppId())
	if err != nil {
		return nil, err
	}
	if len(cs) == 0 {
		return nil, ErrAppMissing
	}
	var verb string
	switch p.GetAction() {
	case agentv1.ControlAction_CONTROL_ACTION_RESTART:
		verb = "restart?t=10"
	case agentv1.ControlAction_CONTROL_ACTION_STOP:
		verb = "stop?t=10"
	case agentv1.ControlAction_CONTROL_ACTION_START:
		verb = "start"
	default:
		return nil, errors.New("action")
	}
	for _, c := range cs {
		if c.Labels["trassa.role"] != "" {
			continue
		}
		err := e.dockerJSON(ctx, http.MethodPost, "/containers/"+c.ID+"/"+verb, nil, nil)
		if err != nil && !strings.Contains(err.Error(), "HTTP 304") {
			return nil, err
		}
	}
	return e.Inspect(ctx, p.GetAppId())
}

type imageInfo struct {
	ID   string `json:"Id"`
	Size int64  `json:"Size"`
}

func (e *Env) imageInspect(ctx context.Context, ref string) (*imageInfo, error) {
	var ii imageInfo
	if err := e.dockerJSON(ctx, http.MethodGet, "/images/"+ref+"/json", nil, &ii); err != nil {
		return nil, err
	}
	return &ii, nil
}

// inUse — образы (по ссылке и id) контейнеров на сервере.
func (e *Env) inUse(ctx context.Context) (map[string]bool, error) {
	var cs []struct {
		Image   string `json:"Image"`
		ImageID string `json:"ImageID"`
	}
	if err := e.dockerJSON(ctx, http.MethodGet, "/containers/json?all=1", nil, &cs); err != nil {
		return nil, err
	}
	used := map[string]bool{}
	for _, c := range cs {
		used[c.Image], used[c.ImageID] = true, true
	}
	return used, nil
}

// pruneImages — DELETE /images/{ref} для образов приложения вне keep и не занятых контейнерами (решение E17 п. 6).
func (e *Env) pruneImages(ctx context.Context, app string, keep []string) ([]string, uint64, error) {
	st, err := e.loadApp(app)
	if err != nil {
		return nil, 0, err
	}
	used, err := e.inUse(ctx)
	if err != nil {
		return nil, 0, err
	}
	keepSet := map[string]bool{}
	for _, k := range keep {
		keepSet[k] = true
	}
	var removed, left []string
	var freed uint64
	for _, img := range st.Images {
		if keepSet[img] || used[img] {
			left = append(left, img)
			continue
		}
		ii, err := e.imageInspect(ctx, img)
		if err != nil {
			if strings.Contains(err.Error(), "HTTP 404") {
				continue
			}
			return removed, freed, err
		}
		if used[ii.ID] {
			left = append(left, img)
			continue
		}
		if err := e.dockerJSON(ctx, http.MethodDelete, "/images/"+img, nil, nil); err != nil {
			if strings.Contains(err.Error(), "HTTP 409") {
				left = append(left, img)
				continue
			}
			return removed, freed, err
		}
		removed, freed = append(removed, img), freed+uint64(ii.Size)
	}
	st.Images = left
	if err := e.saveApp(app, st); err != nil {
		return removed, freed, err
	}
	sort.Strings(removed)
	return removed, freed, nil
}

// PruneImages — deploy.images.prune.
func (e *Env) PruneImages(ctx context.Context, p *agentv1.DeployImagesPruneParams) (*agentv1.DeployImagesPruneResult, error) {
	removed, freed, err := e.pruneImages(ctx, p.GetAppId(), p.GetKeepImages())
	if err != nil {
		return nil, err
	}
	return &agentv1.DeployImagesPruneResult{Removed: removed, FreedBytes: freed}, nil
}

// dropRoutes — маршруты приложения из прокси (нет прокси — нечего убирать).
func (e *Env) dropRoutes(ctx context.Context, app string) error {
	_, _, _, err := e.setAppRoutes(ctx, app, nil)
	if errors.Is(err, ErrProxyMissing) {
		return nil
	}
	return err
}

// Remove — deploy.remove: маршрут, контейнеры, сеть, образы приложения; тома — только с remove_data.
func (e *Env) Remove(ctx context.Context, p *agentv1.DeployRemoveParams) (*agentv1.DeployRemoveResult, error) {
	app := p.GetAppId()
	res := &agentv1.DeployRemoveResult{}
	if err := e.dropRoutes(ctx, app); err != nil {
		return nil, err
	}
	if err := e.composeDown(ctx, app); err != nil {
		return nil, err
	}
	cs, err := e.appContainers(ctx, app)
	if err != nil {
		return nil, err
	}
	for _, c := range cs {
		if err := e.remove(ctx, c.ID); err != nil {
			return res, err
		}
		res.RemovedContainers++
	}
	f, _ := json.Marshal(map[string][]string{"label": {LabelApp + "=" + app}})
	var nets []struct {
		ID string `json:"Id"`
	}
	if err := e.dockerJSON(ctx, http.MethodGet, "/networks?filters="+url.QueryEscape(string(f)), nil, &nets); err != nil {
		return res, err
	}
	for _, n := range nets {
		if err := e.dockerJSON(ctx, http.MethodDelete, "/networks/"+n.ID, nil, nil); err != nil && !strings.Contains(err.Error(), "HTTP 404") {
			return res, err
		}
	}
	removed, freed, err := e.pruneImages(ctx, app, nil)
	res.RemovedImages, res.FreedBytes = uint32(len(removed)), freed
	if err != nil {
		return res, err
	}
	if p.GetRemoveData() {
		var vols struct {
			Volumes []struct {
				Name string `json:"Name"`
			} `json:"Volumes"`
		}
		if err := e.dockerJSON(ctx, http.MethodGet, "/volumes?filters="+url.QueryEscape(string(f)), nil, &vols); err != nil {
			return res, err
		}
		for _, v := range vols.Volumes {
			if err := e.dockerJSON(ctx, http.MethodDelete, "/volumes/"+url.PathEscape(v.Name), nil, nil); err != nil &&
				!strings.Contains(err.Error(), "HTTP 404") {
				return res, err
			}
			res.RemovedVolumes++
		}
	}
	// Каталог приложения (compose.json, state.json) — без перехода по ссылкам.
	fd, err := fsutil.OpenDirNoFollow(e.AppsDir)
	if err == nil {
		err = fsutil.RemoveAllAt(fd, app)
		_ = closeFD(fd)
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return res, err
	}
	return res, nil
}

// Rollback — deploy.rollback: релиз release_id с образом (или документом compose) целевого релиза.
func (e *Env) Rollback(ctx context.Context, j ReleaseJob) (*agentv1.DeployReleaseResult, bool, error) {
	return e.Release(ctx, j)
}

// ProxyHosts — имена маршрутов прокси Trassa (их сертификаты выпускает Caddy; cert.renew E18 их не трогает).
func (e *Env) ProxyHosts() []string {
	st, err := e.LoadProxy()
	if err != nil {
		return nil
	}
	var out []string
	for _, recs := range st.Apps {
		for _, r := range recs {
			out = append(out, r.Hosts...)
		}
	}
	return out
}

// ReleaseImages — образы релизов всех приложений Trassa (точки отката; disk.cleanup E18 их не удаляет).
func (e *Env) ReleaseImages() map[string]bool {
	out := map[string]bool{}
	ents, err := os.ReadDir(e.AppsDir)
	if err != nil {
		return out
	}
	for _, d := range ents {
		if !d.IsDir() {
			continue
		}
		st, err := e.loadApp(d.Name())
		if err != nil {
			continue
		}
		for _, img := range st.Images {
			out[img] = true
		}
	}
	return out
}
