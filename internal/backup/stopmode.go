// SPDX-License-Identifier: AGPL-3.0-only

package backup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/fsutil"
)

// Режим STOP тома Docker (план E13, T6): работающие контейнеры с томом останавливаются на время копии и
// запускаются после неё при любом исходе. Список остановленных лежит на диске до запуска: если помощник упадёт
// посреди копии, при старте он поднимет их сам (RestartStopped).
const (
	CodeContainerNotRestarted = "BACKUP_CONTAINER_NOT_RESTARTED"
	// EventContainerNotRestarted — событие CRIT: контейнер не запустился после бэкапа (инцидент E09).
	EventContainerNotRestarted = "backup.container_not_restarted"
	stopTimeoutSec             = 30
	restartTries               = 3
	stoppedFile                = "stopped-containers.json"
)

// restartDelay — пауза между попытками запуска (переменная для тестов).
var restartDelay = 5 * time.Second

type stoppedRec struct {
	Volume     string   `json:"volume"`
	Containers []string `json:"containers"` // id
}

func (e *Env) stoppedPath() string { return filepath.Join(e.WorkDir, stoppedFile) }

func (e *Env) saveStopped(r *stoppedRec) error {
	if r == nil {
		err := os.Remove(e.stoppedPath())
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if err := os.MkdirAll(e.WorkDir, 0o700); err != nil {
		return err
	}
	raw, _ := json.Marshal(r)
	return fsutil.WriteFileAtomic(e.stoppedPath(), raw, 0o600, fsutil.Keep)
}

func (e *Env) dockerPost(ctx context.Context, path string) (int, error) {
	if e.Docker == nil {
		return 0, errors.New("docker не установлен")
	}
	resp, err := e.Docker.Do(ctx, http.MethodPost, path, nil, nil)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	if resp.StatusCode/100 != 2 && resp.StatusCode != http.StatusNotModified {
		return resp.StatusCode, fmt.Errorf("docker %s: HTTP %d: %s", path, resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return resp.StatusCode, nil
}

type volumeUser struct {
	ID    string   `json:"Id"`
	Names []string `json:"Names"`
}

func (c volumeUser) name() string {
	if len(c.Names) > 0 {
		return strings.TrimPrefix(c.Names[0], "/")
	}
	return c.ID
}

// volumeUsers — работающие контейнеры, к которым подключён том (фильтр volume Engine API).
func (e *Env) volumeUsers(ctx context.Context, volume string) ([]volumeUser, error) {
	f, _ := json.Marshal(map[string][]string{"volume": {volume}, "status": {"running"}})
	var cs []volumeUser
	if err := e.dockerJSON(ctx, "/containers/json?filters="+url.QueryEscape(string(f)), &cs); err != nil {
		return nil, err
	}
	sort.Slice(cs, func(i, j int) bool { return cs[i].ID < cs[j].ID })
	return cs, nil
}

// stopVolumeUsers — остановка перед копией. Возвращает функцию запуска: её обязательно вызвать (defer).
// Ошибка остановки — источник не копируется, уже остановленные поднимаются.
func (e *Env) stopVolumeUsers(ctx context.Context, volume string) ([]volumeUser, func() ([]string, []string), error) {
	users, err := e.volumeUsers(ctx, volume)
	if err != nil {
		return nil, nil, err
	}
	var stopped []volumeUser
	rec := &stoppedRec{Volume: volume}
	start := func() ([]string, []string) {
		bg := context.WithoutCancel(ctx)
		var ok, failed []string
		for _, c := range stopped {
			var err error
			for i := 0; i < restartTries; i++ {
				if i > 0 {
					time.Sleep(restartDelay)
				}
				if _, err = e.dockerPost(bg, "/containers/"+c.ID+"/start"); err == nil {
					break
				}
			}
			if err != nil {
				failed = append(failed, c.name())
				continue
			}
			ok = append(ok, c.name())
		}
		if len(failed) == 0 {
			_ = e.saveStopped(nil)
		}
		return ok, failed
	}
	for _, c := range users {
		// Список — до остановки: упади помощник между stop и записью, контейнер остался бы лежать.
		rec.Containers = append(rec.Containers, c.ID)
		if err := e.saveStopped(rec); err != nil {
			start()
			return nil, nil, fmt.Errorf("список остановленных: %w", err)
		}
		if _, err := e.dockerPost(ctx, fmt.Sprintf("/containers/%s/stop?t=%d", c.ID, stopTimeoutSec)); err != nil {
			start()
			return nil, nil, fmt.Errorf("остановка %s: %w", c.name(), err)
		}
		stopped = append(stopped, c)
	}
	return stopped, start, nil
}

// RestartStopped — старт помощника: контейнеры, оставшиеся остановленными прерванным бэкапом, запускаются.
func (e *Env) RestartStopped(ctx context.Context) error {
	raw, err := fsutil.ReadLimited(e.stoppedPath(), 1<<20)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var rec stoppedRec
	if err := json.Unmarshal(raw, &rec); err != nil {
		return fmt.Errorf("%s повреждён: %w", stoppedFile, err)
	}
	var errs []error
	for _, id := range rec.Containers {
		if _, err := e.dockerPost(ctx, "/containers/"+url.PathEscape(id)+"/start"); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) == 0 {
		return e.saveStopped(nil)
	}
	return errors.Join(errs...)
}

func notRestartedEvent(volume string, names []string, now time.Time) *agentv1.Event {
	return &agentv1.Event{Kind: EventContainerNotRestarted, Severity: agentv1.EventSeverity_EVENT_SEVERITY_CRIT, AtMs: now.UnixMilli(),
		Message:    "контейнеры не запустились после бэкапа тома " + volume,
		Attributes: map[string]string{"subject": strings.Join(names, ","), "volume": volume, "state": "firing"}}
}
