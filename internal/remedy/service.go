// SPDX-License-Identifier: AGPL-3.0-only

package remedy

import (
	"encoding/binary"
	"errors"
	"io"

	"context"
	"fmt"
	"github.com/NogMeer/trassa-agent/internal/redact"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
)

// Метки и имена Trassa: такие контейнеры service.restart не трогает (решение E18 п. 2).
const (
	labelApp       = "trassa.app_id"
	labelRole      = "trassa.role"
	builderPrefix  = "buildx_buildkit_trassa-"
	unitProperties = "LoadState,ActiveState,SubState,MainPID,ActiveEnterTimestampMonotonic,NRestarts"
)

// unitState — свойства службы из systemctl show.
type unitState struct {
	load, active, sub, pid, since string
	restarts                      uint32
}

func (e *Env) unit(ctx context.Context, unit string) (unitState, error) {
	out, err := e.Run(ctx, "systemctl", "show", "-p", unitProperties, "--", unit)
	if err != nil {
		return unitState{}, fmt.Errorf("systemctl show %s: %v", unit, err)
	}
	var s unitState
	for _, l := range strings.Split(string(out), "\n") {
		k, v, _ := strings.Cut(strings.TrimSpace(l), "=")
		switch k {
		case "LoadState":
			s.load = v
		case "ActiveState":
			s.active = v
		case "SubState":
			s.sub = v
		case "MainPID":
			s.pid = v
		case "ActiveEnterTimestampMonotonic":
			s.since = v
		case "NRestarts":
			n, _ := strconv.ParseUint(v, 10, 32)
			s.restarts = uint32(n)
		}
	}
	return s, nil
}

// containerState — то, что сравнивается 60 секунд.
type containerState struct {
	ID    string `json:"Id"`
	Name  string `json:"Name"`
	State struct {
		Status    string `json:"Status"`
		StartedAt string `json:"StartedAt"`
	} `json:"State"`
	RestartCount uint32 `json:"RestartCount"`
	Config       struct {
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
}

func (e *Env) container(ctx context.Context, name string) (*containerState, error) {
	var c containerState
	code, err := e.docker(ctx, http.MethodGet, "/containers/"+url.PathEscape(name)+"/json", &c)
	if code == http.StatusNotFound {
		return nil, fmt.Errorf("%w: контейнер %s", ErrNotFound, name)
	}
	if err != nil {
		return nil, err
	}
	// Engine API находит контейнер и по префиксу id: цель — только точное имя.
	if c.Name != "/"+name {
		return nil, fmt.Errorf("%w: контейнер %s", ErrNotFound, name)
	}
	return &c, nil
}

// Service — service.restart (start=false) и service.start: команда, затем «работает Stable подряд тем же
// процессом». Активная служба при start не перезапускается — только проверяется.
func (e *Env) Service(ctx context.Context, p *agentv1.ServiceRestartParams, start bool) (*agentv1.ServiceRestartResult, error) {
	var res *agentv1.ServiceRestartResult
	var err error
	var id string
	if p.GetKind() == agentv1.ServiceTargetKind_SERVICE_TARGET_KIND_CONTAINER {
		res, id, err = e.containerService(ctx, p.GetContainer(), start)
	} else {
		res, err = e.unitService(ctx, p.GetUnit(), start)
	}
	// Провал команды или проверки — хвост журнала цели для отчёта (секреты вычищены).
	if errors.Is(err, ErrNotStable) || errors.Is(err, ErrRestartFailed) {
		if res == nil {
			res = &agentv1.ServiceRestartResult{}
		}
		res.LogTail = e.logTail(context.WithoutCancel(ctx), p, id)
	}
	return res, err
}

// LogTailLines — сколько строк журнала цели уходит в итог при провале.
const LogTailLines = 20

func (e *Env) logTail(ctx context.Context, p *agentv1.ServiceRestartParams, id string) []string {
	var raw []byte
	if p.GetKind() == agentv1.ServiceTargetKind_SERVICE_TARGET_KIND_CONTAINER {
		if id == "" || e.Docker == nil {
			return nil
		}
		resp, err := e.Docker.Do(ctx, http.MethodGet, "/containers/"+id+"/logs?stdout=1&stderr=1&tail="+strconv.Itoa(LogTailLines), nil, nil)
		if err != nil {
			return nil
		}
		defer resp.Body.Close()
		raw, _ = io.ReadAll(io.LimitReader(resp.Body, 256<<10))
		raw = demux(raw)
	} else {
		out, err := e.Run(ctx, "journalctl", "-u", p.GetUnit(), "-n", strconv.Itoa(LogTailLines), "--no-pager", "-o", "cat")
		if err != nil {
			return nil
		}
		raw = out
	}
	var lines []string
	for _, l := range strings.Split(strings.TrimRight(string(raw), "\n"), "\n") {
		l = strings.ToValidUTF8(redact.Text(strings.TrimRight(l, "\r")), "")
		if len(l) > 500 {
			l = l[:500]
		}
		lines = append(lines, l)
	}
	if len(lines) > LogTailLines {
		lines = lines[len(lines)-LogTailLines:]
	}
	return lines
}

// demux — поток журнала Docker без TTY: кадры с 8-байтовым заголовком; с TTY — как есть.
func demux(b []byte) []byte {
	if len(b) < 8 || b[0] > 2 || b[1] != 0 || b[2] != 0 || b[3] != 0 {
		return b
	}
	var out []byte
	for len(b) >= 8 {
		n := int(binary.BigEndian.Uint32(b[4:8]))
		if n > len(b)-8 {
			n = len(b) - 8
		}
		out, b = append(out, b[8:8+n]...), b[8+n:]
	}
	return out
}

func (e *Env) unitService(ctx context.Context, unit string, start bool) (*agentv1.ServiceRestartResult, error) {
	s, err := e.unit(ctx, unit)
	if err != nil {
		return nil, err
	}
	if s.load == "" || s.load == "not-found" {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, unit)
	}
	if !(start && s.active == "active") {
		verb := "restart"
		if start {
			verb = "start"
		}
		if out, err := e.Run(ctx, "systemctl", verb, "--", unit); err != nil {
			return nil, fmt.Errorf("%w: systemctl %s %s: %v %s", ErrRestartFailed, verb, unit, err, tail(out))
		}
	}
	stable, poll, settle := e.durations()
	var first unitState
	var since time.Time
	deadline := e.now().Add(settle)
	for {
		cur, err := e.unit(ctx, unit)
		if err != nil {
			return nil, err
		}
		switch {
		case cur.active != "active":
			if !since.IsZero() || e.now().After(deadline) {
				return &agentv1.ServiceRestartResult{State: cur.active + "/" + cur.sub, Restarts: cur.restarts},
					fmt.Errorf("%w: %s %s/%s", ErrNotStable, unit, cur.active, cur.sub)
			}
		case since.IsZero():
			first, since = cur, e.now()
		case cur.pid != first.pid || cur.since != first.since:
			return &agentv1.ServiceRestartResult{State: cur.active + "/" + cur.sub, Restarts: cur.restarts},
				fmt.Errorf("%w: %s перезапустилась за время проверки", ErrNotStable, unit)
		case e.now().Sub(since) >= stable:
			return &agentv1.ServiceRestartResult{Active: true, ActiveSinceMs: since.UnixMilli(), Restarts: cur.restarts,
				State: cur.active + "/" + cur.sub}, nil
		}
		if err := e.sleep(ctx, poll); err != nil {
			return nil, err
		}
	}
}

// managed — контейнер Trassa: приложения (deploy.control) и инфраструктура (сборщик, одноразовые).
func managed(c *containerState) bool {
	l := c.Config.Labels
	return l[labelApp] != "" || l[labelRole] != "" || strings.HasPrefix(strings.TrimPrefix(c.Name, "/"), builderPrefix)
}

func (e *Env) containerService(ctx context.Context, name string, start bool) (*agentv1.ServiceRestartResult, string, error) {
	c, err := e.container(ctx, name)
	if err != nil {
		return nil, "", err
	}
	if managed(c) {
		return nil, "", fmt.Errorf("%w: %s — контейнер Trassa (приложение — deploy.control)", ErrManaged, name)
	}
	if !(start && c.State.Status == "running") {
		path := "/containers/" + c.ID + "/restart?t=10"
		if start {
			path = "/containers/" + c.ID + "/start"
		}
		if _, err := e.docker(ctx, http.MethodPost, path, nil); err != nil {
			return nil, c.ID, fmt.Errorf("%w: %v", ErrRestartFailed, err)
		}
	}
	stable, poll, settle := e.durations()
	var first *containerState
	var since time.Time
	deadline := e.now().Add(settle)
	for {
		cur, err := e.container(ctx, name)
		if err != nil {
			return nil, c.ID, err
		}
		res := &agentv1.ServiceRestartResult{State: cur.State.Status, Restarts: cur.RestartCount}
		switch {
		case cur.ID != c.ID:
			return res, c.ID, fmt.Errorf("%w: контейнер %s пересоздан за время проверки", ErrNotStable, name)
		case cur.State.Status != "running":
			if first != nil || e.now().After(deadline) {
				return res, c.ID, fmt.Errorf("%w: %s %s", ErrNotStable, name, cur.State.Status)
			}
		case first == nil:
			first, since = cur, e.now()
		case cur.State.StartedAt != first.State.StartedAt || cur.RestartCount != first.RestartCount:
			return res, c.ID, fmt.Errorf("%w: %s перезапускался за время проверки", ErrNotStable, name)
		case e.now().Sub(since) >= stable:
			res.Active, res.ActiveSinceMs = true, since.UnixMilli()
			return res, c.ID, nil
		}
		if err := e.sleep(ctx, poll); err != nil {
			return nil, c.ID, err
		}
	}
}

// ServiceState — состояние цели сейчас (предпросмотр): без действий.
func (e *Env) ServiceState(ctx context.Context, p *agentv1.ServiceRestartParams) (*agentv1.ServiceRestartResult, error) {
	if p.GetKind() == agentv1.ServiceTargetKind_SERVICE_TARGET_KIND_CONTAINER {
		c, err := e.container(ctx, p.GetContainer())
		if err != nil {
			return nil, err
		}
		if managed(c) {
			return nil, fmt.Errorf("%w: %s", ErrManaged, p.GetContainer())
		}
		return &agentv1.ServiceRestartResult{Active: c.State.Status == "running", State: c.State.Status, Restarts: c.RestartCount}, nil
	}
	s, err := e.unit(ctx, p.GetUnit())
	if err != nil {
		return nil, err
	}
	if s.load == "" || s.load == "not-found" {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, p.GetUnit())
	}
	return &agentv1.ServiceRestartResult{Active: s.active == "active", State: s.active + "/" + s.sub, Restarts: s.restarts}, nil
}
