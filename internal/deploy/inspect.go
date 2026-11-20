// SPDX-License-Identifier: AGPL-3.0-only

package deploy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
)

// Метки контейнеров Trassa.
const (
	LabelApp     = "trassa.app_id"
	LabelRelease = "trassa.release_id"
	LabelConfig  = "trassa.config_hash"
	LabelService = "trassa.service"
)

type dockerContainer struct {
	ID      string            `json:"Id"`
	Names   []string          `json:"Names"`
	Image   string            `json:"Image"`
	State   string            `json:"State"`
	Status  string            `json:"Status"`
	Labels  map[string]string `json:"Labels"`
	Created int64             `json:"Created"`
	Ports   []struct {
		IP         string `json:"IP"`
		PublicPort uint16 `json:"PublicPort"`
	} `json:"Ports"`
}

func (e *Env) dockerJSON(ctx context.Context, method, p string, body io.Reader, out any) error {
	if e.Docker == nil {
		return ErrDockerNotReady
	}
	resp, err := e.Docker.Do(ctx, method, p, body, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("docker %s %s: HTTP %d: %s", method, p, resp.StatusCode, firstLine(b))
	}
	if out == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<20))
		return nil
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(out)
}

// appContainers — контейнеры Trassa (метка trassa.app_id), приложения app или все.
func (e *Env) appContainers(ctx context.Context, app string) ([]dockerContainer, error) {
	label := LabelApp
	if app != "" {
		label += "=" + app
	}
	f, _ := json.Marshal(map[string][]string{"label": {label}})
	var cs []dockerContainer
	if err := e.dockerJSON(ctx, http.MethodGet, "/containers/json?all=1&filters="+url.QueryEscape(string(f)), nil, &cs); err != nil {
		return nil, err
	}
	return cs, nil
}

// Inspect — deploy.inspect: приложения Trassa на сервере, их контейнеры и версии программ.
func (e *Env) Inspect(ctx context.Context, app string) (*agentv1.DeployInspectResult, error) {
	cs, err := e.appContainers(ctx, app)
	if err != nil {
		return nil, err
	}
	res := &agentv1.DeployInspectResult{}
	if v, _, err := e.dockerVersion(ctx); err == nil {
		res.DockerVersion = v
	}
	if st, err := e.LoadProxy(); err == nil {
		res.ProxyVersion = st.Version
		res.Certs = e.certs(st)
	}
	byApp := map[string]*agentv1.AppRuntime{}
	for _, c := range cs {
		a := c.Labels[LabelApp]
		rt := byApp[a]
		if rt == nil {
			rt = &agentv1.AppRuntime{AppId: a}
			byApp[a] = rt
		}
		ac := &agentv1.AppContainer{Id: c.ID, State: c.State, Service: c.Labels[LabelService], StartedAtMs: time.Unix(c.Created, 0).UnixMilli()}
		if len(c.Names) > 0 {
			ac.Name = strings.TrimPrefix(c.Names[0], "/")
		}
		for _, p := range c.Ports {
			if p.IP == "127.0.0.1" && p.PublicPort > 0 {
				ac.HostPort = uint32(p.PublicPort)
			}
		}
		if c.State == "running" {
			rt.ReleaseId, rt.ImageRef = c.Labels[LabelRelease], c.Image
		}
		rt.Containers = append(rt.Containers, ac)
	}
	for _, rt := range byApp {
		res.Apps = append(res.Apps, rt)
	}
	sort.Slice(res.Apps, func(i, j int) bool { return res.Apps[i].AppId < res.Apps[j].AppId })
	return res, nil
}
