// SPDX-License-Identifier: AGPL-3.0-only

package imageupdate

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/NogMeer/trassa-agent/internal/dockerapi"
)

// EngineDocker — Docker поверх Engine API (сокет root помощника).
type EngineDocker struct{ Client *dockerapi.Client }

type inspect struct {
	ID    string `json:"Id"`
	Name  string `json:"Name"`
	Image string `json:"Image"`
	State struct {
		Status string `json:"Status"`
		Health *struct {
			Status string `json:"Status"`
		} `json:"Health"`
	} `json:"State"`
	RestartCount int `json:"RestartCount"`
	Config       struct {
		Image  string            `json:"Image"`
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
}

func (d *EngineDocker) get(ctx context.Context, p string, out any) (int, error) {
	if d.Client == nil {
		return 0, ErrDocker
	}
	resp, err := d.Client.Do(ctx, http.MethodGet, p, nil, nil)
	if err != nil {
		return 0, fmt.Errorf("%w: %v", ErrDocker, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return resp.StatusCode, fmt.Errorf("%w: GET %s: HTTP %d: %s", ErrDocker, p, resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return resp.StatusCode, json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(out)
}

func (i *inspect) container() *Container {
	c := &Container{ID: i.ID, Name: strings.TrimPrefix(i.Name, "/"), ImageID: i.Image, Image: i.Config.Image,
		Labels: i.Config.Labels, Status: i.State.Status, RestartCount: i.RestartCount}
	if i.State.Health != nil {
		c.Health = i.State.Health.Status
	}
	return c
}

// Inspect — контейнер по точному имени (Engine API находит и по префиксу id — такое не принимается).
func (d *EngineDocker) Inspect(ctx context.Context, name string) (*Container, error) {
	var i inspect
	code, err := d.get(ctx, "/containers/"+url.PathEscape(name)+"/json", &i)
	if code == http.StatusNotFound || err == nil && i.Name != "/"+name {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	if err != nil {
		return nil, err
	}
	return i.container(), nil
}

// Service — контейнеры сервиса по меткам compose, с состоянием из inspect.
func (d *EngineDocker) Service(ctx context.Context, project, service string) ([]Container, error) {
	f, _ := json.Marshal(map[string][]string{"label": {LabelProject + "=" + project, LabelService + "=" + service}})
	var list []struct {
		ID     string            `json:"Id"`
		Labels map[string]string `json:"Labels"`
	}
	if _, err := d.get(ctx, "/containers/json?all=1&filters="+url.QueryEscape(string(f)), &list); err != nil {
		return nil, err
	}
	out := make([]Container, 0, len(list))
	for _, x := range list {
		if strings.EqualFold(x.Labels[LabelOneOff], "true") {
			continue
		}
		var i inspect
		if _, err := d.get(ctx, "/containers/"+url.PathEscape(x.ID)+"/json", &i); err != nil {
			return nil, err
		}
		out = append(out, *i.container())
	}
	return out, nil
}

// Tag — POST /images/{id}/tag?repo=&tag=.
func (d *EngineDocker) Tag(ctx context.Context, id, repo, tag string) error {
	if d.Client == nil {
		return ErrDocker
	}
	q := url.Values{"repo": {repo}, "tag": {tag}}
	resp, err := d.Client.Do(ctx, http.MethodPost, "/images/"+url.PathEscape(id)+"/tag?"+q.Encode(), nil, nil)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDocker, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("%w: tag: HTTP %d", ErrDocker, resp.StatusCode)
	}
	return nil
}
