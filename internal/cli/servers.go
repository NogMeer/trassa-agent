// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"text/tabwriter"
	"time"
)

// myServer — GET /v1/workspaces/:ws/access/my-servers (AccessMyServerDto).
type myServer struct {
	ServerID string  `json:"serverId"`
	Name     string  `json:"name"`
	Online   bool    `json:"online"`
	Logins   []login `json:"logins"`
}

type login struct {
	GrantID   string     `json:"grantId"`
	UnixUser  string     `json:"unixUser"`
	Sudo      bool       `json:"sudo"`
	ExpiresAt *time.Time `json:"expiresAt"`
	Ready     bool       `json:"ready"`
}

func wsPath(ws, rest string) string {
	return "/v1/workspaces/" + url.PathEscape(ws) + "/access/" + rest
}

func (a *App) myServers(ctx context.Context, c *client, ws string) ([]myServer, error) {
	var out struct {
		Items []myServer `json:"items"`
	}
	if err := c.do(ctx, http.MethodGet, wsPath(ws, "my-servers"), nil, &out); err != nil {
		return nil, err
	}
	return out.Items, nil
}

// Servers — trassa servers: серверы, где у вас есть доступ, и логины на них.
func (a *App) Servers(ctx context.Context, wsFlag string) error {
	c, cfg, err := a.session()
	if err != nil {
		return err
	}
	ws, err := a.workspaceID(ctx, c, cfg, wsFlag)
	if err != nil {
		return err
	}
	items, err := a.myServers(ctx, c, ws)
	if err != nil {
		return err
	}
	if len(items) == 0 {
		a.printf("servers.empty")
		return nil
	}
	tw := tabwriter.NewWriter(a.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprint(tw, a.t("servers.head"))
	for _, s := range items {
		status := a.t("servers.offline")
		if s.Online {
			status = a.t("servers.online")
		}
		var ls []string
		for _, l := range s.Logins {
			v := clean(l.UnixUser)
			if l.Sudo {
				v += " (sudo)"
			}
			if !l.Ready {
				v += ", " + a.t("servers.pending")
			}
			if l.ExpiresAt != nil {
				v += ", " + a.t("servers.until", l.ExpiresAt.Local().Format("2006-01-02 15:04"))
			}
			ls = append(ls, v)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", clean(s.Name), status, strings.Join(ls, "; "), clean(s.ServerID))
	}
	return tw.Flush()
}

// resolveServer — сервер по id, точному имени или имени без учёта регистра; несколько совпадений — ошибка.
func (a *App) resolveServer(items []myServer, want string) (myServer, error) {
	for _, s := range items {
		if strings.EqualFold(s.ServerID, want) {
			return s, nil
		}
	}
	var exact, fold []myServer
	for _, s := range items {
		switch {
		case s.Name == want:
			exact = append(exact, s)
		case strings.EqualFold(s.Name, want):
			fold = append(fold, s)
		}
	}
	match := exact
	if len(match) == 0 {
		match = fold
	}
	switch len(match) {
	case 0:
		return myServer{}, userError{a.t("err.no_grant")}
	case 1:
		return match[0], nil
	}
	ids := make([]string, 0, len(match))
	for _, s := range match {
		ids = append(ids, clean(s.ServerID))
	}
	return myServer{}, userError{a.t("err.ambiguous", clean(want), strings.Join(ids, ", "))}
}

// pickLogin — логин на сервере: заданный -l или единственный. Без -l при нескольких — выбор за человеком, чтобы
// не войти молча под логин с правами администратора.
func (a *App) pickLogin(s myServer, want string) (string, error) {
	names := make([]string, 0, len(s.Logins))
	for _, l := range s.Logins {
		names = append(names, clean(l.UnixUser))
	}
	if want != "" {
		for _, l := range s.Logins {
			if l.UnixUser == want {
				return want, nil
			}
		}
		return "", userError{a.t("err.login_unknown", clean(want), strings.Join(names, ", "))}
	}
	switch len(s.Logins) {
	case 0:
		return "", userError{a.t("err.no_grant")}
	case 1:
		return s.Logins[0].UnixUser, nil
	}
	return "", userError{a.t("err.pick_login", strings.Join(names, " | "))}
}
