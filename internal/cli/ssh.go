// SPDX-License-Identifier: AGPL-3.0-only

package cli

import "context"

// SSHOptions — trassa ssh.
type SSHOptions struct {
	Workspace string
	Login     string
	Direct    bool
	Server    string
	Remote    []string
}

// SSH — trassa ssh: сервер из ваших, логин, затем через Trassa или --direct. Код выхода — оболочки или ssh.
func (a *App) SSH(ctx context.Context, o SSHOptions, term Terminal) (int, error) {
	c, cfg, err := a.session()
	if err != nil {
		return 1, err
	}
	ws, err := a.workspaceID(ctx, c, cfg, o.Workspace)
	if err != nil {
		return 1, err
	}
	items, err := a.myServers(ctx, c, ws)
	if err != nil {
		return 1, err
	}
	srv, err := a.resolveServer(items, o.Server)
	if err != nil {
		return 1, err
	}
	user, err := a.pickLogin(srv, o.Login)
	if err != nil {
		return 1, err
	}
	if o.Direct {
		return a.Direct(ctx, c, ws, srv, user, o.Remote)
	}
	if len(o.Remote) > 0 {
		// Через Trassa команда не передаётся отдельно: это интерактивный терминал.
		return 1, userError{a.t("err.remote_relay")}
	}
	return a.Relay(ctx, c, ws, srv, user, term)
}
