// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

// Вход по коду устройства (RFC 8628, apps/api modules/cli).
var (
	deviceCodeRe = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	userCodeRe   = regexp.MustCompile(`^[A-Z0-9]{4}-[A-Z0-9]{4}$`)
)

const (
	// slowDownStep — RFC 8628, 3.5: при slow_down интервал растёт на 5 секунд.
	slowDownStep = 5 * time.Second
	maxInterval  = 60 * time.Second
	// loginWait — сколько ждать подтверждения: запрос живёт 10 минут, плюс запас на часы.
	loginWait = 11 * time.Minute
	nameMax   = 60
)

type loginStarted struct {
	DeviceCode string    `json:"deviceCode"`
	UserCode   string    `json:"userCode"`
	VerifyURL  string    `json:"verifyUrl"`
	Interval   int       `json:"interval"`
	ExpiresAt  time.Time `json:"expiresAt"`
}

type tokenReply struct {
	Pending   bool      `json:"pending"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expiresAt"`
}

type me struct {
	User struct {
		ID    string `json:"id"`
		Name  string `json:"name"`
		Email string `json:"email"`
	} `json:"user"`
	CliSession struct {
		ID        string    `json:"id"`
		Name      string    `json:"name"`
		CreatedAt time.Time `json:"createdAt"`
		ExpiresAt time.Time `json:"expiresAt"`
	} `json:"cliSession"`
	Workspaces []workspace `json:"workspaces"`
}

type workspace struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Slug string `json:"slug"`
	Role string `json:"role"`
}

// computerName — имя компьютера для панели: печатаемые символы, не длиннее 60 (CliLoginDto).
func computerName(raw string) string {
	s := strings.TrimSpace(clean(strings.ToValidUTF8(raw, "")))
	for utf8.RuneCountInString(s) > nameMax {
		_, n := utf8.DecodeLastRuneInString(s)
		s = s[:len(s)-n]
	}
	if strings.TrimSpace(s) == "" {
		return "trassa"
	}
	return s
}

// Login — trassa login: код для человека, ожидание подтверждения в панели, токен в хранилище.
func (a *App) Login(ctx context.Context, rawURL, name string) error {
	cfg, err := loadConfig(a.ConfigDir)
	if err != nil {
		return err
	}
	if rawURL == "" {
		rawURL = a.Env("TRASSA_URL")
	}
	if rawURL == "" {
		rawURL = cfg.URL
	}
	if rawURL == "" {
		return userError{a.t("err.no_url")}
	}
	c, err := a.newClient(rawURL, "")
	if err != nil {
		return err
	}
	origin := c.base.String()
	if name == "" && a.Hostname != nil {
		name, _ = a.Hostname()
	}
	var st loginStarted
	if err := c.do(ctx, http.MethodPost, "/v1/cli/login", map[string]string{"name": computerName(name)}, &st); err != nil {
		return err
	}
	if !deviceCodeRe.MatchString(st.DeviceCode) || !userCodeRe.MatchString(st.UserCode) {
		return fmt.Errorf("%w: код входа", errBadResponse)
	}
	verify, err := url.Parse(st.VerifyURL)
	if err != nil || (verify.Scheme != "https" && !(verify.Scheme == "http" && loopback(verify.Hostname()))) {
		return fmt.Errorf("%w: адрес подтверждения", errBadResponse)
	}
	interval := time.Duration(st.Interval) * time.Second
	if interval < time.Second || interval > maxInterval {
		interval = 5 * time.Second
	}
	deadline := a.now().Add(loginWait)
	if !st.ExpiresAt.IsZero() && st.ExpiresAt.Before(deadline) && st.ExpiresAt.After(a.now()) {
		deadline = st.ExpiresAt.Add(30 * time.Second)
	}
	fmt.Fprint(a.Stderr, a.t("login.started", clean(verify.String()), st.UserCode))
	fmt.Fprint(a.Stderr, a.t("login.waiting", deadline.Local().Format("15:04")))

	var tok tokenReply
	for {
		if a.now().After(deadline) {
			return userError{a.t("err.code_expired")}
		}
		if err := a.sleep(ctx, interval); err != nil {
			return err
		}
		tok = tokenReply{}
		err := c.do(ctx, http.MethodPost, "/v1/cli/token", map[string]string{"deviceCode": st.DeviceCode}, &tok)
		var ne *netError
		switch {
		case err == nil && tok.Pending:
			continue
		case err == nil:
		case apiStatus(err) == http.StatusTooManyRequests:
			// CLI_SLOW_DOWN или общий лимит: опрос реже (RFC 8628, 3.5).
			interval = min(interval+slowDownStep, maxInterval)
			continue
		case apiCode(err) == "CLI_DENIED":
			return userError{a.t("err.denied")}
		case apiCode(err) == "CLI_CODE_EXPIRED" || apiStatus(err) == http.StatusGone:
			return userError{a.t("err.code_expired")}
		case errors.As(err, &ne):
			// Сеть пропала на время: опрос продолжается до срока кода.
			continue
		default:
			return err
		}
		break
	}
	if !cliTokenRe.MatchString(tok.Token) {
		return fmt.Errorf("%w: токен", errBadResponse)
	}
	old, oldErr := a.store().get(origin)
	inFile, kerr, err := a.store().set(origin, tok.Token)
	if err != nil {
		return err
	}
	where := a.t("store.keyring")
	if inFile {
		where = a.t("store.file", a.store().path(), kerr)
	}
	cfg.URL = origin
	c.token = tok.Token
	var who me
	if err := c.do(ctx, http.MethodGet, "/v1/cli/me", nil, &who); err != nil {
		return err
	}
	// Прежний вход этого компьютера в ту же панель больше не нужен: отзыв, чтобы не висел 90 дней.
	if oldErr == nil && old != tok.Token {
		if err := a.revokeToken(ctx, origin, old); err != nil && apiStatus(err) != http.StatusUnauthorized {
			fmt.Fprintf(a.Stderr, a.t("keyring.warn"), a.t("login.old", a.Explain(err)))
		}
	}
	if !hasWorkspace(who.Workspaces, cfg.Workspace) {
		cfg.Workspace = ""
		if len(who.Workspaces) == 1 {
			cfg.Workspace = who.Workspaces[0].Slug
		}
	}
	if err := saveConfig(a.ConfigDir, cfg); err != nil {
		return err
	}
	a.printf("login.done", clean(who.User.Name), clean(who.User.Email), where)
	switch {
	case cfg.Workspace != "":
		a.printf("login.ws", clean(cfg.Workspace))
	case len(who.Workspaces) > 1:
		a.printf("login.ws_many")
	}
	return nil
}

func (a *App) revokeToken(ctx context.Context, origin, token string) error {
	c, err := a.newClient(origin, token)
	if err != nil {
		return err
	}
	var who me
	if err := c.do(ctx, http.MethodGet, "/v1/cli/me", nil, &who); err != nil {
		return err
	}
	return c.do(ctx, http.MethodDelete, "/v1/cli/sessions/"+url.PathEscape(who.CliSession.ID), nil, nil)
}

func hasWorkspace(ws []workspace, want string) bool {
	if want == "" {
		return false
	}
	for _, w := range ws {
		if w.Slug == want || w.ID == want {
			return true
		}
	}
	return false
}

// Logout — trassa logout: отозвать свой вход в панели и удалить токен. Панель недоступна — токен всё равно
// удаляется, человеку сказано, где отозвать вход вручную.
func (a *App) Logout(ctx context.Context) error {
	c, _, err := a.session()
	var ue userError
	if errors.As(err, &ue) {
		a.printf("logout.none")
		return nil
	}
	if err != nil {
		return err
	}
	origin := c.base.String()
	rerr := a.revokeToken(ctx, origin, c.token)
	if rerr != nil && apiStatus(rerr) != http.StatusUnauthorized && apiStatus(rerr) != http.StatusNotFound {
		if err := a.store().delete(origin); err != nil {
			return err
		}
		a.printf("logout.local", a.Explain(rerr))
		return nil
	}
	if err := a.store().delete(origin); err != nil {
		return err
	}
	a.printf("logout.done")
	return nil
}

// Whoami — trassa whoami.
func (a *App) Whoami(ctx context.Context) error {
	c, cfg, err := a.session()
	if err != nil {
		return err
	}
	var who me
	if err := c.do(ctx, http.MethodGet, "/v1/cli/me", nil, &who); err != nil {
		return err
	}
	a.printf("whoami.user", clean(who.User.Name), clean(who.User.Email))
	a.printf("whoami.panel", c.base.String())
	a.printf("whoami.session", clean(who.CliSession.Name), who.CliSession.ExpiresAt.Local().Format("2006-01-02"))
	a.printf("whoami.ws_head")
	for _, w := range who.Workspaces {
		mark := " "
		if w.Slug == cfg.Workspace || w.ID == cfg.Workspace {
			mark = "*"
		}
		fmt.Fprintf(a.Stdout, " %s %s (%s) — %s\n", mark, clean(w.Slug), clean(w.Name), clean(w.Role))
	}
	return nil
}

// Use — trassa use <пространство>: пространство по умолчанию.
func (a *App) Use(ctx context.Context, want string) error {
	c, cfg, err := a.session()
	if err != nil {
		return err
	}
	w, err := a.pickWorkspace(ctx, c, want)
	if err != nil {
		return err
	}
	cfg.Workspace = w.Slug
	if err := saveConfig(a.ConfigDir, cfg); err != nil {
		return err
	}
	a.printf("use.done", clean(w.Slug))
	return nil
}

// workspaceID — пространство команды: флаг, TRASSA_WORKSPACE, настройка или единственное.
func (a *App) workspaceID(ctx context.Context, c *client, cfg *Config, flag string) (string, error) {
	want := flag
	if want == "" {
		want = a.Env("TRASSA_WORKSPACE")
	}
	if want == "" {
		want = cfg.Workspace
	}
	w, err := a.pickWorkspace(ctx, c, want)
	if err != nil {
		return "", err
	}
	return w.ID, nil
}

func (a *App) pickWorkspace(ctx context.Context, c *client, want string) (workspace, error) {
	var who me
	if err := c.do(ctx, http.MethodGet, "/v1/cli/me", nil, &who); err != nil {
		return workspace{}, err
	}
	if len(who.Workspaces) == 0 {
		return workspace{}, userError{a.t("err.ws_none")}
	}
	slugs := make([]string, 0, len(who.Workspaces))
	for _, w := range who.Workspaces {
		slugs = append(slugs, clean(w.Slug))
	}
	if want == "" {
		if len(who.Workspaces) == 1 {
			return who.Workspaces[0], nil
		}
		return workspace{}, userError{a.t("err.ws_pick", strings.Join(slugs, ", "))}
	}
	for _, w := range who.Workspaces {
		if w.Slug == want || strings.EqualFold(w.ID, want) {
			return w, nil
		}
	}
	return workspace{}, userError{a.t("err.ws_unknown", clean(want), strings.Join(slugs, ", "))}
}
