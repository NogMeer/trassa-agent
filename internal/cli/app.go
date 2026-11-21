// SPDX-License-Identifier: AGPL-3.0-only

// Package cli — программа trassa (E16-T19, T20): вход по коду устройства, список серверов, вход на сервер через
// Trassa или напрямую по сертификату на 10 минут. Токен входа — в системном хранилище секретов.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// App — окружение команд; в тестах всё подменяется.
type App struct {
	Stdin     *os.File
	Stdout    io.Writer
	Stderr    io.Writer
	Env       func(string) string
	ConfigDir string
	Keyring   Keyring
	HTTP      *http.Client
	Version   string
	Lang      Lang
	Now       func() time.Time
	// Sleep — пауза опроса (в тестах — без ожидания).
	Sleep func(ctx context.Context, d time.Duration) error
	// Hostname — имя компьютера для входа CLI.
	Hostname func() (string, error)
	// LookPath, Exec — системный ssh в --direct.
	LookPath func(string) (string, error)
	RunSSH   func(ctx context.Context, path string, args, env []string) (int, error)
	// GOOS — для проверок платформы в тестах.
	GOOS string
}

func (a *App) t(key string, args ...any) string { return a.Lang.t(key, args...) }

func (a *App) printf(key string, args ...any) { fmt.Fprint(a.Stdout, a.t(key, args...)) }

func (a *App) store() *tokenStore { return &tokenStore{kr: a.Keyring, dir: a.ConfigDir} }

func (a *App) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

func (a *App) sleep(ctx context.Context, d time.Duration) error {
	if a.Sleep != nil {
		return a.Sleep(ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func (a *App) newClient(base string, token string) (*client, error) {
	u, err := normalizeBase(base)
	if err != nil {
		return nil, err
	}
	return &client{base: u, token: token, http: a.HTTP, ua: "trassa-cli/" + a.Version}, nil
}

// session — клиент от имени вошедшего: адрес из настроек, токен из хранилища.
func (a *App) session() (*client, *Config, error) {
	cfg, err := loadConfig(a.ConfigDir)
	if err != nil {
		return nil, nil, err
	}
	if cfg.URL == "" {
		return nil, nil, userError{a.t("err.not_logged_in")}
	}
	u, err := normalizeBase(cfg.URL)
	if err != nil {
		return nil, nil, userError{a.t("err.url_bad")}
	}
	tok, err := a.store().get(u.String())
	var nt *noToken
	if errors.As(err, &nt) {
		if nt.cause != nil {
			return nil, nil, userError{a.t("err.not_logged_in") + " (" + nt.cause.Error() + ")"}
		}
		return nil, nil, userError{a.t("err.not_logged_in")}
	}
	if err != nil {
		return nil, nil, err
	}
	c, err := a.newClient(u.String(), tok)
	return c, cfg, err
}

// userError — сообщение для человека как есть.
type userError struct{ msg string }

func (e userError) Error() string { return e.msg }

// Explain — ошибка как сообщение для человека: коды панели — понятными словами. Итог очищается от управляющих
// символов: текст ошибок TLS и сети несёт строки от удалённой стороны (имена из сертификата).
func (a *App) Explain(err error) string { return clean(a.explain(err)) }

func (a *App) explain(err error) string {
	var ue userError
	if errors.As(err, &ue) {
		return ue.msg
	}
	if errors.Is(err, errBadURL) {
		return a.t("err.url_bad")
	}
	var ne *netError
	if errors.As(err, &ne) {
		return a.t("err.network", ne.err)
	}
	if errors.Is(err, errBadResponse) {
		return a.t("err.bad_response", err)
	}
	var ae *APIError
	if errors.As(err, &ae) {
		switch {
		case ae.Status == http.StatusUnauthorized:
			return a.t("err.relogin")
		case ae.Code == "ACCESS_NO_GRANT" || ae.Status == http.StatusNotFound && ae.Code == "NOT_FOUND":
			return a.t("err.no_grant")
		case ae.Code == "ACCESS_DIRECT_DISABLED":
			return a.t("err.direct_disabled")
		case ae.Code == "ACCESS_MFA_REQUIRED":
			return a.t("err.mfa")
		case ae.Code == "STEP_UP_REQUIRED":
			return a.t("err.step_up")
		case ae.Code == "ACCESS_NOT_READY":
			return a.t("err.not_ready")
		case ae.Code == "SERVER_OFFLINE":
			return a.t("err.offline")
		case ae.Status == http.StatusPaymentRequired:
			return a.t("err.plan")
		case ae.Code == "ACCESS_GRANT_EXPIRED":
			return a.t("err.pass_expired")
		}
		return a.t("err.api", ae.Status, clean(ae.Code), clean(ae.Message))
	}
	return err.Error()
}
