// SPDX-License-Identifier: AGPL-3.0-only

// Package remedy — исправления E18 в помощнике: запуск и перезапуск службы или контейнера с проверкой «работает
// 60 секунд», очистка диска только восстановимого, продление сертификата certbot, наблюдение за падением
// контейнеров и сроком сертификатов. Решения — docs/plan/decisions/E18-agent.md.
package remedy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/NogMeer/trassa-agent/internal/dockerapi"
)

// Коды итога (имена ошибок — коды панели).
var (
	ErrNotFound      = errors.New("SERVICE_NOT_FOUND")
	ErrNotStable     = errors.New("SERVICE_NOT_STABLE")
	ErrRestartFailed = errors.New("SERVICE_RESTART_FAILED")
	ErrManaged       = errors.New("CONTAINER_MANAGED_BY_TRASSA")
	ErrCertNotFound  = errors.New("CERT_NOT_FOUND")
	ErrCertNotDue    = errors.New("CERT_NOT_DUE")
	ErrCertFailed    = errors.New("CERT_RENEW_FAILED")
	ErrCertUnsupport = errors.New("CERT_RENEW_UNSUPPORTED")
	ErrCertProxy     = errors.New("CERT_MANAGED_BY_PROXY")
	ErrPackageBusy   = errors.New("PACKAGE_MANAGER_BUSY")
)

// Codes — все коды пакета (для итога операции).
var Codes = []error{ErrNotFound, ErrNotStable, ErrRestartFailed, ErrManaged, ErrCertNotFound, ErrCertNotDue, ErrCertFailed,
	ErrCertUnsupport, ErrCertProxy, ErrPackageBusy}

// Env — зависимости исправлений.
type Env struct {
	Root   string // "/" на сервере
	Run    func(ctx context.Context, name string, args ...string) ([]byte, error)
	Docker *dockerapi.Client
	Now    func() time.Time
	// Stable — сколько цель обязана работать тем же процессом (план E18: 60 с); Poll — шаг опроса; Settle —
	// сколько ждать перехода в рабочее состояние после команды.
	Stable, Poll, Settle time.Duration
	// ProxyHosts — имена, сертификаты которых выпускает Caddy Trassa (cert.renew их не трогает).
	ProxyHosts func() []string
	// TrassaImages — образы релизов приложений Trassa (их disk.cleanup не удаляет).
	TrassaImages func() map[string]bool
	// Free — свободно на разделе (байт).
	Free func(path string) (uint64, error)
	// PackagesBusy — держатель блокировки пакетов (пусто — свободно).
	PackagesBusy func(ctx context.Context) string
}

func (e *Env) path(p string) string { return filepath.Join(e.Root, p) }

func (e *Env) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

func (e *Env) sleep(ctx context.Context, d time.Duration) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(d):
		return nil
	}
}

func (e *Env) durations() (stable, poll, settle time.Duration) {
	stable, poll, settle = e.Stable, e.Poll, e.Settle
	if stable == 0 {
		stable = 60 * time.Second
	}
	if poll == 0 {
		poll = 5 * time.Second
	}
	if settle == 0 {
		settle = 30 * time.Second
	}
	return
}

// docker — запрос Engine API; out == nil — тело отбрасывается. 304 — не ошибка (уже запущен или остановлен).
func (e *Env) docker(ctx context.Context, method, p string, out any) (int, error) {
	if e.Docker == nil {
		return 0, dockerapi.ErrNoDocker
	}
	resp, err := e.Docker.Do(ctx, method, p, nil, nil)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		return resp.StatusCode, nil
	}
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return resp.StatusCode, fmt.Errorf("docker %s %s: HTTP %d: %s", method, p, resp.StatusCode, strings.TrimSpace(string(b)))
	}
	if out == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 16<<20))
		return resp.StatusCode, nil
	}
	return resp.StatusCode, json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(out)
}

func tail(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 4096 {
		s = s[len(s)-4096:]
	}
	return strings.ToValidUTF8(s, "")
}
