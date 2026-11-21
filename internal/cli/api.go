// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// maxResponse — предел тела ответа панели.
const maxResponse = 1 << 20

// APIError — ответ панели с ошибкой: { code, message, details } (apps/api error.filter.ts).
type APIError struct {
	Status  int
	Code    string         `json:"code"`
	Message string         `json:"message"`
	Details map[string]any `json:"details"`
}

func (e *APIError) Error() string { return fmt.Sprintf("%d %s: %s", e.Status, e.Code, e.Message) }

// apiCode — код ошибки панели или "".
func apiCode(err error) string {
	var ae *APIError
	if errors.As(err, &ae) {
		return ae.Code
	}
	return ""
}

func apiStatus(err error) int {
	var ae *APIError
	if errors.As(err, &ae) {
		return ae.Status
	}
	return 0
}

// NewHTTPClient — клиент панели: таймаут и без переходов по редиректам (заголовок Authorization не уходит на
// другой адрес, а API на эти маршруты не перенаправляет).
func NewHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

type client struct {
	base  *url.URL
	token string
	http  *http.Client
	ua    string
}

func (c *client) endpoint(path string) string {
	u := *c.base
	u.Path = path
	return u.String()
}

// do — запрос к панели; in — тело JSON или nil, out — куда разобрать ответ 2xx или nil.
func (c *client) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.endpoint(path), body)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.ua)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return &netError{err}
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil {
		return &netError{err}
	}
	if len(raw) > maxResponse {
		return fmt.Errorf("%w: ответ больше %d байт", errBadResponse, maxResponse)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		ae := &APIError{Status: resp.StatusCode}
		if json.Unmarshal(raw, ae) != nil || ae.Code == "" {
			ae.Code, ae.Message = fmt.Sprintf("HTTP_%d", resp.StatusCode), http.StatusText(resp.StatusCode)
		}
		ae.Status = resp.StatusCode
		return ae
	}
	if out == nil || resp.StatusCode == http.StatusNoContent {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("%w: %v", errBadResponse, err)
	}
	return nil
}

var errBadResponse = errors.New("bad response")

// netError — панель не ответила (сеть, DNS, TLS, таймаут).
type netError struct{ err error }

func (e *netError) Error() string { return e.err.Error() }
func (e *netError) Unwrap() error { return e.err }
