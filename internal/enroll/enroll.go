// SPDX-License-Identifier: AGPL-3.0-only

// Package enroll — регистрация агента: POST /agent/v1/enroll (E05, раздел 5). Токен одноразовый, в ответ —
// server_id, ключи панели и адрес шлюза. Запускается установщиком от root один раз.
package enroll

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/NogMeer/trassa-agent/internal/config"
)

// Request — тело запроса.
type Request struct {
	Token            string `json:"token"`
	PublicKey        string `json:"publicKey"` // 32 байта Ed25519, base64url без дополнения
	Hostname         string `json:"hostname"`
	OS               string `json:"os"`
	OSVersion        string `json:"osVersion"`
	Arch             string `json:"arch"`
	AgentVersion     string `json:"agentVersion"`
	ProtocolVersions []int  `json:"protocolVersions"`
}

// Error — отказ панели: { code, message }.
type Error struct {
	Status  int
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *Error) Error() string { return fmt.Sprintf("enroll: HTTP %d %s", e.Status, e.Code) }

// Коды отказа (раздел 5).
const (
	CodeTokenInvalid        = "ENROLLMENT_TOKEN_INVALID"
	CodeOSUnsupported       = "OS_UNSUPPORTED"
	CodeProtocolUnsupported = "PROTOCOL_UNSUPPORTED"
)

var tokenRe = regexp.MustCompile(`^trs_enr_[A-Za-z0-9_-]{43}$`)

// ValidToken — токен вида trs_enr_ и 32 байта base64url.
func ValidToken(t string) bool { return tokenRe.MatchString(t) }

// PublicKeyString — открытый ключ агента для запроса.
func PublicKeyString(pk ed25519.PublicKey) string { return base64.RawURLEncoding.EncodeToString(pk) }

// Do отправляет запрос на panelURL (https://agents.<домен>) и проверяет ответ.
func Do(ctx context.Context, c *http.Client, panelURL string, req Request) (config.Enrollment, error) {
	u, err := url.Parse(panelURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return config.Enrollment{}, fmt.Errorf("адрес панели %q: нужен https://", panelURL)
	}
	if !ValidToken(req.Token) {
		return config.Enrollment{}, &Error{Status: 0, Code: CodeTokenInvalid, Message: "неверный формат токена"}
	}
	endpoint := u.JoinPath("/agent/v1/enroll").String()
	body, _ := json.Marshal(req)
	hr, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return config.Enrollment{}, err
	}
	hr.Header.Set("Content-Type", "application/json")
	hr.Header.Set("User-Agent", "trassa-agent/"+req.AgentVersion)
	resp, err := c.Do(hr)
	if err != nil {
		return config.Enrollment{}, fmt.Errorf("нет связи с %s: %w", u.Host, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return config.Enrollment{}, err
	}
	if resp.StatusCode != http.StatusOK {
		e := &Error{Status: resp.StatusCode}
		_ = json.Unmarshal(raw, e)
		if e.Code == "" {
			e.Code = http.StatusText(resp.StatusCode)
		}
		return config.Enrollment{}, e
	}
	var en config.Enrollment
	// Ответ разбирается без строгости к лишним полям: панель может добавить новые, агент их не использует.
	if err := json.Unmarshal(raw, &en); err != nil {
		return config.Enrollment{}, fmt.Errorf("ответ панели не разобран: %w", err)
	}
	if _, err := en.Validate(); err != nil {
		return config.Enrollment{}, err
	}
	// Шлюз — на том же хосте, что и регистрация: адрес панели задаёт тот, кто вставил команду, и ответ не может
	// увести агента к постороннему узлу.
	gu, _ := url.Parse(en.GatewayURL)
	if !strings.EqualFold(gu.Hostname(), u.Hostname()) {
		return config.Enrollment{}, fmt.Errorf("%w: шлюз %s не на хосте панели %s", config.ErrEnrollmentInvalid, gu.Host, u.Host)
	}
	return en, nil
}

// UserMessage — понятный текст для скрипта установки.
func UserMessage(err error) string {
	var e *Error
	if errors.As(err, &e) {
		switch e.Code {
		case CodeTokenInvalid:
			return "Срок действия команды истёк. Получите новую в панели"
		case CodeOSUnsupported:
			return "Эта система пока не поддерживается панелью"
		case CodeProtocolUnsupported:
			return "Версия агента не поддерживается панелью. Получите новую команду в панели"
		}
		if e.Status == http.StatusTooManyRequests {
			return "Слишком много попыток. Подождите минуту и повторите"
		}
		return "Панель отказала в регистрации: " + e.Code
	}
	return "Регистрация не удалась: " + err.Error()
}
