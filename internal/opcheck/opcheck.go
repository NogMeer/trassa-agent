// SPDX-License-Identifier: AGPL-3.0-only

// Package opcheck — проверки 1–3, 5, 6 таблицы раздела 6 E05 для подписанных операций и подтверждений:
// подпись, server_id, сроки, тип из зашитого списка, параметры. Ими пользуются помощник (свои типы) и агент
// без прав (net.check). Проверку 4 (nonce) делает исполнитель вместе с записью своего состояния.
package opcheck

import (
	"time"

	"google.golang.org/protobuf/proto"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/config"
	"github.com/NogMeer/trassa-agent/internal/nonce"
	"github.com/NogMeer/trassa-agent/internal/ops"
	"github.com/NogMeer/trassa-agent/internal/verify"
)

const (
	// MaxNotAfter — not_after не дальше 10 минут (проверка 3).
	MaxNotAfter = 10 * time.Minute
	// ClockTolerance — допуск на расхождение часов агента и панели. Панель не шлёт операции при расхождении
	// больше 60 с (AGENT_CLOCK_SKEW), поэтому больший допуск не нужен.
	ClockTolerance = 60 * time.Second
	// NonceSize — длина nonce операции.
	NonceSize = 16
)

// Checker — проверки 1–6 таблицы раздела 6.
type Checker struct {
	Keys     []verify.PanelKey
	ServerID string
	Catalog  *ops.Catalog
	Nonces   *nonce.Store
	Now      func() time.Time
}

// Rejection — отказ с кодом из таблицы.
type Rejection struct {
	Code   string
	Detail string
}

func (r *Rejection) Error() string { return r.Code + ": " + r.Detail }

func reject(code, detail string) *Rejection { return &Rejection{Code: code, Detail: detail} }

// Checked — операция прошла проверки 1–3, 5, 6. Проверку 4 (nonce) делает исполнитель вместе с записью
// состояния: повтор той же операции — не ошибка.
type Checked struct {
	Body *agentv1.OperationBody
	Spec ops.Spec
}

func (c *Checker) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// Operation проверяет подписанную операцию. Порядок важен: подпись проверяется по полученным байтам до их
// разбора (раздел 6, «Конверт»).
func (c *Checker) Operation(raw []byte) (*Checked, *Rejection) {
	var so agentv1.SignedOperation
	if err := proto.Unmarshal(raw, &so); err != nil {
		return nil, reject(ops.CodeSignatureInvalid, "конверт не разобран")
	}
	// 1. Подпись одним из ключей панели. Пустой список ключей — отказ (verify.Signature).
	if err := verify.Signature(c.Keys, so.GetKeyId(), verify.ContextOperation, so.GetBody(), so.GetSignature()); err != nil {
		return nil, reject(ops.CodeSignatureInvalid, "подпись")
	}
	var b agentv1.OperationBody
	if err := proto.Unmarshal(so.GetBody(), &b); err != nil {
		return nil, reject(ops.CodeParamsInvalid, "тело не разобрано")
	}
	// 2. server_id свой.
	if c.ServerID == "" || b.GetServerId() != c.ServerID {
		return nil, reject(ops.CodeServerMismatch, b.GetServerId())
	}
	// 3. Сроки.
	if r := c.checkTimes(b.GetNotAfterMs(), b.GetIssuedAtMs(), true); r != nil {
		return nil, r
	}
	// 5. Тип из зашитого списка.
	spec, ok := c.Catalog.Lookup(b.GetType())
	if !ok {
		return nil, reject(ops.CodeTypeUnknown, b.GetType())
	}
	// 6. Параметры, плюс поля конверта, без которых операцию нельзя учесть.
	if len(b.GetNonce()) != NonceSize {
		return nil, reject(ops.CodeParamsInvalid, "nonce не 16 байт")
	}
	if !config.IsUUID(b.GetOperationId()) {
		return nil, reject(ops.CodeParamsInvalid, "operation_id")
	}
	if err := ops.CheckParams(spec, &b); err != nil {
		return nil, reject(ops.CodeParamsInvalid, err.Error())
	}
	return &Checked{Body: &b, Spec: spec}, nil
}

// checkTimes — проверка 3. not_after в будущем и не дальше 10 минут от текущего времени (с допуском на часы);
// issued_at, если он подписан, не в будущем и не раньше not_after − 10 минут.
func (c *Checker) checkTimes(notAfterMs, issuedAtMs int64, needIssued bool) *Rejection {
	now := c.now()
	notAfter := time.UnixMilli(notAfterMs)
	if notAfterMs <= 0 || !notAfter.After(now) {
		return reject(ops.CodeExpired, "not_after прошёл")
	}
	if notAfter.Sub(now) > MaxNotAfter+ClockTolerance {
		return reject(ops.CodeNotAfterTooFar, "not_after дальше 10 минут")
	}
	if needIssued {
		issued := time.UnixMilli(issuedAtMs)
		if issuedAtMs <= 0 || notAfter.Sub(issued) > MaxNotAfter || !notAfter.After(issued) {
			return reject(ops.CodeNotAfterTooFar, "not_after дальше 10 минут от issued_at")
		}
		if issued.Sub(now) > ClockTolerance {
			return reject(ops.CodeNotAfterTooFar, "issued_at в будущем: часы сервера отстают")
		}
	}
	return nil
}

// Confirm проверяет подписанное подтверждение (контекст trassa-confirm-v1).
func (c *Checker) Confirm(raw []byte) (*agentv1.ConfirmBody, *Rejection) {
	var sc agentv1.SignedConfirm
	if err := proto.Unmarshal(raw, &sc); err != nil {
		return nil, reject(ops.CodeSignatureInvalid, "конверт не разобран")
	}
	if err := verify.Signature(c.Keys, sc.GetKeyId(), verify.ContextConfirm, sc.GetBody(), sc.GetSignature()); err != nil {
		return nil, reject(ops.CodeSignatureInvalid, "подпись")
	}
	var b agentv1.ConfirmBody
	if err := proto.Unmarshal(sc.GetBody(), &b); err != nil {
		return nil, reject(ops.CodeParamsInvalid, "тело не разобрано")
	}
	if c.ServerID == "" || b.GetServerId() != c.ServerID {
		return nil, reject(ops.CodeServerMismatch, b.GetServerId())
	}
	if r := c.checkTimes(b.GetNotAfterMs(), 0, false); r != nil {
		return nil, r
	}
	if len(b.GetNonce()) != NonceSize || !config.IsUUID(b.GetOperationId()) {
		return nil, reject(ops.CodeParamsInvalid, "nonce или operation_id")
	}
	return &b, nil
}
