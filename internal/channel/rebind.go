// SPDX-License-Identifier: AGPL-3.0-only

package channel

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
)

// Перевод в другую панель (E24-T20). Запись о регистрации меняет и возвращает помощник; агент перед каждым
// подключением перечитывает её (Reload), поэтому после возврата сам оказывается у прежней панели.
const (
	// RebindRetry — задержка между попытками к новой панели.
	RebindRetry = 5 * time.Second
	// RebindUnreachableTries — сколько неудачных подключений подряд до возврата, не дожидаясь срока.
	RebindUnreachableTries = 3
	// rebindAckWait — сколько ждать InboundAck прежней панели на итог AWAITING_CONFIRM до переключения.
	rebindAckWait = 10 * time.Second
	// RebindPoll — как часто во время сеанса с новой панелью сверяться с помощником: подтверждено ли, не вернулся ли
	// он к прежней записи по сроку.
	RebindPoll = 2 * time.Second
)

// errRebindReturn — помощник вернул прежнюю запись: подключиться сразу.
var errRebindReturn = errors.New("перевод не состоялся: возврат к прежней панели")

// pendingRebind — перевод ждёт подтверждения на этом адресе.
type pendingRebind struct {
	OperationID string `json:"operation_id"`
	GatewayURL  string `json:"gateway_url"`
}

// reload — адрес и ключи из записи о регистрации и состояние перевода у помощника. Сбой чтения записи оставляет
// прежние значения (агент продолжает работать с тем, что знал).
func (a *Agent) reload(ctx context.Context) {
	if a.cfg.Reload != nil {
		gw, keys, err := a.cfg.Reload()
		if err != nil {
			a.cfg.Log.Error("запись о регистрации не прочитана: адрес и ключи панели прежние", "err", err)
		} else {
			a.mu.Lock()
			changed := gw != a.gw
			a.gw, a.keys = gw, keys
			a.mu.Unlock()
			if a.cfg.Local != nil && a.cfg.Local.Checker != nil {
				a.cfg.Local.Checker.SetPanelKeys(keys)
			}
			if changed {
				a.cfg.Log.Info("адрес панели сменился", "gateway", gw)
			}
		}
	}
	prev := a.pendingRebind
	a.pendingRebind = nil
	if a.cfg.Rebind == nil {
		return
	}
	defer func() {
		// Перевод был и завершился на том же адресе — подтверждён: итоги прежней панели новой не отдаются.
		if prev != nil && a.pendingRebind == nil && a.gateway() == prev.GatewayURL {
			a.ob.dropExcept(prev.OperationID)
		}
	}()
	sctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	raw, err := a.cfg.Rebind.RebindState(sctx)
	cancel()
	if err != nil || len(raw) == 0 {
		return
	}
	var st pendingRebind
	if json.Unmarshal(raw, &st) != nil || st.OperationID == "" {
		return
	}
	// Перевод относится к адресу из записи: если запись уже другая (возврат идёт), ждать нечего.
	if st.GatewayURL == a.gateway() {
		a.pendingRebind = &st
	}
}

func (a *Agent) rebindOperationID() string {
	if a.pendingRebind == nil {
		return ""
	}
	return a.pendingRebind.OperationID
}

// tlsUntrusted — сертификат новой панели не прошёл проверку (системные корни, имя, срок).
func tlsUntrusted(err error) bool {
	var ua x509.UnknownAuthorityError
	var he x509.HostnameError
	var ci x509.CertificateInvalidError
	var cv *tls.CertificateVerificationError
	return errors.As(err, &ua) || errors.As(err, &he) || errors.As(err, &ci) || errors.As(err, &cv)
}

// rebindDialFailed — новая панель не ответила: сертификат — возврат сразу, иначе после трёх попыток подряд.
func (a *Agent) rebindDialFailed(ctx context.Context, err error) error {
	if tlsUntrusted(err) {
		return a.rebindFailed(ctx, agentv1.RebindFailure_REBIND_FAILURE_TLS_UNTRUSTED, err.Error(), true)
	}
	a.rebindFails++
	return a.rebindFailed(ctx, agentv1.RebindFailure_REBIND_FAILURE_UNREACHABLE, err.Error(),
		a.rebindFails >= RebindUnreachableTries)
}

// rebindFailed — сообщить помощнику причину; now — помощник возвращает прежнюю запись сразу.
func (a *Agent) rebindFailed(ctx context.Context, f agentv1.RebindFailure, detail string, now bool) error {
	p := a.pendingRebind
	if p == nil {
		return errors.New(detail)
	}
	detail = strings.TrimSpace(detail)
	fctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	err := a.cfg.Rebind.RebindFail(fctx, p.OperationID, int32(f), detail, now)
	cancel()
	a.cfg.Log.Warn("новая панель не приняла агента", "failure", f.String(), "detail", detail, "return_now", now)
	if err != nil {
		a.cfg.Log.Error("помощник: причина перевода не записана", "err", err)
		return errors.New(detail)
	}
	if now {
		a.pendingRebind, a.rebindFails = nil, 0
		return errRebindReturn
	}
	return errors.New(detail)
}

// afterRebindApplied — итог AWAITING_CONFIRM ушёл прежней панели: дождаться её квитанции (не дольше 10 с) и
// переподключиться — Reload даст уже новый адрес.
func (a *Agent) afterRebindApplied(ctx context.Context, opID string, raw []byte) {
	var r agentv1.OperationResult
	if proto.Unmarshal(raw, &r) != nil || r.GetOutcome() != agentv1.OperationOutcome_OPERATION_OUTCOME_AWAITING_CONFIRM {
		return
	}
	deadline := time.Now().Add(rebindAckWait)
	for a.ob.get(opID) != nil && time.Now().Before(deadline) && ctx.Err() == nil {
		time.Sleep(100 * time.Millisecond)
	}
	select {
	case a.kick <- struct{}{}:
	default:
	}
}

// rebindWatch — в сеансе с новой панелью: помощник вернул прежнюю запись (срок вышел) — сеанс завершается
// (errRebindReturn), подтверждено — перевод снят, сеанс продолжается. "" — ничего не изменилось.
func (a *Agent) rebindWatch(ctx context.Context) error {
	p := a.pendingRebind
	if p == nil {
		return nil
	}
	sctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	raw, err := a.cfg.Rebind.RebindState(sctx)
	cancel()
	if err != nil {
		return nil // помощник не ответил — проверим в следующий раз
	}
	var st pendingRebind
	if len(raw) > 0 && json.Unmarshal(raw, &st) == nil && st.OperationID == p.OperationID {
		return nil // ещё ждём
	}
	gw := ""
	if a.cfg.Reload != nil {
		if g, _, err := a.cfg.Reload(); err == nil {
			gw = g
		}
	}
	if gw == p.GatewayURL {
		a.pendingRebind = nil
		a.ob.dropExcept(p.OperationID)
		a.cfg.Log.Info("перевод в новую панель подтверждён")
		return nil
	}
	a.pendingRebind, a.rebindFails = nil, 0
	return errRebindReturn
}
