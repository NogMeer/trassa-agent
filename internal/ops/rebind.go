// SPDX-License-Identifier: AGPL-3.0-only

package ops

import (
	"errors"
	"fmt"
	"unicode"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/config"
	"github.com/NogMeer/trassa-agent/internal/verify"
)

// TypeAgentRebind — перевод агента в другую панель (E24-T20, раздел 6 E24).
const TypeAgentRebind = "agent.rebind"

// Срок подтверждения перевода новой панелью, секунд (панель шлёт 300).
const (
	MinRebindConfirm = 60
	MaxRebindConfirm = 600
	maxKeyID         = 128
)

// RebindKeys — ключи новой панели из параметров: 1–2, keyId не пустые, печатные, разные, ключ 32 байта.
func RebindKeys(p *agentv1.AgentRebindParams) ([]verify.PanelKey, error) {
	ks := p.GetPanelKeys()
	if len(ks) < 1 || len(ks) > 2 {
		return nil, errors.New("panel_keys: 1 или 2 ключа")
	}
	seen := map[string]bool{}
	out := make([]verify.PanelKey, 0, len(ks))
	for _, k := range ks {
		id := k.GetKeyId()
		if id == "" || len(id) > maxKeyID || seen[id] {
			return nil, errors.New("panel_keys: пустой, длинный или повторный key_id")
		}
		for _, r := range id {
			if r > unicode.MaxASCII || !unicode.IsPrint(r) || r == ' ' {
				return nil, errors.New("panel_keys: key_id — печатные ASCII без пробелов")
			}
		}
		if len(k.GetPublicKey()) != 32 {
			return nil, fmt.Errorf("panel_keys: ключ %q не 32 байта", id)
		}
		seen[id] = true
		out = append(out, verify.PanelKey{ID: id, PublicKey: append([]byte(nil), k.GetPublicKey()...)})
	}
	return out, nil
}

func validateRebind(b *agentv1.OperationBody) error {
	p := b.GetParams().GetAgentRebind()
	if err := config.ValidGatewayURL(p.GetGatewayUrl()); err != nil {
		return err
	}
	if _, err := RebindKeys(p); err != nil {
		return err
	}
	if cw := b.GetConfirmWithinSec(); cw < MinRebindConfirm || cw > MaxRebindConfirm {
		return fmt.Errorf("confirm_within_sec: %d–%d", MinRebindConfirm, MaxRebindConfirm)
	}
	return nil
}

func rebindSpecs() []Spec {
	return []Spec{{
		// CONFIG — запись о регистрации; автооткат обязателен: без подтверждения новой панелью агент вернётся.
		Type: TypeAgentRebind, Class: Destructive, Rollback: agentv1.RollbackKind_ROLLBACK_KIND_CONFIG, AutoRollback: true,
		match:    func(p *agentv1.OperationParams) bool { return p.GetAgentRebind() != nil },
		Validate: validateRebind,
	}}
}
