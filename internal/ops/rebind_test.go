// SPDX-License-Identifier: AGPL-3.0-only

package ops

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
)

// Общий набор параметров agent.rebind с панелью.
func TestRebindParamsShared(t *testing.T) {
	raw, err := os.ReadFile("../../proto/testdata/agent-rebind.json")
	if err != nil {
		t.Fatal(err)
	}
	var c struct {
		Cases []struct {
			Name      string `json:"name"`
			URL       string `json:"gateway_url"`
			PanelKeys []struct {
				ID  string `json:"key_id"`
				Hex string `json:"public_key_hex"`
			} `json:"panel_keys"`
			Confirm uint32 `json:"confirm_within_sec"`
			Valid   bool   `json:"valid"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	spec, ok := Builtin().Lookup(TypeAgentRebind)
	if !ok || spec.Class != Destructive || spec.Rollback != agentv1.RollbackKind_ROLLBACK_KIND_CONFIG || !spec.AutoRollback {
		t.Fatalf("каталог: %+v", spec)
	}
	for _, tc := range c.Cases {
		p := &agentv1.AgentRebindParams{GatewayUrl: tc.URL}
		for _, k := range tc.PanelKeys {
			b, _ := hex.DecodeString(k.Hex)
			p.PanelKeys = append(p.PanelKeys, &agentv1.RebindPanelKey{KeyId: k.ID, PublicKey: b})
		}
		body := &agentv1.OperationBody{Type: TypeAgentRebind, Rollback: agentv1.RollbackKind_ROLLBACK_KIND_CONFIG, ConfirmWithinSec: tc.Confirm,
			Params: &agentv1.OperationParams{Params: &agentv1.OperationParams_AgentRebind{AgentRebind: p}}}
		if err := CheckParams(spec, body); (err == nil) != tc.Valid {
			t.Errorf("%s: err=%v, ждали valid=%v", tc.Name, err, tc.Valid)
		}
	}
	// Без автоотката и с другим видом отката — тоже отказ.
	body := &agentv1.OperationBody{Type: TypeAgentRebind, Rollback: agentv1.RollbackKind_ROLLBACK_KIND_NONE, ConfirmWithinSec: 300,
		Params: &agentv1.OperationParams{Params: &agentv1.OperationParams_AgentRebind{AgentRebind: &agentv1.AgentRebindParams{}}}}
	if CheckParams(spec, body) == nil {
		t.Fatal("rollback NONE принят")
	}
}
