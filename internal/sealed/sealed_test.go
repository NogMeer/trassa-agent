// SPDX-License-Identifier: AGPL-3.0-only

package sealed

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
)

type vector struct {
	Comment     string `json:"comment"`
	PrivateKey  string `json:"private_key_hex"`
	PublicKey   string `json:"public_key_b64"`
	Kid         string `json:"kid"`
	ServerID    string `json:"server_id"`
	OperationID string `json:"operation_id"`
	Type        string `json:"type"`
	PlanID      string `json:"plan_id"`
	Field       string `json:"field"`
	InfoHex     string `json:"info_hex"`
	Plaintext   string `json:"plaintext"`
	EncCtB64    string `json:"enc_ct_b64"`
}

func readVectors(t *testing.T, name string) []vector {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "test", "vectors", name))
	if err != nil {
		t.Fatal(err)
	}
	var v []vector
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

// Вектор Go → TS: панель расшифровывает enc_ct ключом из вектора. Здесь — то же в Go и сверка info и kid.
func checkVectors(t *testing.T, vs []vector) {
	for i, v := range vs {
		pk, _ := hex.DecodeString(v.PrivateKey)
		k, err := FromBytes(pk)
		if err != nil {
			t.Fatal(err)
		}
		if base64.StdEncoding.EncodeToString(k.Public()) != v.PublicKey || k.ID != v.Kid {
			t.Fatalf("вектор %d: ключ или kid", i)
		}
		info := Info(v.ServerID, v.Kid, v.OperationID, v.Type, v.PlanID, v.Field)
		if hex.EncodeToString(info) != v.InfoHex {
			t.Fatalf("вектор %d: info %x", i, info)
		}
		ct, _ := base64.StdEncoding.DecodeString(v.EncCtB64)
		pt, err := k.Open(&agentv1.SealedSecret{Kid: v.Kid, EncCt: ct}, info)
		if err != nil || string(pt) != v.Plaintext {
			t.Fatalf("вектор %d: %v %q", i, err, pt)
		}
	}
}

func TestGoVectors(t *testing.T) { checkVectors(t, readVectors(t, "hpke-go.json")) }

// Вектор TS → Go (перекрёстный тест E13, обязателен): шифротекст делает панель на @hpke/core. Файл кладёт
// бэкенд панели; без него тест падает в CI, а не пропускается молча.
func TestTSVectors(t *testing.T) {
	if _, err := os.Stat(filepath.Join("..", "..", "test", "vectors", "hpke-ts.json")); errors.Is(err, os.ErrNotExist) {
		if os.Getenv("CI") == "true" {
			t.Fatal("нет test/vectors/hpke-ts.json — вектора TS → Go")
		}
		t.Skip("нет test/vectors/hpke-ts.json")
	}
	checkVectors(t, readVectors(t, "hpke-ts.json"))
}

func TestOpenRejects(t *testing.T) {
	k, err := LoadOrCreate(filepath.Join(t.TempDir(), "enc.key"))
	if err != nil {
		t.Fatal(err)
	}
	info := Info("srv", k.ID, "OP", "backup.init", "plan", "password")
	s, err := Seal(k.Public(), info, []byte("секрет"))
	if err != nil {
		t.Fatal(err)
	}
	if pt, err := k.Open(s, info); err != nil || string(pt) != "секрет" {
		t.Fatal(err)
	}
	// Переложенный в другое поле, другую операцию или план — не расшифровывается.
	for _, other := range [][]byte{
		Info("srv", k.ID, "OP", "backup.init", "plan", "env:AWS_SECRET_ACCESS_KEY"),
		Info("srv", k.ID, "OP2", "backup.init", "plan", "password"),
		Info("srv2", k.ID, "OP", "backup.init", "plan", "password"),
	} {
		if _, err := k.Open(s, other); !errors.Is(err, ErrOpen) {
			t.Errorf("открыт в чужом контексте: %v", err)
		}
	}
	bad := &agentv1.SealedSecret{Kid: k.ID, EncCt: append(bytes.Clone(s.GetEncCt()[:len(s.GetEncCt())-1]), s.GetEncCt()[len(s.GetEncCt())-1]^1)}
	if _, err := k.Open(bad, info); !errors.Is(err, ErrOpen) {
		t.Fatal("подменённый шифротекст открыт")
	}
	if _, err := k.Open(&agentv1.SealedSecret{Kid: "other", EncCt: s.GetEncCt()}, info); !errors.Is(err, ErrKey) {
		t.Fatal(err)
	}
	// Повторная загрузка — тот же ключ; права шире 0600 — отказ.
	p := filepath.Join(t.TempDir(), "enc.key")
	k1, _ := LoadOrCreate(p)
	k2, _ := LoadOrCreate(p)
	if k1.ID != k2.ID {
		t.Fatal("ключ пересоздан")
	}
	_ = os.Chmod(p, 0o644)
	if _, err := LoadOrCreate(p); err == nil {
		t.Fatal("ключ с правами 0644 принят")
	}
}
