// SPDX-License-Identifier: AGPL-3.0-only

package verify

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/protobuf/proto"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
)

var update = flag.Bool("update", false, "переписать test/vectors/go-signed.json")

// Тестовый ключ: RFC 8032, раздел 7.1, тест 2 — тот же, что у панели в тестах (TEST_OPERATION_JWK).
const testSeed = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"

type vector struct {
	Context   string `json:"context"`
	KeyID     string `json:"keyId"`
	PublicKey string `json:"publicKey"`
	Body      string `json:"body"`
	Signature string `json:"signature"`
	Expect    struct {
		OperationID string   `json:"operationId"`
		ServerID    string   `json:"serverId"`
		Type        string   `json:"type"`
		Include     []string `json:"include"`
		NotAfterMs  string   `json:"notAfterMs"`
	} `json:"expect"`
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func readVector(t *testing.T, name string) vector {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "test", "vectors", name))
	if err != nil {
		t.Fatal(err)
	}
	var v vector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestRFC8032Vector2(t *testing.T) {
	key := ed25519.NewKeyFromSeed(unhex(t, testSeed))
	sig := ed25519.Sign(key, []byte{0x72})
	want := "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da" +
		"085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
	if hex.EncodeToString(sig) != want {
		t.Fatalf("подпись %x не равна вектору RFC 8032", sig)
	}
}

// Подписано панелью (TS): подпись проверяется, тело разбирается в те же значения.
func TestVectorFromPanel(t *testing.T) {
	v := readVector(t, "ts-signed.json")
	keys := []PanelKey{{ID: v.KeyID, PublicKey: unhex(t, v.PublicKey)}}
	body, sig := unhex(t, v.Body), unhex(t, v.Signature)
	if err := Signature(keys, v.KeyID, ContextOperation, body, sig); err != nil {
		t.Fatalf("подпись панели не принята: %v", err)
	}
	if Signature(keys, v.KeyID, ContextConfirm, body, sig) == nil {
		t.Fatal("подпись операции принята как подпись подтверждения")
	}
	var op agentv1.OperationBody
	if err := proto.Unmarshal(body, &op); err != nil {
		t.Fatal(err)
	}
	inv := op.GetParams().GetSystemInventory()
	if op.GetOperationId() != v.Expect.OperationID || op.GetServerId() != v.Expect.ServerID ||
		op.GetType() != v.Expect.Type || inv == nil || len(inv.GetInclude()) != len(v.Expect.Include) {
		t.Fatalf("тело разобрано не так: %v", &op)
	}
	for i, k := range inv.GetInclude() {
		if "INVENTORY_KIND_"+v.Expect.Include[i] != k.String() {
			t.Fatalf("include[%d] = %s", i, k)
		}
	}
}

func TestRejects(t *testing.T) {
	key := ed25519.NewKeyFromSeed(unhex(t, testSeed))
	pub := key.Public().(ed25519.PublicKey)
	body := []byte("body")
	sig := ed25519.Sign(key, Input(ContextOperation, body))
	keys := []PanelKey{{ID: "k", PublicKey: pub}}
	cases := map[string]func() error{
		"нет ключей":       func() error { return Signature(nil, "k", ContextOperation, body, sig) },
		"чужой key_id":     func() error { return Signature(keys, "x", ContextOperation, body, sig) },
		"изменённое тело":  func() error { return Signature(keys, "k", ContextOperation, []byte("bodY"), sig) },
		"короткая подпись": func() error { return Signature(keys, "k", ContextOperation, body, sig[:63]) },
		"ключ не 32 байта": func() error {
			return Signature([]PanelKey{{ID: "k", PublicKey: pub[:31]}}, "k", ContextOperation, body, sig)
		},
	}
	for name, fn := range cases {
		if fn() == nil {
			t.Errorf("%s: принято", name)
		}
	}
	if err := Signature(keys, "k", ContextOperation, body, sig); err != nil {
		t.Fatal(err)
	}
}

// Подписано агентом-стороной Go: файл читает тест панели (TS). Ed25519 и сериализация детерминированы — файл
// не меняется, пока не меняется код; -update переписывает его.
func TestGoSignedVector(t *testing.T) {
	key := ed25519.NewKeyFromSeed(unhex(t, testSeed))
	nonce := make([]byte, 16)
	for i := range nonce {
		nonce[i] = byte(16 - i)
	}
	op := &agentv1.OperationBody{
		OperationId: "01a1f4b7-0000-7000-8000-000000000001",
		ServerId:    "01a1f4b7-0000-7000-8000-000000000002",
		Type:        "system.info",
		Params: &agentv1.OperationParams{
			Params: &agentv1.OperationParams_SystemInfo{SystemInfo: &agentv1.SystemInfoParams{}},
		},
		Nonce:      nonce,
		NotAfterMs: 1_795_000_600_000,
		Rollback:   agentv1.RollbackKind_ROLLBACK_KIND_NONE,
		IssuedAtMs: 1_795_000_300_000,
	}
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(op)
	if err != nil {
		t.Fatal(err)
	}
	var v vector
	v.Context = ContextOperation
	v.KeyID = "test-op-key"
	v.PublicKey = hex.EncodeToString(key.Public().(ed25519.PublicKey))
	v.Body = hex.EncodeToString(body)
	v.Signature = hex.EncodeToString(ed25519.Sign(key, Input(ContextOperation, body)))
	v.Expect.OperationID, v.Expect.ServerID, v.Expect.Type = op.OperationId, op.ServerId, op.Type
	v.Expect.Include = []string{}
	v.Expect.NotAfterMs = "1795000600000"
	out, _ := json.MarshalIndent(v, "", "  ")
	out = append(out, '\n')
	path := filepath.Join("..", "..", "test", "vectors", "go-signed.json")
	if *update {
		if err := os.WriteFile(path, out, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(out) {
		t.Fatal("test/vectors/go-signed.json устарел: go test ./internal/verify -run TestGoSignedVector -update")
	}
}
