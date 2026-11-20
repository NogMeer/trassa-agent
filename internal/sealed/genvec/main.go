// SPDX-License-Identifier: AGPL-3.0-only

// genvec — вектор HPKE Go → TS для панели (test/vectors/hpke-go.json). Ключ вектора — тестовый, только для
// проверки совместимости. Запуск: go run ./internal/sealed/genvec > test/vectors/hpke-go.json
package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"

	"github.com/NogMeer/trassa-agent/internal/sealed"
)

func main() {
	priv, _ := hex.DecodeString("a8abababababababababababababababababababababababababababababab6b")
	k, err := sealed.FromBytes(priv)
	if err != nil {
		panic(err)
	}
	type vec struct {
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
	var out []vec
	for _, c := range []struct{ field, pt string }{{"password", "correct horse battery staple"}, {"env:AWS_SECRET_ACCESS_KEY", "example-s3-secret-for-hpke-vector"}} {
		v := vec{Comment: "HPKE RFC 9180 DHKEM(X25519,HKDF-SHA256)/HKDF-SHA256/AES-256-GCM, одноразовый Seal; тестовый ключ",
			PrivateKey: hex.EncodeToString(priv), PublicKey: base64.StdEncoding.EncodeToString(k.Public()), Kid: k.ID,
			ServerID: "01a1f4b6-f327-7a5d-ac23-e95c272c0fe8", OperationID: "01a1f4b6-f2f2-7e66-85b4-000000000123", Type: "backup.init",
			PlanID: "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b", Field: c.field, Plaintext: c.pt}
		info := sealed.Info(v.ServerID, v.Kid, v.OperationID, v.Type, v.PlanID, v.Field)
		v.InfoHex = hex.EncodeToString(info)
		s, err := sealed.Seal(k.Public(), info, []byte(c.pt))
		if err != nil {
			panic(err)
		}
		v.EncCtB64 = base64.StdEncoding.EncodeToString(s.GetEncCt())
		out = append(out, v)
	}
	e := json.NewEncoder(os.Stdout)
	e.SetIndent("", "  ")
	e.SetEscapeHTML(false)
	_ = e.Encode(out)
}
