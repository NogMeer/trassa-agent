// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/NogMeer/trassa-agent/internal/fsutil"
)

func validEnrollment() Enrollment {
	return Enrollment{
		ServerID:        "01a1f4b6-f327-7a5d-ac23-e95c272c0fe8",
		GatewayURL:      "wss://agents.example.com/agent/v1/connect",
		ProtocolVersion: 1,
		PanelKeys:       []PanelKey{{KeyID: "k1", PublicKey: base64.RawURLEncoding.EncodeToString(make([]byte, 32))}},
	}
}

func TestEnrollmentValidate(t *testing.T) {
	if keys, err := validEnrollment().Validate(); err != nil || len(keys) != 1 {
		t.Fatalf("валидная запись: %v", err)
	}
	cases := map[string]func(*Enrollment){
		"пустой server_id":       func(e *Enrollment) { e.ServerID = "" },
		"не wss":                 func(e *Enrollment) { e.GatewayURL = "ws://agents.example.com/" },
		"учётка в адресе":        func(e *Enrollment) { e.GatewayURL = "wss://u:p@agents.example.com/" },
		"нет ключей (R1)":        func(e *Enrollment) { e.PanelKeys = nil },
		"три ключа":              func(e *Enrollment) { e.PanelKeys = append(e.PanelKeys, e.PanelKeys[0], e.PanelKeys[0]) },
		"повтор kid":             func(e *Enrollment) { e.PanelKeys = append(e.PanelKeys, e.PanelKeys[0]) },
		"ключ не 32 байта":       func(e *Enrollment) { e.PanelKeys[0].PublicKey = "AAAA" },
		"чужая версия протокола": func(e *Enrollment) { e.ProtocolVersion = 2 },
	}
	for name, mut := range cases {
		e := validEnrollment()
		mut(&e)
		if _, err := e.Validate(); !errors.Is(err, ErrEnrollmentInvalid) {
			t.Errorf("%s: ждали ErrEnrollmentInvalid, получили %v", name, err)
		}
	}
}

func TestEnrollmentRoundTripAndStrict(t *testing.T) {
	p := filepath.Join(t.TempDir(), "enrollment.json")
	if err := SaveEnrollment(p, validEnrollment(), fsutil.Keep); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(p)
	if st.Mode().Perm() != 0o640 {
		t.Fatalf("права %v", st.Mode().Perm())
	}
	if _, _, err := LoadEnrollment(p); err != nil {
		t.Fatal(err)
	}
	// Неизвестное поле — отказ: нельзя подложить, например, список типов операций.
	if err := os.WriteFile(p, []byte(`{"serverId":"x","types":["exec.run"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadEnrollment(p); !errors.Is(err, ErrEnrollmentInvalid) {
		t.Fatalf("неизвестное поле принято: %v", err)
	}
}
