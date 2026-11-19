// SPDX-License-Identifier: AGPL-3.0-only

package enroll

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/NogMeer/trassa-agent/internal/config"
)

const token = "trs_enr_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func server(t *testing.T, h http.HandlerFunc) *httptest.Server {
	s := httptest.NewTLSServer(h)
	t.Cleanup(s.Close)
	return s
}

func okHandler(gw func(host string) string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/agent/v1/enroll" {
			http.NotFound(w, r)
			return
		}
		var req Request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Token != token || len(req.ProtocolVersions) == 0 {
			w.WriteHeader(400)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"serverId": "01a1f4b6-f327-7a5d-ac23-e95c272c0fe8", "gatewayUrl": gw(r.Host), "protocolVersion": 1,
			"panelKeys": []map[string]string{{"keyId": "k1", "publicKey": base64.RawURLEncoding.EncodeToString(make([]byte, 32))}},
			"extra":     "ignored",
		})
	}
}

func TestEnrollOK(t *testing.T) {
	s := server(t, okHandler(func(h string) string { return "wss://" + h + "/agent/v1/connect" }))
	en, err := Do(context.Background(), s.Client(), s.URL, Request{Token: token, ProtocolVersions: []int{1}})
	if err != nil {
		t.Fatal(err)
	}
	if en.ServerID == "" || len(en.PanelKeys) != 1 {
		t.Fatalf("%+v", en)
	}
}

func TestEnrollGatewayElsewhere(t *testing.T) {
	s := server(t, okHandler(func(string) string { return "wss://evil.example/agent/v1/connect" }))
	_, err := Do(context.Background(), s.Client(), s.URL, Request{Token: token, ProtocolVersions: []int{1}})
	if !errors.Is(err, config.ErrEnrollmentInvalid) {
		t.Fatalf("чужой шлюз принят: %v", err)
	}
}

func TestEnrollErrors(t *testing.T) {
	s := server(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		_, _ = w.Write([]byte(`{"code":"ENROLLMENT_TOKEN_INVALID","message":"x"}`))
	})
	_, err := Do(context.Background(), s.Client(), s.URL, Request{Token: token})
	var e *Error
	if !errors.As(err, &e) || e.Code != CodeTokenInvalid || !strings.Contains(UserMessage(err), "истёк") {
		t.Fatalf("%v", err)
	}
	if _, err := Do(context.Background(), s.Client(), strings.Replace(s.URL, "https", "http", 1), Request{Token: token}); err == nil {
		t.Fatal("http принят")
	}
	if _, err := Do(context.Background(), s.Client(), s.URL, Request{Token: "trs_enr_short"}); err == nil {
		t.Fatal("кривой токен ушёл в сеть")
	}
}
