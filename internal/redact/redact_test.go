// SPDX-License-Identifier: AGPL-3.0-only

package redact

import (
	"strings"
	"testing"
)

// Словарь подложенных секретов: ни один не должен дойти до вывода. Значения синтетические.
var secrets = []struct{ name, in, secret string }{
	{"trassa enrollment", "token trs_enr_AbCdEfGhIjKlMnOpQrStUvWxYz012345", "AbCdEfGhIjKlMnOpQrStUvWxYz012345"},
	{"github pat", "GITHUB ghp_0123456789abcdefghijklmnopqrstuvwxyzAB", "ghp_0123456789abcdefghij"},
	{"github fine", "github_pat_11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyz0123456789", "github_pat_11ABCDEFG"},
	{"gitlab", "glpat-abcdefghij0123456789", "glpat-abcdefghij0123456789"},
	{"slack", "xoxb-1234567890-abcdefghij", "xoxb-1234567890"},
	{"aws key", "AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE"},
	{"aws secret", "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "wJalrXUtnFEMI"},
	{"google", "key=AIzaSyA-0123456789abcdefghijklmnopqrstu", "AIzaSyA-0123456789"},
	{"stripe", "sk_live_0123456789abcdefABCDEF", "sk_live_0123456789"},
	{"anthropic", "ANTHROPIC sk-ant-api03-abcdefghijklmnopqrstuvwxyz", "sk-ant-api03"},
	{"openai", "sk-proj-abcdefghijklmnopqrstuvwxyz0123", "abcdefghijklmnopqrstuvwxyz0123"},
	{"jwt", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U", "dozjgNryP4J3"},
	{"telegram", "bot 123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsawQ", "AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsawQ"},
	{"bearer", "Authorization: Bearer abc.def.ghi-long-opaque", "abc.def.ghi-long-opaque"},
	{"basic", "authorization=basic dXNlcjpwYXNz", "dXNlcjpwYXNz"},
	{"url creds", "postgres://app:S3cr3tP4ss@db:5432/app", "S3cr3tP4ss"},
	{"env password", "DB_PASSWORD=hunter2hunter2", "hunter2hunter2"},
	{"yaml secret", "client_secret: \"s3cr3t-value\"", "s3cr3t-value"},
	{"json token", `{"api_key": "abcd1234efgh5678"}`, "abcd1234efgh5678"},
	{"pem inline", "-----BEGIN RSA PRIVATE KEY-----MIIEpAIBAAKCAQEA-----END RSA PRIVATE KEY-----", "MIIEpAIBAAKCAQEA"},
}

func TestString(t *testing.T) {
	for _, s := range secrets {
		out := String(s.in)
		if strings.Contains(out, s.secret) {
			t.Errorf("%s: секрет остался: %q", s.name, out)
		}
		if !strings.Contains(out, Mask) {
			t.Errorf("%s: нет метки: %q", s.name, out)
		}
	}
}

func TestCryptHashes(t *testing.T) {
	for _, in := range []string{
		"/etc/shadow:root:$y$j9T$abcdefghijklmnop$QRSTUVWXYZ0123456789abcdefghijklmnopqrs:19700:0:99999:7:::",
		"u:$6$saltsalt$0123456789abcdefABCDEF0123456789abcdefABCDEF:19000::::::",
		"$2b$12$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234",
	} {
		if out := String(in); strings.Contains(out, "0123456789") || strings.Contains(out, "QRSTUV") || !strings.Contains(out, Mask) {
			t.Errorf("%q → %q", in, out)
		}
	}
}

// Конфигурация nginx (config.read, E20): заголовки без «:» и «=».
func TestWebServerHeaders(t *testing.T) {
	for in, secret := range map[string]string{
		`proxy_set_header Authorization "Bearer abcdefghijklmnop";`: "abcdefghijklmnop",
		`proxy_set_header X-Api-Key s3cr3tvalue1234;`:               "s3cr3tvalue1234",
		`  add_header Set-Cookie "session=qwertyuiop12";`:           "qwertyuiop12",
		`fastcgi_param DB_PASSWORD hunter2hunter2;`:                 "hunter2hunter2",
		`RequestHeader set X-Auth-Token "zxcvbnm098765"`:            "zxcvbnm098765",
	} {
		if out := String(in); strings.Contains(out, secret) || !strings.Contains(out, Mask) {
			t.Errorf("%q → %q", in, out)
		}
	}
	for _, keep := range []string{`proxy_set_header Host $host;`, `add_header Strict-Transport-Security "max-age=31536000";`,
		`fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;`} {
		if String(keep) != keep {
			t.Errorf("испорчено: %q → %q", keep, String(keep))
		}
	}
}

func TestKeepsHarmless(t *testing.T) {
	for _, s := range []string{
		"nginx.service active running",
		"Listening on 0.0.0.0:443",
		"https://example.com/path?x=1",
		"tokens processed: 42",
	} {
		if String(s) != s {
			t.Errorf("испорчено: %q → %q", s, String(s))
		}
	}
	if got := String("password_hint is shown"); got != "password_hint is shown" {
		t.Errorf("без значения: %q", got)
	}
}

func TestMultilinePEM(t *testing.T) {
	in := "before\n-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\nAAAAbm9uZQ==\n-----END OPENSSH PRIVATE KEY-----\nafter"
	out := Text(in)
	if strings.Contains(out, "b3BlbnNzaC1rZXktdjEAAAAA") || strings.Contains(out, "AAAAbm9uZQ") {
		t.Fatalf("тело ключа осталось: %q", out)
	}
	if !strings.Contains(out, "before") || !strings.Contains(out, "after") || !strings.Contains(out, Mask) {
		t.Fatalf("%q", out)
	}
	// Блок разорван между кусками вывода.
	var l Lines
	var got []string
	for _, line := range strings.Split(in, "\n") {
		if v, ok := l.Line(line); ok {
			got = append(got, v)
		}
	}
	if strings.Contains(strings.Join(got, "\n"), "AAAAbm9uZQ") {
		t.Fatal("кусковая обработка пропустила тело ключа")
	}
}
