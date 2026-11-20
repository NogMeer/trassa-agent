// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"aead.dev/minisign"

	"github.com/NogMeer/trassa-agent/internal/update"
)

func TestSign(t *testing.T) {
	pub, priv, err := minisign.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubText, _ := pub.MarshalText()
	dir := t.TempDir()
	sums := filepath.Join(dir, "SHA256SUMS")
	body := []byte("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef  trassa-agent-linux-amd64\n")
	if err := os.WriteFile(sums, body, 0o600); err != nil {
		t.Fatal(err)
	}
	// Расшифровку ключа (scrypt minisign, ~1 ГиБ памяти) делает библиотека; здесь — подпись уже открытым ключом.
	if err := sign(priv, "1.2.3", sums); err != nil {
		t.Fatal(err)
	}
	sig, err := os.ReadFile(sums + ".minisig")
	if err != nil {
		t.Fatal(err)
	}
	// Подпись принимает проверка обновления агента — с той же версией и только с ней.
	v, err := update.NewVerifier([]string{string(pubText)})
	if err != nil {
		t.Fatal(err)
	}
	if err := v.VerifySums(body, sig, "1.2.3"); err != nil {
		t.Fatalf("подпись не принята: %v", err)
	}
	if err := v.VerifySums(body, sig, "1.2.4"); err == nil {
		t.Fatal("подпись принята для другой версии")
	}

	for name, c := range map[string]struct {
		version, key, pw string
	}{
		"нет ключа":        {"1.2.3", "", ""},
		"версия с v":       {"v1.2.3", "x", "pw"},
		"ключ не minisign": {"1.2.3", "not a key", "pw"},
	} {
		if err := run(c.version, []string{sums}, c.key, c.pw); err == nil {
			t.Errorf("%s: подписано", name)
		}
	}
}
