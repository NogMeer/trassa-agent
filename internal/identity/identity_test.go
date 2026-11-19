// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/NogMeer/trassa-agent/internal/fsutil"
)

func TestGenerateLoadSign(t *testing.T) {
	p := filepath.Join(t.TempDir(), "agent.key")
	id, err := Generate(p, fsutil.Keep)
	if err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(p)
	if st.Mode().Perm() != 0o600 || st.Size() != 32 {
		t.Fatalf("права %v, размер %d", st.Mode().Perm(), st.Size())
	}
	if _, err := Generate(p, fsutil.Keep); err == nil {
		t.Fatal("существующий ключ перезаписан")
	}
	loaded, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.PublicKey().Equal(id.PublicKey()) {
		t.Fatal("ключ после чтения другой")
	}
	nonce := make([]byte, 32)
	sig, err := loaded.SignChallenge(nonce, "srv")
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(id.PublicKey(), append(append([]byte("trassa-agent-auth-v1"), nonce...), "srv"...), sig) {
		t.Fatal("подпись рукопожатия не сошлась")
	}
	if _, err := loaded.SignChallenge(make([]byte, 31), "srv"); err == nil {
		t.Fatal("подписан nonce не из 32 байт")
	}
}

func TestLoadRejectsInsecure(t *testing.T) {
	p := filepath.Join(t.TempDir(), "agent.key")
	if _, err := Generate(p, fsutil.Keep); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); !errors.Is(err, ErrKeyInsecure) {
		t.Fatalf("ключ 0640 принят: %v", err)
	}
	short := filepath.Join(t.TempDir(), "short.key")
	if err := os.WriteFile(short, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(short); err == nil {
		t.Fatal("короткий ключ принят")
	}
}
