// SPDX-License-Identifier: AGPL-3.0-only

package update

import (
	"bytes"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"aead.dev/minisign"
)

func keypair(t *testing.T) (string, minisign.PrivateKey) {
	t.Helper()
	pub, priv, err := minisign.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	txt, _ := pub.MarshalText()
	return string(txt), priv
}

func readAll(r *minisign.Reader) {
	buf := make([]byte, 4096)
	for {
		if _, err := r.Read(buf); err != nil {
			return
		}
	}
}

func sign(priv minisign.PrivateKey, msg []byte, comment string) []byte {
	r := minisign.NewReader(bytes.NewReader(msg))
	readAll(r)
	return r.SignWithComments(priv, comment, "")
}

func TestVerifySums(t *testing.T) {
	pub, priv := keypair(t)
	other, otherPriv := keypair(t)
	sums := []byte("aaaa  trassa-agent-linux-amd64\n")
	v, err := NewVerifier([]string{other, pub})
	if err != nil {
		t.Fatal(err)
	}
	good := sign(priv, sums, "trassa-agent 1.2.3")
	if err := v.VerifySums(sums, good, "1.2.3"); err != nil {
		t.Fatalf("верная подпись: %v", err)
	}
	cases := map[string]func() error{
		"другая версия":   func() error { return v.VerifySums(sums, good, "1.2.4") },
		"изменённый файл": func() error { return v.VerifySums(append(sums, 'x'), good, "1.2.3") },
		"пустая подпись":  func() error { return v.VerifySums(sums, nil, "1.2.3") },
		"пустой файл":     func() error { return v.VerifySums(nil, good, "1.2.3") },
		"мусор":           func() error { return v.VerifySums(sums, []byte("garbage"), "1.2.3") },
		"без хэша (Ed)": func() error {
			return v.VerifySums(sums, minisign.SignWithComments(priv, sums, "trassa-agent 1.2.3", ""), "1.2.3")
		},
		"пустой верификатор": func() error { return (&Verifier{}).VerifySums(sums, good, "1.2.3") },
		"nil верификатор":    func() error { var nv *Verifier; return nv.VerifySums(sums, good, "1.2.3") },
	}
	onlyOther, _ := NewVerifier([]string{other})
	cases["чужой ключ"] = func() error { return onlyOther.VerifySums(sums, good, "1.2.3") }
	cases["подпись чужим ключом"] = func() error {
		pubOnly, _ := NewVerifier([]string{pub})
		return pubOnly.VerifySums(sums, sign(otherPriv, sums, "trassa-agent 1.2.3"), "1.2.3")
	}
	for name, f := range cases {
		if err := f(); !errors.Is(err, ErrSignatureInvalid) {
			t.Errorf("%s: ждали UPDATE_SIGNATURE_INVALID, получили %v", name, err)
		}
	}
	if _, err := NewVerifier(nil); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatal("пустой список ключей принят")
	}
	if _, err := NewVerifier(ReleaseKeys); len(ReleaseKeys) == 0 && err == nil {
		t.Fatal("сборка без ключей выпуска принимает обновления")
	}
}

func TestParseSums(t *testing.T) {
	h := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	m, err := ParseSums([]byte(h + "  trassa-agent-linux-amd64\n" + h + " *trassa-helper-linux-amd64\n"))
	if err != nil || len(m) != 2 {
		t.Fatalf("%v %v", m, err)
	}
	for _, bad := range []string{"", "xyz  a\n", h + "  ../evil\n", h + "  a\n" + h + "  a\n"} {
		if _, err := ParseSums([]byte(bad)); err == nil {
			t.Errorf("принято %q", bad)
		}
	}
}

func TestCompare(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"1.2.3", "1.2.3", 0}, {"1.2.3", "1.2.4", -1}, {"1.10.0", "1.9.9", 1}, {"2.0.0-rc.1", "2.0.0", -1},
		{"2.0.0", "2.0.0-rc.1", 1}, {"v1.0.0", "1.0.0", 0},
	} {
		if got, err := Compare(c.a, c.b); err != nil || got != c.want {
			t.Errorf("%s %s: %d %v", c.a, c.b, got, err)
		}
	}
	if _, err := Compare("1.2", "1.2.3"); err == nil {
		t.Fatal("кривая версия принята")
	}
}

func TestInstallRestore(t *testing.T) {
	root := t.TempDir()
	bin, prev := filepath.Join(root, "bin"), filepath.Join(root, "prev")
	_ = os.MkdirAll(bin, 0o755)
	_ = os.WriteFile(filepath.Join(bin, "trassa-agent"), []byte("old"), 0o755)
	if err := Install(bin, prev, map[string][]byte{"trassa-agent": []byte("new")}); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(bin, "trassa-agent")); string(b) != "new" {
		t.Fatal(string(b))
	}
	if err := RestorePrev(bin, prev, []string{"trassa-agent"}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(bin, "trassa-agent"))
	st, _ := os.Stat(filepath.Join(bin, "trassa-agent"))
	if string(b) != "old" || st.Mode().Perm() != 0o755 {
		t.Fatalf("%q %v", b, st.Mode().Perm())
	}
}
