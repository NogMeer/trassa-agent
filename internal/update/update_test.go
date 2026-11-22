// SPDX-License-Identifier: AGPL-3.0-only

package update

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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
	// Ключи выпуска зашиты (OPS-10): 1–2 ключа (R12), каждый разбирается.
	if n := len(ReleaseKeys); n < 1 || n > 2 {
		t.Fatalf("ключей выпуска %d, нужно 1–2", n)
	}
	if _, err := NewVerifier(ReleaseKeys); err != nil {
		t.Fatalf("зашитые ключи выпуска не разбираются: %v", err)
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

func TestReadStaged(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "ok"), []byte("data"), 0o600)
	if b, err := ReadStaged(dir, "ok", 10); err != nil || string(b) != "data" {
		t.Fatalf("%q %v", b, err)
	}
	if _, err := ReadStaged(dir, "ok", 3); err == nil {
		t.Fatal("больше предела принято")
	}
	secret := filepath.Join(t.TempDir(), "secret")
	_ = os.WriteFile(secret, []byte("s"), 0o600)
	_ = os.Symlink(secret, filepath.Join(dir, "link"))
	if _, err := ReadStaged(dir, "link", 10); err == nil {
		t.Fatal("ссылка на файл прочитана")
	}
	linkDir := filepath.Join(t.TempDir(), "d")
	_ = os.Symlink(dir, linkDir)
	if _, err := ReadStaged(linkDir, "ok", 10); err == nil {
		t.Fatal("каталог-ссылка прочитан")
	}
	_ = os.Mkdir(filepath.Join(dir, "sub"), 0o700)
	if _, err := ReadStaged(dir, "sub", 10); err == nil {
		t.Fatal("каталог прочитан как файл")
	}
	if _, err := ReadStaged(dir, "../ok", 10); err == nil {
		t.Fatal("путь с .. принят")
	}
}

func TestStage(t *testing.T) {
	files := map[string][]byte{"SHA256SUMS.minisig": []byte("sig"), "SHA256SUMS": []byte("sums"), "trassa-agent-linux-amd64": []byte("bin")}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, ok := files[filepath.Base(r.URL.Path)]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(b)
	}))
	defer srv.Close()
	dir := filepath.Join(t.TempDir(), "stage")
	err := Stage(context.Background(), srv.Client(), srv.URL+"/v/SHA256SUMS.minisig",
		map[string]string{"trassa-agent-linux-amd64": srv.URL + "/v/trassa-agent-linux-amd64"}, dir)
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range files {
		if b, err := ReadStaged(dir, name, 100); err != nil || !bytes.Equal(b, want) {
			t.Fatalf("%s: %q %v", name, b, err)
		}
	}
	if err := Stage(context.Background(), srv.Client(), srv.URL+"/v/SHA256SUMS.minisig",
		map[string]string{"../evil": srv.URL + "/v/x"}, dir); err == nil {
		t.Fatal("имя с путём принято")
	}
	if err := Stage(context.Background(), srv.Client(), strings.Replace(srv.URL, "https", "http", 1)+"/v/SHA256SUMS.minisig", nil, dir); err == nil {
		t.Fatal("http принят")
	}
}
