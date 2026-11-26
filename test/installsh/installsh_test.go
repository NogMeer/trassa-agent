// SPDX-License-Identifier: AGPL-3.0-only

// Package installsh проверяет функции scripts/install.sh: подпись minisign через openssl (decisions п. 9) на тех же
// подписях, что принимает internal/update, контрольные суммы и совпадение встроенных юнитов с packaging/systemd.
package installsh

import (
	"bytes"
	"crypto/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"aead.dev/minisign"

	"github.com/NogMeer/trassa-agent/internal/update"
)

var script = filepath.Join("..", "..", "scripts", "install.sh")

func requireOpenSSL3(t *testing.T) {
	out, err := exec.Command("openssl", "version").Output()
	if err != nil {
		t.Skip("нет openssl: проверка подписи скрипта требует OpenSSL 3 (есть на всех целевых ОС и в CI)")
	}
	v := strings.Fields(string(out))
	if len(v) < 2 || v[0] != "OpenSSL" || v[1] < "3" {
		t.Skipf("нужен OpenSSL 3, здесь %q", strings.TrimSpace(string(out)))
	}
}

// lib запускает функцию скрипта в sh с ключами keys.
func lib(t *testing.T, keys, call string) error {
	t.Helper()
	abs, err := filepath.Abs(script)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(shell(), "-c", `TRASSA_INSTALL_LIB=1; . "$0"; TRASSA_RELEASE_KEYS="$1"; `+call, abs, keys)
	cmd.Dir = t.TempDir()
	out, err := cmd.CombinedOutput()
	if err != nil && len(out) > 0 {
		t.Logf("sh: %s", out)
	}
	return err
}

func pubText(t *testing.T, pk minisign.PublicKey) string {
	b, err := pk.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	return lines[len(lines)-1]
}

func signHashed(priv minisign.PrivateKey, msg []byte, comment string) []byte {
	r := minisign.NewReader(bytes.NewReader(msg))
	buf := make([]byte, 4096)
	for {
		if _, err := r.Read(buf); err != nil {
			break
		}
	}
	return r.SignWithComments(priv, comment, "untrusted")
}

func write(t *testing.T, dir, name string, b []byte) string {
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestVerifyMinisig(t *testing.T) {
	requireOpenSSL3(t)
	pub, priv, _ := minisign.GenerateKey(rand.Reader)
	otherPub, otherPriv, _ := minisign.GenerateKey(rand.Reader)
	keys := pubText(t, otherPub) + " " + pubText(t, pub)
	dir := t.TempDir()
	sums := []byte("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef  trassa-agent-linux-amd64\n")
	f := write(t, dir, "SHA256SUMS", sums)
	good := signHashed(priv, sums, "trassa-agent 1.2.3")
	sig := write(t, dir, "good.minisig", good)

	// Та же подпись проходит Go-проверку обновления.
	v, _ := update.NewVerifier([]string{pubText(t, pub)})
	if err := v.VerifySums(sums, good, "1.2.3"); err != nil {
		t.Fatalf("Go-проверка: %v", err)
	}
	if err := lib(t, keys, `verify_minisig "`+f+`" "`+sig+`" 1.2.3`); err != nil {
		t.Fatalf("верная подпись отклонена: %v", err)
	}
	bad := map[string]func() (keys, file, sig, version string){
		"другая версия": func() (string, string, string, string) { return keys, f, sig, "1.2.4" },
		"изменённый файл": func() (string, string, string, string) {
			return keys, write(t, dir, "mod", append(append([]byte{}, sums...), 'x')), sig, "1.2.3"
		},
		"чужой ключ": func() (string, string, string, string) { return pubText(t, otherPub), f, sig, "1.2.3" },
		"нет ключей": func() (string, string, string, string) { return "", f, sig, "1.2.3" },
		"подпись чужим ключом": func() (string, string, string, string) {
			return pubText(t, pub), f, write(t, dir, "other.minisig", signHashed(otherPriv, sums, "trassa-agent 1.2.3")), "1.2.3"
		},
		"без хэша (Ed)": func() (string, string, string, string) {
			return keys, f, write(t, dir, "ed.minisig", minisign.SignWithComments(priv, sums, "trassa-agent 1.2.3", "u")), "1.2.3"
		},
		"подменён комментарий": func() (string, string, string, string) {
			return keys, f, write(t, dir, "tc.minisig", bytes.Replace(good, []byte("trassa-agent 1.2.3"), []byte("trassa-agent 9.9.9"), 1)), "9.9.9"
		},
		"мусор": func() (string, string, string, string) {
			return keys, f, write(t, dir, "junk", []byte("junk\n")), "1.2.3"
		},
		"кривой ключ": func() (string, string, string, string) { return "RWnotakey", f, sig, "1.2.3" },
	}
	for name, mk := range bad {
		k, file, s, ver := mk()
		if err := lib(t, k, `verify_minisig "`+file+`" "`+s+`" `+ver); err == nil {
			t.Errorf("%s: подпись принята", name)
		}
	}
}

func TestCheckSum(t *testing.T) {
	dir := t.TempDir()
	bin := write(t, dir, "trassa-agent-linux-amd64", []byte("binary"))
	sum := update.SHA256Hex([]byte("binary"))
	sums := write(t, dir, "SHA256SUMS", []byte(sum+"  trassa-agent-linux-amd64\n"+sum+" *trassa-helper-linux-amd64\n"))
	if err := lib(t, "", `check_sum "`+sums+`" trassa-agent-linux-amd64 "`+bin+`"`); err != nil {
		t.Fatalf("верная сумма: %v", err)
	}
	if err := lib(t, "", `check_sum "`+sums+`" trassa-helper-linux-amd64 "`+bin+`"`); err != nil {
		t.Fatalf("строка со звёздочкой: %v", err)
	}
	evil := write(t, dir, "evil", []byte("evil"))
	if err := lib(t, "", `check_sum "`+sums+`" trassa-agent-linux-amd64 "`+evil+`"`); err == nil {
		t.Fatal("чужой файл принят")
	}
	if err := lib(t, "", `check_sum "`+sums+`" missing "`+bin+`"`); err == nil {
		t.Fatal("имя без строки принято")
	}
	dup := write(t, dir, "DUP", []byte(sum+"  a\n"+strings.Repeat("0", 64)+"  a\n"))
	if err := lib(t, "", `check_sum "`+dup+`" a "`+bin+`"`); err == nil {
		t.Fatal("две строки на имя приняты")
	}
}

// Список систем установщика совпадает с матрицей ОС в CI; соседние выпуски и другие системы — отказ.
func TestOSSupported(t *testing.T) {
	for _, ok := range []string{"ubuntu 22.04", "ubuntu 24.04", "ubuntu 26.04", "debian 12", "debian 13"} {
		if err := lib(t, "", "os_supported "+ok); err != nil {
			t.Errorf("%s: отказ", ok)
		}
	}
	for _, bad := range []string{"ubuntu 20.04", "ubuntu 25.10", "ubuntu 26.10", "ubuntu 26.04.1", "debian 11", "debian 14",
		"fedora 41", "ubuntu ''", "'' 26.04"} {
		if err := lib(t, "", "os_supported "+bad); err == nil {
			t.Errorf("%s: принята", bad)
		}
	}
}

// Встроенные в скрипт юниты совпадают с packaging/systemd.
func TestUnitsInSync(t *testing.T) {
	raw, err := os.ReadFile(script)
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	for _, name := range []string{"trassa-helper", "trassa-agent"} {
		want, err := os.ReadFile(filepath.Join("..", "..", "packaging", "systemd", name+".service"))
		if err != nil {
			t.Fatal(err)
		}
		marker := `cat >"$UNIT_DIR/.` + name + `.service.new" <<'UNIT'` + "\n"
		i := strings.Index(s, marker)
		if i < 0 {
			t.Fatalf("нет юнита %s в скрипте", name)
		}
		body := s[i+len(marker):]
		body = body[:strings.Index(body, "\nUNIT\n")+1]
		if body != string(want) {
			t.Fatalf("%s в install.sh разошёлся с packaging/systemd", name)
		}
	}
	if !strings.Contains(s, `TRASSA_RELEASE_KEYS=""`) && len(update.ReleaseKeys) == 0 {
		t.Fatal("ключи выпуска в скрипте и в internal/update разошлись")
	}
}

// Отказ до любых изменений: без root, без токена, с кривым адресом.
func TestMainRefusesEarly(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("тест проверяет отказ без root")
	}
	cmd := exec.Command("sh", script, "--url", "https://agents.example.com")
	cmd.Env = append(os.Environ(), "TRASSA_ENROLL_TOKEN=trs_enr_"+strings.Repeat("A", 43))
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "root") {
		t.Fatalf("без root: %v %s", err, out)
	}
}

// shell — dash, если есть (это /bin/sh в Ubuntu и Debian), иначе sh.
func shell() string {
	if p, err := exec.LookPath("dash"); err == nil {
		return p
	}
	return "sh"
}
