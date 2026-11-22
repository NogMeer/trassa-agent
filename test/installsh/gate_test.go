// SPDX-License-Identifier: AGPL-3.0-only

package installsh

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"aead.dev/minisign"

	"github.com/NogMeer/trassa-agent/internal/update"
)

var gate = filepath.Join("..", "..", "scripts", "release-gate.sh")

var releaseFiles = []string{"trassa-agent-linux-amd64", "trassa-agent-linux-arm64", "trassa-helper-linux-amd64", "trassa-helper-linux-arm64"}

var keysLine = regexp.MustCompile(`(?m)^TRASSA_RELEASE_KEYS="[^"]*"$`)

// scriptWithKeys — копия install.sh с ключами keys вместо зашитых.
func scriptWithKeys(t *testing.T, keys string) string {
	raw, err := os.ReadFile(script)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(keysLine.FindAllIndex(raw, -1)); n != 1 {
		t.Fatalf("в install.sh должна быть ровно одна строка TRASSA_RELEASE_KEYS, найдено %d", n)
	}
	s := keysLine.ReplaceAllLiteralString(string(raw), `TRASSA_RELEASE_KEYS="`+keys+`"`)
	return write(t, t.TempDir(), "install.sh", []byte(s))
}

// dist — каталог выпуска с четырьмя бинарниками и SHA256SUMS.
func dist(t *testing.T) (string, []byte) {
	dir := t.TempDir()
	var sums strings.Builder
	for _, f := range releaseFiles {
		b := []byte("binary " + f)
		write(t, dir, f, b)
		h := sha256.Sum256(b)
		fmt.Fprintf(&sums, "%s  %s\n", hex.EncodeToString(h[:]), f)
	}
	write(t, dir, "SHA256SUMS", []byte(sums.String()))
	return dir, []byte(sums.String())
}

func runGate(t *testing.T, dir, version, installSh string) (string, error) {
	t.Helper()
	out, err := exec.Command(shell(), gate, dir, version, installSh).CombinedOutput()
	return string(out), err
}

// Выпуск без подписи не публикуется (E05-T29): шлюз отказывает при пустых ключах, без подписи, с чужой подписью,
// с другой версией и при несовпадении сумм; пропускает только подписанный и целый выпуск.
func TestReleaseGate(t *testing.T) {
	requireOpenSSL3(t)
	pub, priv, _ := minisign.GenerateKey(rand.Reader)
	_, otherPriv, _ := minisign.GenerateKey(rand.Reader)
	withKey := scriptWithKeys(t, pubText(t, pub))

	dir, sums := dist(t)
	write(t, dir, "SHA256SUMS.minisig", signHashed(priv, sums, "trassa-agent 1.2.3"))
	if out, err := runGate(t, dir, "1.2.3", withKey); err != nil {
		t.Fatalf("подписанный выпуск отклонён: %v %s", err, out)
	}

	cases := map[string]func() (dir, version, installSh string){
		"ключей нет (настоящий install.sh)": func() (string, string, string) { return dir, "1.2.3", script },
		"нет подписи": func() (string, string, string) {
			d, _ := dist(t)
			return d, "1.2.3", withKey
		},
		"подпись чужим ключом": func() (string, string, string) {
			d, s := dist(t)
			write(t, d, "SHA256SUMS.minisig", signHashed(otherPriv, s, "trassa-agent 1.2.3"))
			return d, "1.2.3", withKey
		},
		"другая версия": func() (string, string, string) { return dir, "1.2.4", withKey },
		"подменён бинарник": func() (string, string, string) {
			d, s := dist(t)
			write(t, d, "SHA256SUMS.minisig", signHashed(priv, s, "trassa-agent 1.2.3"))
			write(t, d, releaseFiles[1], []byte("evil"))
			return d, "1.2.3", withKey
		},
		"нет бинарника arm64": func() (string, string, string) {
			d := t.TempDir()
			var b strings.Builder
			for _, f := range releaseFiles[:1] {
				data := []byte("binary " + f)
				write(t, d, f, data)
				h := sha256.Sum256(data)
				fmt.Fprintf(&b, "%s  %s\n", hex.EncodeToString(h[:]), f)
			}
			write(t, d, "SHA256SUMS", []byte(b.String()))
			write(t, d, "SHA256SUMS.minisig", signHashed(priv, []byte(b.String()), "trassa-agent 1.2.3"))
			return d, "1.2.3", withKey
		},
	}
	for name, mk := range cases {
		d, v, s := mk()
		out, err := runGate(t, d, v, s)
		if err == nil {
			t.Errorf("%s: выпуск пропущен к публикации", name)
		} else if !strings.Contains(out, "не публикуется") {
			t.Errorf("%s: нет понятной причины: %s", name, out)
		}
	}
}

// Ключи выпуска в install.sh и в internal/update — один и тот же список (R12).
func TestReleaseKeysInSync(t *testing.T) {
	raw, err := os.ReadFile(script)
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^TRASSA_RELEASE_KEYS="([^"]*)"$`).FindAllStringSubmatch(string(raw), -1)
	if len(m) != 1 {
		t.Fatalf("в install.sh должна быть ровно одна строка TRASSA_RELEASE_KEYS, найдено %d", len(m))
	}
	inScript := strings.Fields(m[0][1])
	inGo := make([]string, 0, len(update.ReleaseKeys))
	for _, k := range update.ReleaseKeys {
		inGo = append(inGo, strings.TrimSpace(k))
	}
	if !slices.Equal(inScript, inGo) {
		t.Fatalf("ключи выпуска разошлись: install.sh %q, internal/update %q", inScript, inGo)
	}
}

// Настоящий вектор ключа trassa-release-1 (test/vectors/release-key-1): пробный файл подписан закрытым ключом
// выпусков (minisign -S, docs/ops/key-ceremonies.md, раздел 1, п. 3). Зашитый в install.sh и internal/update ключ
// принимает подпись, изменённый файл и чужая версия — отказ.
func TestRealReleaseKeyVector(t *testing.T) {
	requireOpenSSL3(t)
	dir := filepath.Join("..", "vectors", "release-key-1")
	probe, err := os.ReadFile(filepath.Join(dir, "probe.txt"))
	if err != nil {
		t.Fatal(err)
	}
	sig, err := os.ReadFile(filepath.Join(dir, "probe.txt.minisig"))
	if err != nil {
		t.Fatal(err)
	}
	abs, err := filepath.Abs(script)
	if err != nil {
		t.Fatal(err)
	}
	verify := func(file, version string) error {
		return exec.Command(shell(), "-c", `TRASSA_INSTALL_LIB=1; . "$0"; verify_minisig "$1" "$2" "$3"`,
			abs, file, filepath.Join(dir, "probe.txt.minisig"), version).Run()
	}
	if err := verify(filepath.Join(dir, "probe.txt"), "0.0.0-probe"); err != nil {
		t.Fatalf("install.sh не принял подпись настоящего ключа: %v", err)
	}
	if verify(filepath.Join(dir, "probe.txt"), "0.0.1-probe") == nil {
		t.Fatal("install.sh принял подпись с чужой версией")
	}
	tampered := write(t, t.TempDir(), "probe.txt", append(append([]byte{}, probe...), 'x'))
	if verify(tampered, "0.0.0-probe") == nil {
		t.Fatal("install.sh принял изменённый файл")
	}

	v, err := update.NewVerifier(update.ReleaseKeys)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.VerifySums(probe, sig, "0.0.0-probe"); err != nil {
		t.Fatalf("internal/update не принял подпись настоящего ключа: %v", err)
	}
	if v.VerifySums(append(append([]byte{}, probe...), 'x'), sig, "0.0.0-probe") == nil {
		t.Fatal("internal/update принял изменённый файл")
	}
}
