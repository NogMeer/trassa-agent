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

// scriptWithKeys — копия install.sh с ключами keys вместо пустого списка.
func scriptWithKeys(t *testing.T, keys string) string {
	raw, err := os.ReadFile(script)
	if err != nil {
		t.Fatal(err)
	}
	s := strings.Replace(string(raw), "\nTRASSA_RELEASE_KEYS=\"\"\n", "\nTRASSA_RELEASE_KEYS=\""+keys+"\"\n", 1)
	if s == string(raw) {
		t.Fatal("в install.sh нет строки TRASSA_RELEASE_KEYS=\"\"")
	}
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
