// SPDX-License-Identifier: AGPL-3.0-only

package backup

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fake — поддельный restic: подкоманда — первый аргумент после глобальных опций; ответ — файлы <sub>.out
// (stdout), <sub>.err (stderr), <sub>.code (код), <sub>.sh (действия на месте, позиционные аргументы те же).
// Каждый вызов дописывается в calls, окружение — в env.<sub>.
type fake struct {
	t   *testing.T
	dir string
	bin string
}

func newFake(t *testing.T) *fake {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "restic")
	script := `#!/bin/sh
D='` + dir + `'
sub=""
skip=0
for a in "$@"; do
	if [ $skip = 1 ]; then skip=0; continue; fi
	case "$a" in
		--json) ;;
		-o|--limit-upload) skip=1 ;;
		*) sub="$a"; break ;;
	esac
done
printf '%s\n' "$*" >> "$D/calls"
env | sort > "$D/env.$sub"
if [ -f "$D/$sub.sh" ]; then . "$D/$sub.sh"; fi
if [ -f "$D/$sub.out" ]; then cat "$D/$sub.out"; fi
if [ -f "$D/$sub.err" ]; then cat "$D/$sub.err" >&2; fi
exit $(cat "$D/$sub.code" 2>/dev/null || echo 0)
`
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return &fake{t: t, dir: dir, bin: bin}
}

func (f *fake) on(sub, out string, code int, extra ...string) {
	f.t.Helper()
	write := func(name, s string) {
		if err := os.WriteFile(filepath.Join(f.dir, name), []byte(s), 0o644); err != nil {
			f.t.Fatal(err)
		}
	}
	write(sub+".out", out)
	write(sub+".code", itoa(code))
	if len(extra) > 0 {
		write(sub+".sh", extra[0])
	}
	if len(extra) > 1 {
		write(sub+".err", extra[1])
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func (f *fake) calls() []string {
	raw, _ := os.ReadFile(filepath.Join(f.dir, "calls"))
	return strings.Split(strings.TrimSpace(string(raw)), "\n")
}

func (f *fake) env(sub string) string {
	raw, _ := os.ReadFile(filepath.Join(f.dir, "env."+sub))
	return string(raw)
}

// restic — Restic поверх поддельного бинарника с паролем в файле.
func (f *fake) restic(url string, env map[string]string) *Restic {
	f.t.Helper()
	pw := filepath.Join(f.dir, "password")
	if err := os.WriteFile(pw, []byte("correct horse battery"), 0o600); err != nil {
		f.t.Fatal(err)
	}
	return &Restic{
		Bin: f.bin, CacheDir: filepath.Join(f.dir, "cache"), Repo: &Repo{URL: url, Password: []byte("correct horse battery"), Env: env},
		PasswordFile: pw, SSHKey: filepath.Join(f.dir, "id_ed25519"), KnownHosts: filepath.Join(f.dir, "known_hosts"),
	}
}

func sha256hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
