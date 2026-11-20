// SPDX-License-Identifier: AGPL-3.0-only

package security

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Фрагмент `sshd -T` Ubuntu 22.04 (ключи в нижнем регистре, Port повторяется).
const sshdT = `port 22
port 2222
addressfamily any
listenaddress [::]:22
listenaddress 0.0.0.0:22
usepam yes
logingracetime 120
maxauthtries 6
permitrootlogin yes
passwordauthentication no
kbdinteractiveauthentication no
permitemptypasswords no
x11forwarding yes
ciphers chacha20-poly1305@openssh.com,aes128-ctr,aes256-gcm@openssh.com
macs umac-64-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha1
kexalgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,ecdh-sha2-nistp256
hostkeyagent none
`

func sshBlob(typ string, parts ...[]byte) string {
	var b []byte
	put := func(x []byte) {
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(x)))
		b = append(append(b, l[:]...), x...)
	}
	put([]byte(typ))
	for _, p := range parts {
		put(p)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func rsaKey(t *testing.T, bits int) string {
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	return "ssh-rsa " + sshBlob("ssh-rsa", []byte{1, 0, 1}, append([]byte{0}, k.N.Bytes()...)) + " user@host"
}

func TestSSH(t *testing.T) {
	sys := build(t, tree{
		"etc/passwd": passwd, "etc/shadow": shadow, "usr/sbin/sshd": "",
		"home/alice/.ssh/authorized_keys": `command="echo hi there",no-pty ` + rsaKey(t, 1024) + "\n" +
			"ssh-dss " + sshBlob("ssh-dss", []byte{1}) + " old\n" +
			"ssh-ed25519 " + sshBlob("ssh-ed25519", make([]byte, 32)) + " ok\n",
		"etc/ssh/sshd_config": "", "etc/ssh/ssh_host_ed25519_key": "PRIVATE",
	})
	if err := os.Chmod(filepath.Join(sys.Root, "etc/ssh/ssh_host_ed25519_key"), 0o644); err != nil {
		t.Fatal(err)
	}
	sys.Run = func(_ context.Context, name string, args ...string) ([]byte, error) {
		switch name {
		case "sshd":
			return []byte(sshdT), nil
		case "systemctl":
			return []byte("disabled\n"), errors.New("exit 1")
		}
		return nil, errors.New("нет")
	}
	codes := []string{"SSH_PASSWORD_AUTH", "ROOT_LOGIN", "SSH_EMPTY_PASSWORDS", "SSH_FORWARDING", "SSH_DEFAULT_PORT",
		"SSH_WEAK_CRYPTO", "SSH_MAX_AUTH_TRIES", "SSH_CONFIG_PERMS", "SSH_NO_KEYS", "SSH_WEAK_USER_KEYS"}
	r := scan(t, sys, codes...)
	want := map[string]string{
		"SSH_PASSWORD_AUTH":   "PASS:",
		"ROOT_LOGIN":          "FAIL:",
		"SSH_EMPTY_PASSWORDS": "PASS:",
		"SSH_FORWARDING":      "FAIL:",
		"SSH_DEFAULT_PORT":    "FAIL:tcp/22",
		"SSH_WEAK_CRYPTO":     "FAIL:kexalgorithms,FAIL:macs",
		"SSH_MAX_AUTH_TRIES":  "FAIL:maxauthtries,FAIL:logingracetime",
		"SSH_CONFIG_PERMS":    "FAIL:/etc/ssh/ssh_host_ed25519_key",
		"SSH_NO_KEYS":         "PASS:",
	}
	for code, w := range want {
		if got := states(r[code]); got != w {
			t.Errorf("%s: %s, ждали %s", code, got, w)
		}
	}
	weak := r["SSH_WEAK_USER_KEYS"]
	if len(weak) != 2 || !strings.Contains(weak[0].GetEvidence(), "RSA 1024") || !strings.Contains(weak[1].GetEvidence(), "DSA") {
		t.Fatalf("%+v", weak)
	}
	if strings.Contains(weak[0].GetEvidence(), "AAAA") || !strings.HasPrefix(strings.Fields(weak[0].GetSubject())[1], "SHA256:") {
		t.Fatalf("ключ в evidence: %+v", weak[0])
	}
	if !strings.Contains(r["SSH_WEAK_CRYPTO"][0].GetEvidence(), "ecdh-sha2-nistp256") || strings.Contains(r["SSH_WEAK_CRYPTO"][1].GetEvidence(), "hmac-sha2-256-etm") {
		t.Fatalf("%+v", r["SSH_WEAK_CRYPTO"])
	}
	// Снимок: порты складываются, сокет выключен.
	e, _ := newScan(sys).SSH(context.Background())
	if len(e.GetPorts()) != 2 || e.GetSettings()["listenaddress"] != "[::]:22 0.0.0.0:22" || e.GetSocketActivated() {
		t.Fatalf("%+v", e)
	}
	// Без sshd — NA.
	sys2 := build(t, tree{})
	sys2.Run = func(context.Context, string, ...string) ([]byte, error) { return nil, errors.New("нет sshd") }
	if got := states(scan(t, sys2, "ROOT_LOGIN")["ROOT_LOGIN"]); got != "NA:" {
		t.Fatal(got)
	}
	if rsaBits([]byte{0, 0, 0, 9}) != 0 {
		t.Fatal("кривой blob")
	}
}

func TestTimeAndEOL(t *testing.T) {
	sys := build(t, tree{"etc/os-release": "ID=debian\nVERSION_ID=\"12\"\n"})
	sys.Adjtimex = func() (int64, error) { return 16_000_000, nil }
	sys.Run = func(context.Context, string, ...string) ([]byte, error) { return []byte("inactive"), errors.New("3") }
	sys.Now = func() time.Time { return time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC) }
	r := scan(t, sys, "TIME_SYNC_OFF", "OS_EOL")
	if states(r["TIME_SYNC_OFF"]) != "FAIL:" || states(r["OS_EOL"]) != "PASS:debian 12" {
		t.Fatalf("%s %s", states(r["TIME_SYNC_OFF"]), states(r["OS_EOL"]))
	}
	sys.Adjtimex = func() (int64, error) { return 50_000, nil }
	sys.Now = func() time.Time { return time.Date(2028, 7, 1, 0, 0, 0, 0, time.UTC) }
	r = scan(t, sys, "TIME_SYNC_OFF", "OS_EOL")
	if states(r["TIME_SYNC_OFF"]) != "PASS:" || states(r["OS_EOL"]) != "FAIL:debian 12" {
		t.Fatalf("%s %s", states(r["TIME_SYNC_OFF"]), states(r["OS_EOL"]))
	}
	// adjtimex запрещён песочницей — ответ timedatectl.
	sys.Adjtimex = func() (int64, error) { return 0, errors.New("operation not permitted") }
	sys.Run = func(_ context.Context, name string, _ ...string) ([]byte, error) {
		if name == "timedatectl" {
			return []byte("yes\n"), nil
		}
		return nil, errors.New("нет")
	}
	if got := states(scan(t, sys, "TIME_SYNC_OFF")["TIME_SYNC_OFF"]); got != "PASS:" {
		t.Fatal("timedatectl:", got)
	}
	if got := states(scan(t, build(t, tree{"etc/os-release": "ID=fedora\nVERSION_ID=40\n"}), "OS_EOL")["OS_EOL"]); got != "NA:" {
		t.Fatal(got)
	}
}
