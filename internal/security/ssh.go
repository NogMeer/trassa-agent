// SPDX-License-Identifier: AGPL-3.0-only

package security

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
)

func init() {
	register(Check{Code: "SSH_PASSWORD_AUTH", Run: checkSSHPassword})
	register(Check{Code: "ROOT_LOGIN", Run: checkRootLogin})
	register(Check{Code: "SSH_EMPTY_PASSWORDS", Run: sshFlag("permitemptypasswords", "yes", "разрешён вход с пустым паролем")})
	register(Check{Code: "SSH_FORWARDING", Run: sshFlag("x11forwarding", "yes", "включена пересылка X11")})
	register(Check{Code: "SSH_DEFAULT_PORT", Run: checkSSHPort})
	register(Check{Code: "SSH_WEAK_CRYPTO", Run: checkSSHCrypto})
	register(Check{Code: "SSH_MAX_AUTH_TRIES", Run: checkSSHTries})
	register(Check{Code: "SSH_CONFIG_PERMS", Run: checkSSHPerms})
	register(Check{Code: "SSH_NO_KEYS", Run: checkSSHNoKeys})
	register(Check{Code: "SSH_WEAK_USER_KEYS", Run: checkSSHUserKeys})
	snapshotParts = append(snapshotParts, func(ctx context.Context, s *Scan, res *agentv1.SecurityScanResult) {
		if e, err := s.SSH(ctx); err == nil {
			res.Ssh = e
		}
	})
}

// sshKeys — ключи `sshd -T`, которые уходят в снимок и нужны проверкам (в нижнем регистре, как печатает sshd).
var sshKeys = []string{
	"port", "listenaddress", "passwordauthentication", "kbdinteractiveauthentication", "challengeresponseauthentication",
	"permitrootlogin", "permitemptypasswords", "maxauthtries", "logingracetime", "x11forwarding", "pubkeyauthentication",
	"usepam", "kexalgorithms", "ciphers", "macs", "hostkeyalgorithms", "pubkeyacceptedalgorithms", "authorizedkeysfile",
	"allowtcpforwarding", "permituserenvironment",
}

// SSH — действующие настройки по `sshd -T` (глобальные; блоки Match для отдельных подключений сюда не входят).
func (s *Scan) SSH(ctx context.Context) (*agentv1.SshEffective, error) {
	s.mu.Lock()
	if s.ssh != nil || s.sshErr != nil {
		defer s.mu.Unlock()
		return s.ssh, s.sshErr
	}
	s.mu.Unlock()
	e, err := readSSH(ctx, s.sys)
	s.mu.Lock()
	s.ssh, s.sshErr = e, err
	s.mu.Unlock()
	return e, err
}

func readSSH(ctx context.Context, sys *System) (*agentv1.SshEffective, error) {
	out, err := sys.run(ctx, "sshd", "-T")
	if err != nil {
		return nil, fmt.Errorf("sshd -T: %w", err)
	}
	return parseSSHD(out, func() bool {
		o, _ := sys.run(ctx, "systemctl", "is-enabled", "ssh.socket")
		a, _ := sys.run(ctx, "systemctl", "is-active", "ssh.socket")
		return strings.TrimSpace(string(o)) == "enabled" || strings.TrimSpace(string(a)) == "active"
	}()), nil
}

func parseSSHD(out []byte, socket bool) *agentv1.SshEffective {
	known := map[string]bool{}
	for _, k := range sshKeys {
		known[k] = true
	}
	e := &agentv1.SshEffective{Settings: map[string]string{}, SocketActivated: socket}
	for _, l := range strings.Split(string(out), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(l), " ")
		if !ok || !known[k] {
			continue
		}
		// Port и ListenAddress повторяются: значения складываются.
		if k == "port" {
			if p, err := strconv.ParseUint(v, 10, 16); err == nil {
				e.Ports = append(e.Ports, uint32(p))
			}
		}
		if cur, dup := e.Settings[k]; dup {
			e.Settings[k] = cur + " " + v
		} else {
			e.Settings[k] = v
		}
	}
	return e
}

func sshOr(ctx context.Context, s *Scan) (*agentv1.SshEffective, []Finding) {
	e, err := s.SSH(ctx)
	if err != nil {
		if _, serr := os.Stat(s.sys.path("/usr/sbin/sshd")); os.IsNotExist(serr) {
			return nil, []Finding{na("сервер SSH не установлен")}
		}
		return nil, []Finding{failed(ErrReadFailed, err)}
	}
	return e, nil
}

func sshFlag(key, bad, msg string) func(context.Context, *Scan) []Finding {
	return func(ctx context.Context, s *Scan) []Finding {
		e, f := sshOr(ctx, s)
		if f != nil {
			return f
		}
		if e.GetSettings()[key] == bad {
			return []Finding{fail("", msg+" ("+key+" "+bad+")")}
		}
		return nil
	}
}

func checkSSHPassword(ctx context.Context, s *Scan) []Finding {
	e, f := sshOr(ctx, s)
	if f != nil {
		return f
	}
	st := e.GetSettings()
	switch {
	case st["passwordauthentication"] == "yes":
		return []Finding{fail("", "вход по паролю разрешён (passwordauthentication yes)")}
	case st["kbdinteractiveauthentication"] == "yes" && st["usepam"] == "yes":
		return []Finding{fail("", "пароль принимается через PAM (kbdinteractiveauthentication yes)")}
	}
	return nil
}

func checkRootLogin(ctx context.Context, s *Scan) []Finding {
	e, f := sshOr(ctx, s)
	if f != nil {
		return f
	}
	// prohibit-password (он же without-password), forced-commands-only и no не пускают root по паролю.
	if v := e.GetSettings()["permitrootlogin"]; v == "yes" {
		return []Finding{fail("", "root может входить по SSH с паролем (permitrootlogin yes)")}
	}
	return nil
}

func checkSSHPort(ctx context.Context, s *Scan) []Finding {
	e, f := sshOr(ctx, s)
	if f != nil {
		return f
	}
	for _, p := range e.GetPorts() {
		if p == 22 {
			return []Finding{fail("tcp/22", "SSH слушает порт 22")}
		}
	}
	return nil
}

// Алгоритмы, которые ssh-audit отмечает как слабые (FAIL), и режимы CBC (WARN: слабый режим шифра).
var weakAlgos = map[string][]string{
	"kexalgorithms": {"diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1",
		"ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521"},
	"ciphers": {"3des-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc", "blowfish-cbc", "cast128-cbc", "arcfour", "arcfour128",
		"arcfour256", "rijndael-cbc@lysator.liu.se"},
	"macs": {"hmac-sha1", "hmac-sha1-etm@openssh.com", "hmac-sha1-96", "hmac-sha1-96-etm@openssh.com", "hmac-md5",
		"hmac-md5-etm@openssh.com", "hmac-md5-96", "hmac-md5-96-etm@openssh.com", "umac-64@openssh.com", "umac-64-etm@openssh.com"},
}

func checkSSHCrypto(ctx context.Context, s *Scan) []Finding {
	e, f := sshOr(ctx, s)
	if f != nil {
		return f
	}
	var out []Finding
	for _, k := range []string{"kexalgorithms", "ciphers", "macs"} {
		have := map[string]bool{}
		for _, a := range strings.Split(e.GetSettings()[k], ",") {
			have[a] = true
		}
		var weak []string
		for _, a := range weakAlgos[k] {
			if have[a] {
				weak = append(weak, a)
			}
		}
		if len(weak) > 0 {
			out = append(out, fail(k, k+": разрешены устаревшие "+strings.Join(weak, ", ")))
		}
	}
	return out
}

// Пороги SSH_MAX_AUTH_TRIES — решение продукта (уровень 1 CIS с пунктами в T1 не сверен).
const (
	maxAuthTries   = 4
	maxGraceSecond = 60
)

func checkSSHTries(ctx context.Context, s *Scan) []Finding {
	e, f := sshOr(ctx, s)
	if f != nil {
		return f
	}
	var out []Finding
	if n, err := strconv.Atoi(e.GetSettings()["maxauthtries"]); err == nil && n > maxAuthTries {
		out = append(out, fail("maxauthtries", fmt.Sprintf("maxauthtries %d, рекомендуется не больше %d", n, maxAuthTries)))
	}
	if n, err := strconv.Atoi(e.GetSettings()["logingracetime"]); err == nil && (n == 0 || n > maxGraceSecond) {
		out = append(out, fail("logingracetime", fmt.Sprintf("logingracetime %d с, рекомендуется не больше %d", n, maxGraceSecond)))
	}
	return out
}

func checkSSHPerms(_ context.Context, s *Scan) []Finding {
	rules := []permRule{{"/etc/ssh/sshd_config", 0o644}}
	if ents, err := os.ReadDir(s.sys.path("/etc/ssh/sshd_config.d")); err == nil {
		for _, e := range ents {
			rules = append(rules, permRule{"/etc/ssh/sshd_config.d/" + e.Name(), 0o644})
		}
	}
	if ents, err := os.ReadDir(s.sys.path("/etc/ssh")); err == nil {
		for _, e := range ents {
			n := e.Name()
			switch {
			case strings.HasPrefix(n, "ssh_host_") && strings.HasSuffix(n, "_key"):
				rules = append(rules, permRule{"/etc/ssh/" + n, 0o600})
			case strings.HasPrefix(n, "ssh_host_") && strings.HasSuffix(n, "_key.pub"):
				rules = append(rules, permRule{"/etc/ssh/" + n, 0o644})
			}
		}
	}
	return checkPerms(s, rules)
}

// authorizedKey — ключ из authorized_keys: тип, длина RSA и отпечаток SHA256 (содержимое ключа не уходит).
type authorizedKey struct {
	user, file, typ, fingerprint string
	bits                         int
}

func (s *Scan) authorizedKeys() ([]authorizedKey, error) {
	users, err := s.Users()
	if err != nil {
		return nil, err
	}
	var out []authorizedKey
	for _, u := range users {
		if !u.CanLogin() || u.Home == "" || u.Home == "/nonexistent" {
			continue
		}
		for _, name := range []string{"authorized_keys", "authorized_keys2"} {
			p := filepath.Join(u.Home, ".ssh", name)
			ls, err := s.sys.lines(p)
			if err != nil {
				continue
			}
			for _, l := range ls {
				if k, ok := parseAuthorizedKey(l); ok {
					k.user, k.file = u.Name, p
					out = append(out, k)
				}
			}
		}
	}
	return out, nil
}

var keyTypes = map[string]bool{
	"ssh-rsa": true, "ssh-dss": true, "ssh-ed25519": true, "ecdsa-sha2-nistp256": true, "ecdsa-sha2-nistp384": true,
	"ecdsa-sha2-nistp521": true, "sk-ssh-ed25519@openssh.com": true, "sk-ecdsa-sha2-nistp256@openssh.com": true,
}

// parseAuthorizedKey — строка authorized_keys: [параметры] тип ключ [комментарий]. Параметры могут содержать
// пробелы в кавычках, поэтому ищется первое поле, которое является типом ключа.
func parseAuthorizedKey(l string) (authorizedKey, bool) {
	f := strings.Fields(l)
	for i := 0; i+1 < len(f); i++ {
		if !keyTypes[f[i]] {
			continue
		}
		blob, err := base64.StdEncoding.DecodeString(f[i+1])
		if err != nil {
			return authorizedKey{}, false
		}
		sum := sha256.Sum256(blob)
		k := authorizedKey{typ: f[i], fingerprint: "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])}
		if f[i] == "ssh-rsa" {
			k.bits = rsaBits(blob)
		}
		return k, true
	}
	return authorizedKey{}, false
}

// rsaBits — длина модуля RSA из blob «string ssh-rsa, mpint e, mpint n» (RFC 4253, 6.6).
func rsaBits(blob []byte) int {
	var parts [][]byte
	for len(blob) >= 4 && len(parts) < 3 {
		n := binary.BigEndian.Uint32(blob)
		if uint64(n) > uint64(len(blob)-4) {
			return 0
		}
		parts = append(parts, blob[4:4+n])
		blob = blob[4+n:]
	}
	if len(parts) != 3 || string(parts[0]) != "ssh-rsa" {
		return 0
	}
	return new(big.Int).SetBytes(parts[2]).BitLen()
}

func checkSSHNoKeys(_ context.Context, s *Scan) []Finding {
	keys, err := s.authorizedKeys()
	if err != nil {
		return []Finding{failed(ErrReadFailed, err)}
	}
	if len(keys) == 0 {
		return []Finding{fail("", "ни у одного пользователя нет SSH-ключа")}
	}
	return []Finding{pass("", fmt.Sprintf("ключей SSH: %d", len(keys)))}
}

// checkSSHUserKeys — DSA и RSA короче 2048 бит (пороги ssh-audit: 2048 — предел, 3072 — норма).
func checkSSHUserKeys(_ context.Context, s *Scan) []Finding {
	keys, err := s.authorizedKeys()
	if err != nil {
		return []Finding{failed(ErrReadFailed, err)}
	}
	var out []Finding
	for _, k := range keys {
		sub := k.user + " " + k.fingerprint
		switch {
		case k.typ == "ssh-dss":
			out = append(out, fail(sub, k.user+": ключ DSA "+k.fingerprint+" ("+k.file+")"))
		case k.typ == "ssh-rsa" && k.bits > 0 && k.bits < 2048:
			out = append(out, fail(sub, fmt.Sprintf("%s: ключ RSA %d бит %s (%s)", k.user, k.bits, k.fingerprint, k.file)))
		}
	}
	return out
}
