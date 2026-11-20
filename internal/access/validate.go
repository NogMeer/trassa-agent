// SPDX-License-Identifier: AGPL-3.0-only

// Package access — доступ к серверу (E16): доверие к CA пространства, пользователи по принципалам сертификатов,
// аварийный вход trassa-rescue, состояние и закрытие сеансов. Решения — decisions/E16-access.md.
package access

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/config"
)

// RescueUser — аварийный пользователь: sudo, вход только по короткому сертификату (access.rescue.grant).
const RescueUser = "trassa-rescue"

// MaxRescueTTL — предел выдачи trassa-rescue от issued_at_ms операции.
const MaxRescueTTL = 30 * time.Minute

// ErrUserForbidden — имя занято системой или Trassa (ACCESS_UNIX_USER_FORBIDDEN).
var ErrUserForbidden = errors.New("ACCESS_UNIX_USER_FORBIDDEN")

var (
	userRe      = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
	principalRe = regexp.MustCompile(`^trassa:[A-Za-z0-9-]{1,64}:[A-Za-z0-9-]{1,64}$`)
	rescueRe    = regexp.MustCompile(`^trassa:[A-Za-z0-9-]{1,64}:rescue:[A-Za-z0-9-]{1,64}$`)
	fpRe        = regexp.MustCompile(`^SHA256:[A-Za-z0-9+/]{43}$`)
	keyIDRe     = regexp.MustCompile(`^trassa:[A-Za-z0-9-]{1,64}:[A-Za-z0-9-]{1,64}:[0-9]{1,20}$`)
)

// forbiddenUsers — системные и служебные имена: доступ ими не управляет.
var forbiddenUsers = map[string]bool{
	"root": true, "daemon": true, "bin": true, "sys": true, "sync": true, "games": true, "man": true, "lp": true,
	"mail": true, "news": true, "uucp": true, "proxy": true, "www-data": true, "backup": true, "list": true,
	"irc": true, "gnats": true, "nobody": true, "systemd-network": true, "systemd-resolve": true, "messagebus": true,
	"sshd": true, "syslog": true, "_apt": true, "ubuntu": true, "debian": true, "admin": true, "postgres": true,
	"mysql": true, "docker": true,
}

// CheckUser — имя управляемого пользователя: не системное, не Trassa (trassa*), не аварийный.
func CheckUser(u string) error {
	if !userRe.MatchString(u) || forbiddenUsers[u] || strings.HasPrefix(u, "trassa") || u == config.UserName {
		return fmt.Errorf("%w: %q", ErrUserForbidden, u)
	}
	return nil
}

// ParseCA — ключ CA: одна строка «ssh-ed25519 AAAA…» без опций; отпечаток SHA256.
func ParseCA(line string) (ssh.PublicKey, string, error) {
	if strings.ContainsAny(line, "\n\r\x00") {
		return nil, "", errors.New("ключ CA: перевод строки")
	}
	k, _, opts, rest, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil || len(opts) > 0 || len(rest) > 0 {
		return nil, "", errors.New("ключ CA: не одна строка authorized_keys без опций")
	}
	if k.Type() != ssh.KeyAlgoED25519 {
		return nil, "", fmt.Errorf("ключ CA: %s, нужен ssh-ed25519", k.Type())
	}
	return k, ssh.FingerprintSHA256(k), nil
}

// ValidateTrust — sshca.trust: 1–4 разных ключа ed25519 (пустой набор — отказ, R1).
func ValidateTrust(p *agentv1.SshCaTrustParams) error {
	keys := p.GetCaPublicKeys()
	if len(keys) < 1 || len(keys) > 4 {
		return errors.New("ca_public_keys: от 1 до 4")
	}
	seen := map[string]bool{}
	for _, l := range keys {
		_, fp, err := ParseCA(l)
		if err != nil {
			return err
		}
		if seen[fp] {
			return errors.New("ca_public_keys: ключ дважды")
		}
		seen[fp] = true
	}
	return nil
}

// ValidateUntrust — sshca.untrust: 1–4 отпечатка SHA256.
func ValidateUntrust(p *agentv1.SshCaUntrustParams) error {
	fps := p.GetCaFingerprints()
	if len(fps) < 1 || len(fps) > 4 {
		return errors.New("ca_fingerprints: от 1 до 4")
	}
	for _, f := range fps {
		if !fpRe.MatchString(f) {
			return errors.New("ca_fingerprints")
		}
	}
	return nil
}

func checkPrincipals(ps []*agentv1.AccessPrincipal, re *regexp.Regexp) error {
	seen := map[string]bool{}
	for _, p := range ps {
		if !re.MatchString(p.GetName()) || seen[p.GetName()] {
			return fmt.Errorf("принципал %q", p.GetName())
		}
		seen[p.GetName()] = true
		if p.GetExpiresAtMs() < 0 {
			return errors.New("expires_at_ms")
		}
	}
	return nil
}

// ValidateUserEnsure — access.user.ensure: 1–64 принципала (снятие — access.user.remove), оболочка из списка.
func ValidateUserEnsure(p *agentv1.AccessUserEnsureParams) error {
	if err := CheckUser(p.GetUnixUser()); err != nil {
		return err
	}
	if n := len(p.GetPrincipals()); n < 1 || n > 64 {
		return errors.New("principals: от 1 до 64")
	}
	if err := checkPrincipals(p.GetPrincipals(), principalRe); err != nil {
		return err
	}
	if _, ok := shells[p.GetShell()]; !ok {
		return errors.New("shell")
	}
	return nil
}

// ValidateUserRemove — access.user.remove.
func ValidateUserRemove(p *agentv1.AccessUserRemoveParams) error { return CheckUser(p.GetUnixUser()) }

// ValidateTerminate — access.sessions.terminate: хотя бы один идентификатор, до 100.
func ValidateTerminate(p *agentv1.AccessSessionsTerminateParams) error {
	n := len(p.GetSessionIds()) + len(p.GetCertKeyIds())
	if n < 1 || n > 100 {
		return errors.New("session_ids и cert_key_ids: от 1 до 100")
	}
	for _, s := range p.GetSessionIds() {
		if !config.IsUUID(s) {
			return errors.New("session_ids")
		}
	}
	for _, k := range p.GetCertKeyIds() {
		if !keyIDRe.MatchString(k) {
			return errors.New("cert_key_ids")
		}
	}
	return nil
}

// ValidateRescueGrant — access.rescue.grant: один принципал trassa:<ws>:rescue:<grant>, срок — от выдачи
// операции до MaxRescueTTL.
func ValidateRescueGrant(p *agentv1.AccessRescueGrantParams, issuedAtMs int64) error {
	if !rescueRe.MatchString(p.GetPrincipal()) {
		return errors.New("principal")
	}
	exp := p.GetExpiresAtMs()
	if issuedAtMs <= 0 || exp <= issuedAtMs || exp-issuedAtMs > MaxRescueTTL.Milliseconds() {
		return fmt.Errorf("expires_at_ms: от выдачи операции до %s", MaxRescueTTL)
	}
	return nil
}

// shells — оболочка управляемого пользователя (путь проверяется по /etc/shells при создании).
var shells = map[agentv1.AccessShell]string{
	agentv1.AccessShell_ACCESS_SHELL_UNSPECIFIED: "/bin/bash",
	agentv1.AccessShell_ACCESS_SHELL_BASH:        "/bin/bash",
	agentv1.AccessShell_ACCESS_SHELL_SH:          "/bin/sh",
	agentv1.AccessShell_ACCESS_SHELL_ZSH:         "/usr/bin/zsh",
}
