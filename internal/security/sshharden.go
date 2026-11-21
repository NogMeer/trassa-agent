// SPDX-License-Identifier: AGPL-3.0-only

package security

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/fsutil"
	"github.com/NogMeer/trassa-agent/internal/rollback"
)

// SSHConfigFile — файл настроек Trassa для sshd (decisions E10, п. 2): Include в начале sshd_config, файлы по
// алфавиту, побеждает первое значение — «00-» перекрывает 50-cloud-init.conf. Файлы пользователя не правятся.
const SSHConfigFile = "/etc/ssh/sshd_config.d/00-trassa.conf"

// Строгий набор алгоритмов по ssh-audit; поддерживается с OpenSSH 8.9 (самая старая на целевых ОС).
var strictCrypto = map[string]string{
	"KexAlgorithms": "sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256",
	"Ciphers":       "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr",
	"MACs":          "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com",
}

// sshdOrder — порядок строк в файле Trassa.
var sshdOrder = []string{"Port", "PasswordAuthentication", "KbdInteractiveAuthentication", "PermitRootLogin",
	"PermitEmptyPasswords", "X11Forwarding", "MaxAuthTries", "KexAlgorithms", "Ciphers", "MACs"}

// MaxSSHAuthTries — верхняя граница max_auth_tries в ssh.harden.
const MaxSSHAuthTries = 10

// ValidateSSHHarden — схема ssh.harden. Операция только ужесточает: включить пароль или пустые пароли ей нельзя
// (прежнее возвращает rollback.restore). Пустой запрос отклоняется (R1).
func ValidateSSHHarden(p *agentv1.SshHardenParams) error {
	if p.PasswordAuth != nil && p.GetPasswordAuth() {
		return errors.New("password_auth: ssh.harden только выключает вход по паролю")
	}
	if p.EmptyPasswords != nil && p.GetEmptyPasswords() {
		return errors.New("empty_passwords: ssh.harden только запрещает пустые пароли")
	}
	if p.X11Forwarding != nil && p.GetX11Forwarding() {
		return errors.New("x11_forwarding: ssh.harden только выключает пересылку X11")
	}
	if p.GetRootLogin() < agentv1.RootLogin_ROOT_LOGIN_UNSPECIFIED || p.GetRootLogin() > agentv1.RootLogin_ROOT_LOGIN_KEY_ONLY {
		return errors.New("root_login")
	}
	if p.GetCryptoPreset() < agentv1.CryptoPreset_CRYPTO_PRESET_UNSPECIFIED || p.GetCryptoPreset() > agentv1.CryptoPreset_CRYPTO_PRESET_STRICT {
		return errors.New("crypto_preset")
	}
	if p.GetPort() > 65535 {
		return errors.New("port: от 1 до 65535")
	}
	if p.GetMaxAuthTries() > MaxSSHAuthTries {
		return fmt.Errorf("max_auth_tries: от 1 до %d", MaxSSHAuthTries)
	}
	if len(targets(p)) == 0 {
		return errors.New("ни одной настройки")
	}
	return nil
}

// targets — строки sshd_config, которые задаёт запрос.
func targets(p *agentv1.SshHardenParams) map[string]string {
	t := map[string]string{}
	if p.PasswordAuth != nil {
		t["PasswordAuthentication"] = "no"
		t["KbdInteractiveAuthentication"] = "no"
	}
	if p.EmptyPasswords != nil {
		t["PermitEmptyPasswords"] = "no"
	}
	if p.X11Forwarding != nil {
		t["X11Forwarding"] = "no"
	}
	switch p.GetRootLogin() {
	case agentv1.RootLogin_ROOT_LOGIN_NO:
		t["PermitRootLogin"] = "no"
	case agentv1.RootLogin_ROOT_LOGIN_KEY_ONLY:
		t["PermitRootLogin"] = "prohibit-password"
	}
	if p.GetPort() != 0 {
		t["Port"] = strconv.Itoa(int(p.GetPort()))
	}
	if p.GetMaxAuthTries() != 0 {
		t["MaxAuthTries"] = strconv.Itoa(int(p.GetMaxAuthTries()))
	}
	if p.GetCryptoPreset() == agentv1.CryptoPreset_CRYPTO_PRESET_STRICT {
		for k, v := range strictCrypto {
			t[k] = v
		}
	}
	return t
}

// PlanSSHHarden — ssh.harden: файл Trassa с целевыми значениями (вместе с прежними значениями файла), проверки
// условий на стороне сервера, применение без разрыва сессий и сверка действующих значений `sshd -T`.
func PlanSSHHarden(ctx context.Context, sys *System, p *agentv1.SshHardenParams) (*FixPlan, error) {
	s := newScan(sys)
	cur, err := s.SSH(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPrecondition, err)
	}
	want := targets(p)
	if err := sshPreconditions(ctx, s, cur, want); err != nil {
		return nil, err
	}
	real := sys.path(SSHConfigFile)
	old, err := os.ReadFile(real)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	merged := parseSSHDConfig(string(old))
	for k, v := range want {
		merged[k] = v
	}
	content := renderSSHDConfig(merged)

	portChange := want["Port"] != ""
	socket := cur.GetSocketActivated()
	plan := &FixPlan{
		Summary:  "Настройки SSH: " + strings.Join(sortedKeys(want), ", "),
		Paths:    []string{real},
		Services: []string{"ssh.service"},
		Changes:  []*agentv1.FileChange{{Path: SSHConfigFile, Kind: changeKind(old), Diff: lineDiff(string(old), content)}},
		Notes:    []string{"Открытые сеансы SSH не прерываются"},
	}
	if portChange {
		plan.Notes = append(plan.Notes, "Новый порт "+want["Port"]+" должен быть открыт в firewall до применения")
		if socket {
			// Ubuntu 24.04: порт сокета пишет sshd-socket-generator по sshd_config (decisions E10, п. 3).
			if _, err := os.Stat(sys.path("/usr/lib/systemd/system-generators/sshd-socket-generator")); err != nil {
				return nil, fmt.Errorf("%w: SSH запущен через ssh.socket без генератора порта — порт меняется вручную (ListenStream)", ErrPrecondition)
			}
			plan.Services = []string{"ssh.socket", "ssh.service"}
			plan.State = rollback.State{DaemonReload: true}
		}
	}
	plan.Apply = func(ctx context.Context) error {
		if err := os.MkdirAll(dirOf(real), 0o755); err != nil {
			return err
		}
		if err := fsutil.WriteFileAtomic(real, []byte(content), 0o644, fsutil.Keep); err != nil {
			return err
		}
		if out, err := sys.run(ctx, "sshd", "-t"); err != nil {
			return fmt.Errorf("sshd -t: %v %s", err, tail(out))
		}
		if portChange && socket {
			if out, err := sys.run(ctx, "systemctl", "daemon-reload"); err != nil {
				return fmt.Errorf("systemctl daemon-reload: %v %s", err, tail(out))
			}
		}
		return nil // перезапуск служб — после Apply (Services); KillMode=process сеансы не трогает
	}
	plan.Verify = func(ctx context.Context) error {
		e, err := readSSH(ctx, sys)
		if err != nil {
			return err
		}
		for k, v := range want {
			key := strings.ToLower(k)
			if key == "port" {
				continue
			}
			if got := e.GetSettings()[key]; got != v {
				return fmt.Errorf("%s: действует %q, ждали %q", k, got, v)
			}
		}
		if portChange {
			n, _ := strconv.Atoi(want["Port"])
			if !contains(e.GetPorts(), uint32(n)) {
				return fmt.Errorf("sshd не слушает порт %d по настройкам", n)
			}
			ls, err := newScan(sys).Listeners(ctx)
			if err != nil {
				return err
			}
			if !listening(ls, uint32(n)) {
				return fmt.Errorf("порт %d не открыт на сервере", n)
			}
		}
		return nil
	}
	return plan, nil
}

// sshPreconditions — условия, которые панель проверяет тоже (E10, раздел 6): помощник не доверяет панели.
func sshPreconditions(ctx context.Context, s *Scan, cur *agentv1.SshEffective, want map[string]string) error {
	root := cur.GetSettings()["permitrootlogin"]
	if v, ok := want["PermitRootLogin"]; ok {
		root = v
	}
	keys, err := s.authorizedKeys()
	if err != nil {
		return err
	}
	admins, err := admins(s)
	if err != nil {
		return err
	}
	isAdmin := map[string]bool{}
	for _, a := range admins {
		isAdmin[a] = true
	}
	if root == "no" && len(admins) == 0 {
		return fmt.Errorf("%w: для запрета входа root нужен пользователь с sudo", ErrPrecondition)
	}
	// Вход по паролю после изменения: запрошенный или действующий сейчас (PAM через keyboard-interactive тоже
	// пароль). Без пароля войти можно только ключом — он нужен, даже если пароль выключили раньше.
	password := cur.GetSettings()["passwordauthentication"]
	if v, ok := want["PasswordAuthentication"]; ok {
		password = v
	}
	kbd := cur.GetSettings()["kbdinteractiveauthentication"]
	if v, ok := want["KbdInteractiveAuthentication"]; ok {
		kbd = v
	}
	if password != "yes" && kbd != "yes" {
		// Вход по сертификату пользователем с sudo (E16) — тоже вход без пароля.
		ok := s.sys.Now != nil && s.sys.accessCertAdmin(s.sys.Now())
		for _, k := range keys {
			if isAdmin[k.user] || (k.user == "root" && root != "no") {
				ok = true
			}
		}
		if !ok {
			return fmt.Errorf("%w: без пароля войти будет некому — нет ключа SSH у пользователя с sudo", ErrPrecondition)
		}
	}
	if p := want["Port"]; p != "" {
		n, _ := strconv.Atoi(p)
		ls, err := s.Listeners(ctx)
		if err != nil {
			return err
		}
		for _, l := range ls {
			if l.GetProtocol() == "tcp" && l.GetPort() == uint32(n) && l.GetProcess() != "sshd" {
				return fmt.Errorf("%w: порт %d занят процессом %s", ErrPrecondition, n, l.GetProcess())
			}
		}
		// Межсетевой экран Trassa загружен — новый порт должен быть в нём открыт, иначе после перезапуска sshd
		// новые соединения не пройдут.
		if table, err := s.sys.run(ctx, "nft", "list", "table", "inet", "trassa"); err == nil && !nftInputOpens(string(table), uint32(n)) {
			return fmt.Errorf("%w: порт %d не открыт в межсетевом экране Trassa — сначала добавьте правило", ErrPrecondition, n)
		}
	}
	return nil
}

var nftTCPAccept = regexp.MustCompile(`\btcp dport (\d+)(?:-(\d+))?\b.*\baccept\b`)

// nftInputOpens — в цепочке input таблицы Trassa (вывод `nft list table`) есть правило accept для tcp-порта.
func nftInputOpens(table string, port uint32) bool {
	in := false
	for _, l := range strings.Split(table, "\n") {
		l = strings.TrimSpace(l)
		switch {
		case strings.HasPrefix(l, "chain "):
			in = strings.HasPrefix(l, "chain input ")
			continue
		case !in:
			continue
		}
		m := nftTCPAccept.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		from, _ := strconv.ParseUint(m[1], 10, 16)
		to := from
		if m[2] != "" {
			to, _ = strconv.ParseUint(m[2], 10, 16)
		}
		if uint64(port) >= from && uint64(port) <= to {
			return true
		}
	}
	return false
}

func parseSSHDConfig(s string) map[string]string {
	m := map[string]string{}
	for _, l := range strings.Split(s, "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		if k, v, ok := strings.Cut(l, " "); ok {
			m[k] = strings.TrimSpace(v)
		}
	}
	return m
}

func renderSSHDConfig(m map[string]string) string {
	var b strings.Builder
	b.WriteString("# Trassa: настройки SSH центра безопасности. Файл пишет Trassa; откат — из панели.\n")
	done := map[string]bool{}
	for _, k := range sshdOrder {
		if v, ok := m[k]; ok {
			fmt.Fprintf(&b, "%s %s\n", k, v)
			done[k] = true
		}
	}
	var rest []string
	for k := range m {
		if !done[k] {
			rest = append(rest, k)
		}
	}
	sort.Strings(rest)
	for _, k := range rest {
		fmt.Fprintf(&b, "%s %s\n", k, m[k])
	}
	return b.String()
}

func changeKind(old []byte) agentv1.FileChangeKind {
	if old == nil {
		return agentv1.FileChangeKind_FILE_CHANGE_KIND_CREATE
	}
	return agentv1.FileChangeKind_FILE_CHANGE_KIND_MODIFY
}

func contains(xs []uint32, x uint32) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func listening(ls []*agentv1.Listener, port uint32) bool {
	for _, l := range ls {
		if l.GetProtocol() == "tcp" && l.GetPort() == port {
			return true
		}
	}
	return false
}
