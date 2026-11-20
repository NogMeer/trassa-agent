// SPDX-License-Identifier: AGPL-3.0-only

package access

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/fsutil"
)

// Файлы доступа (decisions E16, часть 1; все root:root).
const (
	SSHDropInDir  = "/etc/ssh/sshd_config.d"
	AccessConf    = "/etc/ssh/sshd_config.d/00-trassa-access.conf"
	RescueConf    = "/etc/ssh/sshd_config.d/00-trassa-rescue.conf"
	TrustDir      = "/etc/ssh/trassa"
	CAFile        = "/etc/ssh/trassa/ca.pub"
	PrincipalsDir = "/etc/ssh/trassa/principals"
	SudoersDir    = "/etc/sudoers.d"
	StateFile     = "/etc/trassa/access/state.json"
	sshdMain      = "/etc/ssh/sshd_config"
	sudoersMain   = "/etc/sudoers"
	certAlgo      = "ssh-ed25519-cert-v01@openssh.com"
)

// Коды итога.
var (
	ErrSSHDConflict   = errors.New("ACCESS_SSHD_CONFLICT")
	ErrSSHDInvalid    = errors.New("ACCESS_SSHD_INVALID")
	ErrIncludeMissing = errors.New("ACCESS_INCLUDE_MISSING")
	ErrUserForeign    = errors.New("ACCESS_USER_FOREIGN")
	ErrNotManaged     = errors.New("ACCESS_USER_NOT_MANAGED")
	ErrSudoMissing    = errors.New("ACCESS_SUDO_UNAVAILABLE")
	ErrSudoInclude    = errors.New("ACCESS_SUDO_INCLUDE_MISSING")
)

// Env — доступ под корнем Root ("/" на сервере).
type Env struct {
	Root string
	Run  func(ctx context.Context, name string, args ...string) ([]byte, error)
	// Lookup — учётная запись (os/user; в тестах — подмена).
	Lookup func(name string) (*user.User, error)
}

func (e *Env) path(p string) string { return filepath.Join(e.Root, p) }

func (e *Env) lookup(name string) (*user.User, error) {
	if e.Lookup != nil {
		return e.Lookup(name)
	}
	return user.Lookup(name)
}

// State — реестр помощника: какие учётные записи созданы Trassa (только их доступ меняет и удаляет).
type State struct {
	Users        map[string]UserState `json:"users"`
	RescueExpiry int64                `json:"rescue_expires_at_ms,omitempty"`
	// RescueCreated — trassa-rescue создан доступом Trassa (только тогда E10 не считает его находкой).
	RescueCreated bool `json:"rescue_created,omitempty"`
}

// SudoRule — единственная строка правила sudo Trassa для пользователя u (E10 сверяет файл с ней побайтно).
func SudoRule(u string) string { return u + " ALL=(ALL:ALL) NOPASSWD: ALL\n" }

// UserState — пользователь доступа.
type UserState struct {
	Sudo       bool              `json:"sudo"`
	Shell      string            `json:"shell"`
	Principals []PrincipalRecord `json:"principals"`
}

// PrincipalRecord — строка файла принципалов.
type PrincipalRecord struct {
	Name      string `json:"name"`
	ExpiresMs int64  `json:"expires_at_ms,omitempty"`
}

func (e *Env) loadState() (*State, error) {
	raw, err := fsutil.ReadLimited(e.path(StateFile), 4<<20)
	if errors.Is(err, os.ErrNotExist) {
		return &State{Users: map[string]UserState{}}, nil
	}
	if err != nil {
		return nil, err
	}
	var st State
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, fmt.Errorf("реестр доступа повреждён: %w", err)
	}
	if st.Users == nil {
		st.Users = map[string]UserState{}
	}
	return &st, nil
}

func (e *Env) saveState(st *State) error {
	if err := os.MkdirAll(filepath.Dir(e.path(StateFile)), 0o700); err != nil {
		return err
	}
	raw, _ := json.Marshal(st)
	return fsutil.WriteFileAtomic(e.path(StateFile), raw, 0o600, fsutil.Keep)
}

// Paths — файлы, которые меняют операции доступа для пользователей users (точка отката CONFIG).
func (e *Env) Paths(users ...string) []string {
	out := []string{e.path(AccessConf), e.path(RescueConf), e.path(CAFile), e.path(StateFile)}
	for _, u := range users {
		out = append(out, e.path(filepath.Join(PrincipalsDir, u)), e.path(filepath.Join(SudoersDir, "trassa-"+u)))
	}
	for _, f := range []string{"/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow"} {
		if _, err := os.Stat(e.path(f)); err == nil {
			out = append(out, e.path(f))
		}
	}
	return out
}

var includeRe = regexp.MustCompile(`(?mi)^\s*Include\s+/etc/ssh/sshd_config\.d/\*\.conf\s*$`)

// sshdT — действующие значения sshd -T [-C user=…] как ключ → значения.
func (e *Env) sshdT(ctx context.Context, u string) (map[string][]string, error) {
	args := []string{"-T"}
	if u != "" {
		args = append(args, "-C", "user="+u+",host=localhost,addr=127.0.0.1")
	}
	out, err := e.Run(ctx, "sshd", args...)
	if err != nil {
		return nil, fmt.Errorf("%w: sshd -T: %v", ErrSSHDInvalid, err)
	}
	m := map[string][]string{}
	for _, l := range strings.Split(string(out), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(l), " ")
		if ok {
			m[strings.ToLower(k)] = append(m[strings.ToLower(k)], v)
		}
	}
	return m, nil
}

func first(m map[string][]string, k string) string {
	if v := m[k]; len(v) > 0 {
		return v[0]
	}
	return ""
}

// preflight — до изменений: Include sshd_config.d, чужие CA и принципалы (в том числе в чужих Match для root и
// управляемых), алгоритмы сертификата не выключены.
func (e *Env) preflight(ctx context.Context, users []string) error {
	main, err := os.ReadFile(e.path(sshdMain))
	if err != nil {
		return fmt.Errorf("%w: %s: %v", ErrSSHDInvalid, sshdMain, err)
	}
	if !includeRe.Match(main) {
		return fmt.Errorf("%w: в %s нет Include %s/*.conf", ErrIncludeMissing, sshdMain, SSHDropInDir)
	}
	for _, u := range append([]string{"root"}, users...) {
		m, err := e.sshdT(ctx, u)
		if err != nil {
			return err
		}
		if v := first(m, "trustedusercakeys"); v != "none" && v != CAFile && v != "" {
			return fmt.Errorf("%w: чужой TrustedUserCAKeys %s (для %s)", ErrSSHDConflict, v, u)
		}
		if v := first(m, "authorizedprincipalsfile"); v != "none" && v != "" && !ourPrincipals(v, u) {
			return fmt.Errorf("%w: чужой AuthorizedPrincipalsFile %s (для %s)", ErrSSHDConflict, v, u)
		}
		if v := first(m, "authorizedprincipalscommand"); v != "none" && v != "" {
			return fmt.Errorf("%w: задан AuthorizedPrincipalsCommand (для %s)", ErrSSHDConflict, u)
		}
		if v := first(m, "pubkeyacceptedalgorithms"); v != "" && !strings.Contains(","+v+",", ","+certAlgo+",") {
			return fmt.Errorf("%w: %s выключен в PubkeyAcceptedAlgorithms", ErrSSHDConflict, certAlgo)
		}
		if v := first(m, "casignaturealgorithms"); v != "" && !strings.Contains(","+v+",", ",ssh-ed25519,") {
			return fmt.Errorf("%w: ssh-ed25519 выключен в CASignatureAlgorithms", ErrSSHDConflict)
		}
	}
	return nil
}

// ourPrincipals — значение sshd -T для нашего файла: с нераскрытым %u или с подставленным именем.
func ourPrincipals(v, u string) bool {
	return v == PrincipalsDir+"/%u" || v == PrincipalsDir+"/"+u
}

// verify — после применения: для root, управляемых и trassa-rescue действуют наш CA и наш файл принципалов.
func (e *Env) verify(ctx context.Context, users []string) error {
	for _, u := range append([]string{"root"}, users...) {
		m, err := e.sshdT(ctx, u)
		if err != nil {
			return err
		}
		if first(m, "trustedusercakeys") != CAFile || !ourPrincipals(first(m, "authorizedprincipalsfile"), u) {
			return fmt.Errorf("для %s действуют trustedusercakeys %q и authorizedprincipalsfile %q", u,
				first(m, "trustedusercakeys"), first(m, "authorizedprincipalsfile"))
		}
	}
	return nil
}

func (e *Env) reload(ctx context.Context) error {
	if out, err := e.Run(ctx, "sshd", "-t"); err != nil {
		return fmt.Errorf("%w: sshd -t: %v %s", ErrSSHDInvalid, err, firstLine(out))
	}
	for _, unit := range []string{"ssh.service", "sshd.service"} {
		if _, err := e.Run(ctx, "systemctl", "is-active", "--quiet", unit); err == nil {
			if out, err := e.Run(ctx, "systemctl", "reload", unit); err != nil {
				return fmt.Errorf("systemctl reload %s: %v %s", unit, err, firstLine(out))
			}
			return nil
		}
	}
	return nil
}

func firstLine(b []byte) string {
	s := string(b)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

func (e *Env) managed(st *State) []string {
	out := make([]string, 0, len(st.Users)+1)
	for u := range st.Users {
		out = append(out, u)
	}
	sort.Strings(out)
	if _, err := e.lookup(RescueUser); err == nil {
		out = append(out, RescueUser)
	}
	return out
}

func (e *Env) writeRoot(p string, data []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(e.path(p)), 0o755); err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(e.path(p), data, perm, fsutil.Keep)
}

// ensureTrustDirs — /etc/ssh/trassa и principals: 0755 (UMask помощника 0077; sshd читает файл принципалов от
// имени пользователя — нужен проход).
func (e *Env) ensureTrustDirs() error {
	for _, d := range []string{TrustDir, PrincipalsDir} {
		if err := os.MkdirAll(e.path(d), 0o755); err != nil {
			return err
		}
		if err := os.Chmod(e.path(d), 0o755); err != nil {
			return err
		}
	}
	return nil
}

// Trust — sshca.trust: полный набор CA; файл доступа с двумя глобальными строками.
func (e *Env) Trust(ctx context.Context, keys []string) (*agentv1.SshCaTrustResult, error) {
	st, err := e.loadState()
	if err != nil {
		return nil, err
	}
	users := e.managed(st)
	if err := e.preflight(ctx, users); err != nil {
		return nil, err
	}
	var b strings.Builder
	var fps []string
	for _, l := range keys {
		k, fp, err := ParseCA(l)
		if err != nil {
			return nil, err
		}
		f := strings.Fields(l)
		fmt.Fprintf(&b, "%s %s %s\n", k.Type(), f[1], fp)
		fps = append(fps, fp)
	}
	if err := e.ensureTrustDirs(); err != nil {
		return nil, err
	}
	if err := e.writeRoot(CAFile, []byte(b.String()), 0o644); err != nil {
		return nil, err
	}
	conf := "# Trassa: доверие к CA пространства (E16). Файл пишет Trassa.\nTrustedUserCAKeys " + CAFile +
		"\nAuthorizedPrincipalsFile " + PrincipalsDir + "/%u\n"
	if err := e.writeRoot(AccessConf, []byte(conf), 0o644); err != nil {
		return nil, err
	}
	if err := e.reload(ctx); err != nil {
		return nil, err
	}
	if err := e.verify(ctx, users); err != nil {
		return nil, err
	}
	return e.trustResult(ctx, fps)
}

func (e *Env) trustResult(ctx context.Context, fps []string) (*agentv1.SshCaTrustResult, error) {
	m, err := e.sshdT(ctx, "")
	if err != nil {
		return nil, err
	}
	return &agentv1.SshCaTrustResult{CaFingerprints: fps, EffectiveTrustedUserCaKeys: first(m, "trustedusercakeys"),
		EffectiveAuthorizedPrincipalsFile: first(m, "authorizedprincipalsfile")}, nil
}

// trustedCAs — строки ca.pub (ключ и отпечаток).
func (e *Env) trustedCAs() ([]string, []string, error) {
	raw, err := os.ReadFile(e.path(CAFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	var lines, fps []string
	for _, l := range strings.Split(string(raw), "\n") {
		f := strings.Fields(l)
		if len(f) < 2 {
			continue
		}
		_, fp, err := ParseCA(f[0] + " " + f[1])
		if err != nil {
			return nil, nil, fmt.Errorf("ca.pub: %w", err)
		}
		lines, fps = append(lines, f[0]+" "+f[1]), append(fps, fp)
	}
	return lines, fps, nil
}

// Untrust — sshca.untrust: снять CA по отпечаткам; не осталось ни одного — файл доступа и ca.pub удаляются.
func (e *Env) Untrust(ctx context.Context, remove []string) (*agentv1.SshCaTrustResult, error) {
	lines, fps, err := e.trustedCAs()
	if err != nil {
		return nil, err
	}
	drop := map[string]bool{}
	for _, f := range remove {
		drop[f] = true
	}
	var keep []string
	for i, l := range lines {
		if !drop[fps[i]] {
			keep = append(keep, l)
		}
	}
	if len(keep) > 0 {
		return e.Trust(ctx, keep)
	}
	for _, f := range []string{AccessConf, CAFile} {
		if err := fsutil.RemoveSync(e.path(f)); err != nil {
			return nil, err
		}
	}
	if err := e.reload(ctx); err != nil {
		return nil, err
	}
	m, err := e.sshdT(ctx, "")
	if err != nil {
		return nil, err
	}
	if v := first(m, "trustedusercakeys"); v == CAFile {
		return nil, errors.New("TrustedUserCAKeys Trassa остался после снятия")
	}
	return &agentv1.SshCaTrustResult{EffectiveTrustedUserCaKeys: first(m, "trustedusercakeys"),
		EffectiveAuthorizedPrincipalsFile: first(m, "authorizedprincipalsfile")}, nil
}

// principalsText — строки файла принципалов: restrict,pty и срок (sshd сам перестаёт принимать строку после
// expiry-time — выдача кончается и без связи с панелью).
func principalsText(ps []PrincipalRecord) string {
	var b strings.Builder
	for _, p := range ps {
		b.WriteString("restrict,pty")
		if p.ExpiresMs > 0 {
			fmt.Fprintf(&b, `,expiry-time="%s"`, time.UnixMilli(p.ExpiresMs).UTC().Format("200601021504Z"))
		}
		b.WriteString(" " + p.Name + "\n")
	}
	return b.String()
}

func toRecords(ps []*agentv1.AccessPrincipal) []PrincipalRecord {
	out := make([]PrincipalRecord, 0, len(ps))
	for _, p := range ps {
		out = append(out, PrincipalRecord{Name: p.GetName(), ExpiresMs: p.GetExpiresAtMs()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// ensureAccount — учётная запись доступа: новая — с домашним каталогом, паролем «*» (вход по ключу и
// сертификату, без пароля); существующая и не из реестра — ACCESS_USER_FOREIGN.
func (e *Env) ensureAccount(ctx context.Context, st *State, u, shell string) (bool, *user.User, error) {
	if _, err := e.lookup(u); err == nil {
		if _, ours := st.Users[u]; !ours && u != RescueUser {
			return false, nil, fmt.Errorf("%w: %s создан не Trassa", ErrUserForeign, u)
		}
		if out, err := e.Run(ctx, "usermod", "--shell", shell, "--password", "*", u); err != nil {
			return false, nil, fmt.Errorf("usermod: %v %s", err, firstLine(out))
		}
		acc, err := e.lookup(u)
		return false, acc, err
	}
	if !e.allowedShell(shell) {
		return false, nil, fmt.Errorf("оболочки %s нет в /etc/shells", shell)
	}
	if out, err := e.Run(ctx, "useradd", "--create-home", "--user-group", "--shell", shell, "--comment", "trassa-access",
		"--password", "*", u); err != nil {
		return false, nil, fmt.Errorf("useradd: %v %s", err, firstLine(out))
	}
	acc, err := e.lookup(u)
	return true, acc, err
}

func (e *Env) allowedShell(sh string) bool {
	raw, err := os.ReadFile(e.path("/etc/shells"))
	if err != nil {
		return false
	}
	for _, l := range strings.Split(string(raw), "\n") {
		if strings.TrimSpace(l) == sh {
			return true
		}
	}
	return false
}

// setSudo — /etc/sudoers.d/trassa-<user>: «<user> ALL=(ALL:ALL) NOPASSWD: ALL», 0440; временный файл
// проверяется visudo -cf, после установки — visudo -c всей конфигурации. sudo=false — файл удаляется.
func (e *Env) setSudo(ctx context.Context, u string, sudo bool) error {
	dst := e.path(filepath.Join(SudoersDir, "trassa-"+u))
	if !sudo {
		return fsutil.RemoveSync(dst)
	}
	main, err := os.ReadFile(e.path(sudoersMain))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrSudoMissing, err)
	}
	if !regexp.MustCompile(`(?m)^[@#]includedir\s+/etc/sudoers\.d\s*$`).Match(main) {
		return fmt.Errorf("%w: в /etc/sudoers нет @includedir /etc/sudoers.d", ErrSudoInclude)
	}
	tmp := e.path(filepath.Join(SudoersDir, ".trassa-"+u+".tmp"))
	if err := os.MkdirAll(filepath.Dir(tmp), 0o750); err != nil {
		return err
	}
	if err := fsutil.WriteFileAtomic(tmp, []byte(SudoRule(u)), 0o440, fsutil.Keep); err != nil {
		return err
	}
	defer os.Remove(tmp)
	if out, err := e.Run(ctx, "visudo", "-c", "-q", "-f", tmp); err != nil {
		return fmt.Errorf("%w: visudo -cf: %v %s", ErrSudoMissing, err, firstLine(out))
	}
	if err := os.Rename(tmp, dst); err != nil {
		return err
	}
	if out, err := e.Run(ctx, "visudo", "-c", "-q"); err != nil {
		_ = os.Remove(dst)
		return fmt.Errorf("visudo -c: %v %s", err, firstLine(out))
	}
	return nil
}

func (e *Env) writePrincipals(u string, ps []PrincipalRecord) error {
	if err := e.ensureTrustDirs(); err != nil {
		return err
	}
	p := filepath.Join(PrincipalsDir, u)
	if len(ps) == 0 {
		return fsutil.RemoveSync(e.path(p))
	}
	return e.writeRoot(p, []byte(principalsText(ps)), 0o644)
}

// UserEnsure — access.user.ensure: учётная запись, принципалы (полный набор), sudo.
func (e *Env) UserEnsure(ctx context.Context, p *agentv1.AccessUserEnsureParams) (*agentv1.AccessUserEnsureResult, error) {
	st, err := e.loadState()
	if err != nil {
		return nil, err
	}
	u, shell := p.GetUnixUser(), shells[p.GetShell()]
	users := append(e.managed(st), u)
	if err := e.preflight(ctx, users); err != nil {
		return nil, err
	}
	created, acc, err := e.ensureAccount(ctx, st, u, shell)
	if err != nil {
		return nil, err
	}
	recs := toRecords(p.GetPrincipals())
	if err := e.writePrincipals(u, recs); err != nil {
		return nil, err
	}
	if err := e.setSudo(ctx, u, p.GetSudo()); err != nil {
		return nil, err
	}
	st.Users[u] = UserState{Sudo: p.GetSudo(), Shell: shell, Principals: recs}
	if err := e.saveState(st); err != nil {
		return nil, err
	}
	if _, err := os.Stat(e.path(AccessConf)); err == nil {
		if err := e.verify(ctx, []string{u}); err != nil {
			return nil, err
		}
	}
	uid, _ := strconv.Atoi(acc.Uid)
	return &agentv1.AccessUserEnsureResult{Created: created, Uid: uint32(uid), Principals: uint32(len(recs)), Sudo: p.GetSudo()}, nil
}

// endSessions — закрыть сеансы и процессы пользователя (логин нужен только ему).
func (e *Env) endSessions(ctx context.Context, u string) uint32 {
	_, _ = e.Run(ctx, "loginctl", "terminate-user", u)
	out, _ := e.Run(ctx, "pgrep", "-u", u)
	n := uint32(len(strings.Fields(string(out))))
	_, _ = e.Run(ctx, "pkill", "-KILL", "-u", u)
	return n
}

// UserRemove — access.user.remove: только пользователь из реестра; сеансы закрываются, домашний каталог — по
// delete_home.
func (e *Env) UserRemove(ctx context.Context, p *agentv1.AccessUserRemoveParams) (*agentv1.AccessUserRemoveResult, error) {
	st, err := e.loadState()
	if err != nil {
		return nil, err
	}
	u := p.GetUnixUser()
	if _, ok := st.Users[u]; !ok {
		return nil, fmt.Errorf("%w: %s", ErrNotManaged, u)
	}
	if err := e.writePrincipals(u, nil); err != nil {
		return nil, err
	}
	if err := e.setSudo(ctx, u, false); err != nil {
		return nil, err
	}
	killed := e.endSessions(ctx, u)
	if _, err := e.lookup(u); err == nil {
		args := []string{u}
		if p.GetDeleteHome() {
			args = []string{"--remove", u}
		}
		if out, err := e.Run(ctx, "userdel", args...); err != nil {
			return nil, fmt.Errorf("userdel: %v %s", err, firstLine(out))
		}
	}
	delete(st.Users, u)
	if err := e.saveState(st); err != nil {
		return nil, err
	}
	return &agentv1.AccessUserRemoveResult{ProcessesKilled: killed, HomeKept: !p.GetDeleteHome()}, nil
}

// rescueConfText — у trassa-rescue нет ключей: только сертификат (AuthorizedKeysFile none).
const rescueConfText = "# Trassa: аварийный вход только по короткому сертификату (E16). Файл пишет Trassa.\nMatch User " +
	RescueUser + "\n\tAuthorizedKeysFile none\n\tPasswordAuthentication no\n\tKbdInteractiveAuthentication no\n"

// RescueGrant — access.rescue.grant: trassa-rescue с sudo, один принципал до expires_at (строкой с
// expiry-time); вход — только по сертификату с этим принципалом.
func (e *Env) RescueGrant(ctx context.Context, p *agentv1.AccessRescueGrantParams) (*agentv1.AccessRescueGrantResult, error) {
	st, err := e.loadState()
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(e.path(AccessConf)); err != nil {
		return nil, fmt.Errorf("%w: нет доверия к CA (sshca.trust)", ErrSSHDInvalid)
	}
	users := append(e.managed(st), RescueUser)
	if err := e.preflight(ctx, users); err != nil {
		return nil, err
	}
	created, _, err := e.ensureAccount(ctx, st, RescueUser, "/bin/bash")
	if err != nil {
		return nil, err
	}
	if !created && !st.RescueCreated {
		return nil, fmt.Errorf("%w: %s создан не Trassa", ErrUserForeign, RescueUser)
	}
	st.RescueCreated = true
	if err := e.writeRoot(RescueConf, []byte(rescueConfText), 0o644); err != nil {
		return nil, err
	}
	if err := e.writePrincipals(RescueUser, []PrincipalRecord{{Name: p.GetPrincipal(), ExpiresMs: p.GetExpiresAtMs()}}); err != nil {
		return nil, err
	}
	if err := e.setSudo(ctx, RescueUser, true); err != nil {
		return nil, err
	}
	st.RescueExpiry = p.GetExpiresAtMs()
	if err := e.saveState(st); err != nil {
		return nil, err
	}
	if err := e.reload(ctx); err != nil {
		return nil, err
	}
	if err := e.verify(ctx, []string{RescueUser}); err != nil {
		return nil, err
	}
	m, err := e.sshdT(ctx, RescueUser)
	if err != nil {
		return nil, err
	}
	if first(m, "authorizedkeysfile") != "none" {
		return nil, fmt.Errorf("для %s действуют ключи (authorizedkeysfile %q)", RescueUser, first(m, "authorizedkeysfile"))
	}
	return &agentv1.AccessRescueGrantResult{UnixUser: RescueUser, ExpiresAtMs: p.GetExpiresAtMs()}, nil
}

// RescueRevoke — access.rescue.revoke: принципал снимается, sudo снимается, сеансы trassa-rescue закрываются.
func (e *Env) RescueRevoke(ctx context.Context) error {
	st, err := e.loadState()
	if err != nil {
		return err
	}
	if err := e.writePrincipals(RescueUser, nil); err != nil {
		return err
	}
	if err := e.setSudo(ctx, RescueUser, false); err != nil {
		return err
	}
	if _, err := e.lookup(RescueUser); err == nil {
		e.endSessions(ctx, RescueUser)
	}
	st.RescueExpiry = 0
	return e.saveState(st)
}

// StateRead — access.state.read.
func (e *Env) StateRead(ctx context.Context) (*agentv1.AccessStateResult, error) {
	st, err := e.loadState()
	if err != nil {
		return nil, err
	}
	_, fps, err := e.trustedCAs()
	if err != nil {
		return nil, err
	}
	res := &agentv1.AccessStateResult{CaFingerprints: fps, RescueExpiresAtMs: st.RescueExpiry}
	for _, u := range e.managed(st) {
		if u == RescueUser {
			continue
		}
		us := st.Users[u]
		mu := &agentv1.AccessManagedUser{Name: u, Sudo: us.Sudo}
		if acc, err := e.lookup(u); err == nil {
			uid, _ := strconv.Atoi(acc.Uid)
			mu.Uid = uint32(uid)
		} else {
			res.Conflicts = append(res.Conflicts, "MISSING_USER:"+u)
		}
		for _, p := range us.Principals {
			mu.Principals = append(mu.Principals, &agentv1.AccessPrincipal{Name: p.Name, ExpiresAtMs: p.ExpiresMs})
		}
		for k, v := range shells {
			if v == us.Shell && k != agentv1.AccessShell_ACCESS_SHELL_UNSPECIFIED {
				mu.Shell = k
			}
		}
		res.Users = append(res.Users, mu)
	}
	m, err := e.sshdT(ctx, "")
	if err != nil {
		return nil, err
	}
	for _, p := range m["port"] {
		if n, err := strconv.Atoi(p); err == nil {
			res.SshPorts = append(res.SshPorts, uint32(n))
		}
	}
	for _, hk := range m["hostkey"] {
		if raw, err := fsutil.ReadLimited(e.path(hk+".pub"), 16<<10); err == nil {
			if f := strings.Fields(string(raw)); len(f) >= 2 {
				res.HostKeys = append(res.HostKeys, f[0]+" "+f[1])
			}
		}
	}
	if out, err := e.Run(ctx, "dpkg-query", "-W", "-f=${Version}", "openssh-server"); err == nil {
		res.OpensshVersion = strings.TrimSpace(string(out))
	}
	res.TrustEffective = len(fps) > 0 && e.verify(ctx, e.managed(st)) == nil
	if err := e.preflight(ctx, e.managed(st)); err != nil && errors.Is(err, ErrSSHDConflict) {
		res.Conflicts = append(res.Conflicts, err.Error())
	}
	_, err = e.Run(ctx, "visudo", "-c", "-q")
	res.SudoAvailable = err == nil
	if out, err := e.Run(ctx, "locale", "-a"); err == nil {
		for _, l := range strings.Fields(string(out)) {
			for _, want := range []string{"ru_RU.utf8", "en_US.utf8", "C.utf8", "C.UTF-8"} {
				if l == want {
					res.Locales = append(res.Locales, l)
				}
			}
		}
	}
	return res, nil
}
