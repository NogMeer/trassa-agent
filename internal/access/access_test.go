// SPDX-License-Identifier: AGPL-3.0-only

package access

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
)

func caKey(t *testing.T) (string, string) {
	t.Helper()
	pk, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, _ := ssh.NewPublicKey(pk)
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k))), ssh.FingerprintSHA256(k)
}

// fakeHost — корень с sshd_config и sudoers, sshd -T по нашим файлам, учётные записи в памяти.
type fakeHost struct {
	t       *testing.T
	root    string
	users   map[string]bool
	calls   []string
	foreign string // чужой TrustedUserCAKeys
}

func newHost(t *testing.T) (*Env, *fakeHost) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	h := &fakeHost{t: t, root: root, users: map[string]bool{}}
	write := func(p, s string) {
		_ = os.MkdirAll(filepath.Dir(filepath.Join(root, p)), 0o755)
		_ = os.WriteFile(filepath.Join(root, p), []byte(s), 0o644)
	}
	write("/etc/ssh/sshd_config", "Include /etc/ssh/sshd_config.d/*.conf\nPort 22\n")
	write("/etc/sudoers", "root ALL=(ALL:ALL) ALL\n@includedir /etc/sudoers.d\n")
	write("/etc/shells", "/bin/sh\n/bin/bash\n")
	write("/etc/ssh/ssh_host_ed25519_key.pub", "ssh-ed25519 AAAAhost root@h\n")
	e := &Env{Root: root, Run: h.run,
		Lookup: func(name string) (*user.User, error) {
			if h.users[name] {
				return &user.User{Username: name, Uid: "1001", Gid: "1001"}, nil
			}
			return nil, user.UnknownUserError(name)
		}}
	return e, h
}

func (h *fakeHost) exists(p string) bool {
	_, err := os.Stat(filepath.Join(h.root, p))
	return err == nil
}

func (h *fakeHost) run(_ context.Context, name string, args ...string) ([]byte, error) {
	c := name + " " + strings.Join(args, " ")
	h.calls = append(h.calls, c)
	switch name {
	case "sshd":
		if len(args) > 0 && args[0] == "-t" {
			return nil, nil
		}
		u := ""
		if len(args) > 2 {
			u = strings.TrimPrefix(strings.Split(args[2], ",")[0], "user=")
		}
		ca, pf := "none", "none"
		if h.exists(AccessConf) {
			ca, pf = CAFile, PrincipalsDir+"/%u"
		}
		if h.foreign != "" {
			ca = h.foreign
		}
		akf := ".ssh/authorized_keys .ssh/authorized_keys2"
		if u == RescueUser && h.exists(RescueConf) {
			akf = "none"
		}
		return []byte(fmt.Sprintf("port 22\nhostkey /etc/ssh/ssh_host_ed25519_key\ntrustedusercakeys %s\nauthorizedprincipalsfile %s\n"+
			"authorizedprincipalscommand none\nauthorizedkeysfile %s\npubkeyacceptedalgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com\n"+
			"casignaturealgorithms ssh-ed25519,rsa-sha2-512\n", ca, pf, akf)), nil
	case "useradd":
		h.users[args[len(args)-1]] = true
	case "userdel":
		delete(h.users, args[len(args)-1])
	case "systemctl":
		return nil, errors.New("inactive")
	}
	return nil, nil
}

func (h *fakeHost) called(prefix string) bool {
	for _, c := range h.calls {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}

func TestValidate(t *testing.T) {
	k1, _ := caKey(t)
	if err := ValidateTrust(&agentv1.SshCaTrustParams{CaPublicKeys: []string{k1}}); err != nil {
		t.Fatal(err)
	}
	for name, keys := range map[string][]string{
		"пусто":      nil,
		"дважды":     {k1, k1},
		"опции":      {`cert-authority ` + k1},
		"не ed25519": {"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ"},
	} {
		if ValidateTrust(&agentv1.SshCaTrustParams{CaPublicKeys: keys}) == nil {
			t.Errorf("%s принят", name)
		}
	}
	for _, u := range []string{"root", "trassa", "trassa-rescue", "www-data", "Bad", "a b", "-x"} {
		if CheckUser(u) == nil {
			t.Errorf("пользователь %q принят", u)
		}
	}
	ok := &agentv1.AccessUserEnsureParams{UnixUser: "ops", Principals: []*agentv1.AccessPrincipal{{Name: "trassa:ws1:m1"}}}
	if err := ValidateUserEnsure(ok); err != nil {
		t.Fatal(err)
	}
	for name, ps := range map[string][]*agentv1.AccessPrincipal{
		"пусто":     nil,
		"имя":       {{Name: "ops"}},
		"запятая":   {{Name: "trassa:ws1:m1,root"}},
		"дважды":    {{Name: "trassa:ws1:m1"}, {Name: "trassa:ws1:m1"}},
		"аварийный": {{Name: "trassa:ws1:rescue:g1"}},
	} {
		if ValidateUserEnsure(&agentv1.AccessUserEnsureParams{UnixUser: "ops", Principals: ps}) == nil {
			t.Errorf("принципалы %s приняты", name)
		}
	}
	issued := int64(1_800_000_000_000)
	g := &agentv1.AccessRescueGrantParams{Principal: "trassa:ws1:rescue:g1", ExpiresAtMs: issued + 10*60_000}
	if err := ValidateRescueGrant(g, issued); err != nil {
		t.Fatal(err)
	}
	for _, exp := range []int64{issued, issued + 31*60_000} {
		if ValidateRescueGrant(&agentv1.AccessRescueGrantParams{Principal: g.Principal, ExpiresAtMs: exp}, issued) == nil {
			t.Errorf("срок %d принят", exp-issued)
		}
	}
	if ValidateTerminate(&agentv1.AccessSessionsTerminateParams{}) == nil ||
		ValidateTerminate(&agentv1.AccessSessionsTerminateParams{CertKeyIds: []string{"trassa:ws1:m1:x"}}) == nil {
		t.Fatal("пустой или кривой список сеансов принят")
	}
}

func TestTrustUntrust(t *testing.T) {
	e, h := newHost(t)
	k1, fp1 := caKey(t)
	k2, fp2 := caKey(t)
	res, err := e.Trust(context.Background(), []string{k1, k2})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.GetCaFingerprints()) != 2 || res.GetEffectiveTrustedUserCaKeys() != CAFile {
		t.Fatalf("%+v", res)
	}
	conf, _ := os.ReadFile(filepath.Join(h.root, AccessConf))
	if !strings.Contains(string(conf), "TrustedUserCAKeys "+CAFile+"\n") || !strings.Contains(string(conf), "AuthorizedPrincipalsFile "+PrincipalsDir+"/%u\n") || strings.Contains(string(conf), "Match") {
		t.Fatalf("%s", conf)
	}
	for p, want := range map[string]os.FileMode{TrustDir: 0o755, PrincipalsDir: 0o755, CAFile: 0o644, AccessConf: 0o644} {
		if st, _ := os.Stat(filepath.Join(h.root, p)); st.Mode().Perm() != want {
			t.Errorf("%s: %v", p, st.Mode().Perm())
		}
	}
	if !h.called("sshd -t") {
		t.Fatal("нет sshd -t")
	}
	if _, err := e.Untrust(context.Background(), []string{fp1}); err != nil {
		t.Fatal(err)
	}
	_, fps, _ := e.trustedCAs()
	if len(fps) != 1 || fps[0] != fp2 {
		t.Fatalf("%v", fps)
	}
	if _, err := e.Untrust(context.Background(), []string{fp2}); err != nil {
		t.Fatal(err)
	}
	if h.exists(AccessConf) || h.exists(CAFile) {
		t.Fatal("после снятия последнего CA файлы остались")
	}
	// Чужой CA в действующей конфигурации — отказ до изменений.
	h.foreign = "/etc/ssh/other_ca"
	if _, err := e.Trust(context.Background(), []string{k1}); !errors.Is(err, ErrSSHDConflict) || h.exists(CAFile) {
		t.Fatalf("чужой CA: %v", err)
	}
	h.foreign = ""
	_ = os.WriteFile(filepath.Join(h.root, sshdMain), []byte("Port 22\n"), 0o644)
	if _, err := e.Trust(context.Background(), []string{k1}); !errors.Is(err, ErrIncludeMissing) {
		t.Fatalf("без Include: %v", err)
	}
}

func TestUserEnsureRemove(t *testing.T) {
	e, h := newHost(t)
	k1, _ := caKey(t)
	if _, err := e.Trust(context.Background(), []string{k1}); err != nil {
		t.Fatal(err)
	}
	p := &agentv1.AccessUserEnsureParams{UnixUser: "ops", Sudo: true, Principals: []*agentv1.AccessPrincipal{
		{Name: "trassa:ws1:m2", ExpiresAtMs: 1_800_003_600_000}, {Name: "trassa:ws1:m1"}}}
	res, err := e.UserEnsure(context.Background(), p)
	if err != nil || !res.GetCreated() || res.GetPrincipals() != 2 {
		t.Fatalf("%+v %v", res, err)
	}
	if !h.called("useradd --create-home --user-group --shell /bin/bash --comment trassa-access --password * ops") {
		t.Fatalf("%v", h.calls)
	}
	pr, _ := os.ReadFile(filepath.Join(h.root, PrincipalsDir, "ops"))
	if string(pr) != "restrict,pty trassa:ws1:m1\nrestrict,pty,expiry-time=\"202701150900Z\" trassa:ws1:m2\n" {
		t.Fatalf("%q", pr)
	}
	sud := filepath.Join(h.root, SudoersDir, "trassa-ops")
	raw, _ := os.ReadFile(sud)
	st, _ := os.Stat(sud)
	if string(raw) != "ops ALL=(ALL:ALL) NOPASSWD: ALL\n" || st.Mode().Perm() != 0o440 || !h.called("visudo -c -q -f ") || !h.called("visudo -c -q") {
		t.Fatalf("sudo: %q %v %v", raw, st.Mode(), h.calls)
	}
	// Повтор без sudo: правило снимается, учётная запись не создаётся заново.
	p.Sudo = false
	if res, err := e.UserEnsure(context.Background(), p); err != nil || res.GetCreated() {
		t.Fatalf("%+v %v", res, err)
	}
	if _, err := os.Stat(sud); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("правило sudo осталось")
	}
	// Чужой пользователь с тем же логином — отказ.
	h.users["deploy"] = true
	if _, err := e.UserEnsure(context.Background(), &agentv1.AccessUserEnsureParams{UnixUser: "deploy", Principals: p.Principals}); !errors.Is(err, ErrUserForeign) {
		t.Fatalf("чужой: %v", err)
	}
	if _, err := e.UserRemove(context.Background(), &agentv1.AccessUserRemoveParams{UnixUser: "deploy"}); !errors.Is(err, ErrNotManaged) {
		t.Fatalf("удаление чужого: %v", err)
	}
	out, err := e.UserRemove(context.Background(), &agentv1.AccessUserRemoveParams{UnixUser: "ops"})
	if err != nil || !out.GetHomeKept() || h.users["ops"] || h.exists(filepath.Join(PrincipalsDir, "ops")) {
		t.Fatalf("%+v %v", out, err)
	}
	if !h.called("loginctl terminate-user ops") || !h.called("userdel ops") {
		t.Fatalf("%v", h.calls)
	}
	stt, _ := e.loadState()
	if len(stt.Users) != 0 {
		t.Fatal("реестр не очищен")
	}
}

func TestRescue(t *testing.T) {
	e, h := newHost(t)
	g := &agentv1.AccessRescueGrantParams{Principal: "trassa:ws1:rescue:g1", ExpiresAtMs: 1_800_000_600_000}
	if _, err := e.RescueGrant(context.Background(), g); !errors.Is(err, ErrSSHDInvalid) {
		t.Fatalf("без CA: %v", err)
	}
	k1, _ := caKey(t)
	if _, err := e.Trust(context.Background(), []string{k1}); err != nil {
		t.Fatal(err)
	}
	res, err := e.RescueGrant(context.Background(), g)
	if err != nil || res.GetUnixUser() != RescueUser {
		t.Fatalf("%+v %v", res, err)
	}
	pr, _ := os.ReadFile(filepath.Join(h.root, PrincipalsDir, RescueUser))
	if string(pr) != "restrict,pty,expiry-time=\"202701150810Z\" trassa:ws1:rescue:g1\n" {
		t.Fatalf("%q", pr)
	}
	if !h.exists(filepath.Join(SudoersDir, "trassa-"+RescueUser)) {
		t.Fatal("нет sudo")
	}
	conf, _ := os.ReadFile(filepath.Join(h.root, RescueConf))
	if !strings.Contains(string(conf), "Match User trassa-rescue\n\tAuthorizedKeysFile none\n") {
		t.Fatalf("%s", conf)
	}
	st, _ := e.StateRead(context.Background())
	if st.GetRescueExpiresAtMs() != g.ExpiresAtMs || len(st.GetCaFingerprints()) != 1 || !st.GetTrustEffective() {
		t.Fatalf("%+v", st)
	}
	if err := e.RescueRevoke(context.Background()); err != nil {
		t.Fatal(err)
	}
	if h.exists(filepath.Join(PrincipalsDir, RescueUser)) || h.exists(filepath.Join(SudoersDir, "trassa-"+RescueUser)) || !h.called("pkill -KILL -u trassa-rescue") {
		t.Fatalf("аварийный доступ остался: %v", h.calls)
	}
}

// Закрытие прямого сеанса по keyId: тот же монитор sshd (exe, uid 0, старт до записи) — сеанс logind
// закрывается; pid, переиспользованный после записи, не трогается.
func TestTerminateCerts(t *testing.T) {
	e, h := newHost(t)
	proc := func(pid int, start uint64, exe string, session string) {
		d := filepath.Join(h.root, "proc", fmt.Sprint(pid))
		_ = os.MkdirAll(d, 0o755)
		_ = os.Symlink(exe, filepath.Join(d, "exe"))
		_ = os.WriteFile(filepath.Join(d, "status"), []byte("Name:\tsshd-session\nUid:\t0\t0\t0\t0\n"), 0o644)
		_ = os.WriteFile(filepath.Join(d, "stat"), []byte(fmt.Sprintf("%d (sshd-session) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 %d 20", pid, start)), 0o644)
		_ = os.WriteFile(filepath.Join(d, "cgroup"), []byte("0::/user.slice/user-1001.slice/session-"+session+".scope\n"), 0o644)
	}
	proc(500, 1000, "/usr/lib/openssh/sshd-session", "7") // старт 10 с после загрузки, запись в 20 с
	proc(600, 5000, "/usr/lib/openssh/sshd-session", "8") // старт 50 с — позже записи (pid переиспользован)
	line := func(pid int, keyID string) string {
		return fmt.Sprintf(`{"MESSAGE":"Accepted publickey for ops from 10.0.0.5 port 50022 ssh2: ED25519-CERT SHA256:abc ID %s (serial 9) CA ED25519 SHA256:ca","_PID":"%d","__MONOTONIC_TIMESTAMP":"20000000"}`, keyID, pid)
	}
	journal := line(500, "trassa:ws1:m1:9") + "\n" + line(600, "trassa:ws1:m2:4") + "\n"
	run := h.run
	e.Run = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name == "journalctl" {
			return []byte(journal), nil
		}
		return run(ctx, name, args...)
	}
	done, missing, err := e.TerminateCerts(context.Background(), []string{"trassa:ws1:m1:9", "trassa:ws1:m2:4", "trassa:ws1:m3:1"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(done, ",") != "trassa:ws1:m1:9" || strings.Join(missing, ",") != "trassa:ws1:m2:4,trassa:ws1:m3:1" {
		t.Fatalf("%v %v", done, missing)
	}
	if !h.called("loginctl terminate-session 7") || h.called("loginctl terminate-session 8") {
		t.Fatalf("%v", h.calls)
	}
}

// Истёкшая выдача снимается задачей помощника; чужой trassa-rescue доступ не трогает.
func TestRescueExpireAndForeign(t *testing.T) {
	e, h := newHost(t)
	k1, _ := caKey(t)
	if _, err := e.Trust(context.Background(), []string{k1}); err != nil {
		t.Fatal(err)
	}
	g := &agentv1.AccessRescueGrantParams{Principal: "trassa:ws1:rescue:g1", ExpiresAtMs: 1_800_000_600_000}
	if _, err := e.RescueGrant(context.Background(), g); err != nil {
		t.Fatal(err)
	}
	if err := e.ExpireRescue(context.Background(), time.UnixMilli(1_800_000_000_000)); err != nil || !h.exists(filepath.Join(SudoersDir, "trassa-"+RescueUser)) {
		t.Fatalf("снято до срока: %v", err)
	}
	if err := e.ExpireRescue(context.Background(), time.UnixMilli(1_800_000_600_001)); err != nil || h.exists(filepath.Join(SudoersDir, "trassa-"+RescueUser)) {
		t.Fatalf("после срока sudo остался: %v", err)
	}
	// Чужая учётная запись trassa-rescue: отказ до любых изменений (usermod не вызывается).
	e2, h2 := newHost(t)
	if _, err := e2.Trust(context.Background(), []string{k1}); err != nil {
		t.Fatal(err)
	}
	h2.users[RescueUser] = true
	h2.calls = nil
	if _, err := e2.RescueGrant(context.Background(), g); !errors.Is(err, ErrUserForeign) || h2.called("usermod") {
		t.Fatalf("чужой trassa-rescue: %v %v", err, h2.calls)
	}
}
