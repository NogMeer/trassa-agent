// SPDX-License-Identifier: AGPL-3.0-only

package security

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFixCodesAreChecks(t *testing.T) {
	if len(FixCodes()) != 12 {
		t.Fatalf("%v", FixCodes())
	}
	for _, c := range FixCodes() {
		if !Known(c) {
			t.Errorf("исправление %s без проверки", c)
		}
	}
}

type recorder struct {
	calls []string
	out   map[string]string
}

func (r *recorder) run(_ context.Context, name string, args ...string) ([]byte, error) {
	c := name + " " + strings.Join(args, " ")
	r.calls = append(r.calls, c)
	for k, v := range r.out {
		if strings.HasPrefix(c, k) {
			return []byte(v), nil
		}
	}
	return []byte("inactive\n"), errors.New("exit 3")
}

func TestUserFixes(t *testing.T) {
	sys := build(t, tree{"etc/passwd": passwd, "etc/shadow": shadow, "etc/group": "g:x:1:\n"})
	rec := &recorder{out: map[string]string{"usermod": ""}}
	sys.Run = rec.run
	p, err := PlanFix(context.Background(), sys, "USER_SERVICE_SHELL", []string{"www-data"})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Paths) != 2 || !strings.HasSuffix(p.Paths[0], "/etc/passwd") {
		t.Fatalf("%v", p.Paths)
	}
	if err := p.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	if rec.calls[len(rec.calls)-1] != "usermod -s /usr/sbin/nologin -- www-data" {
		t.Fatalf("%v", rec.calls)
	}
	if _, err := PlanFix(context.Background(), sys, "USER_EMPTY_PASSWORD", []string{"alice"}); !errors.Is(err, ErrSubject) {
		t.Fatalf("у alice пароль есть: %v", err)
	}
	p, _ = PlanFix(context.Background(), sys, "USER_EMPTY_PASSWORD", []string{"bob"})
	_ = p.Apply(context.Background())
	if rec.calls[len(rec.calls)-1] != "usermod -L -- bob" {
		t.Fatalf("%v", rec.calls)
	}
}

func TestAutoUpdatesAndTimeFix(t *testing.T) {
	sys := build(t, tree{"var/lib/dpkg/status": "Package: unattended-upgrades\nStatus: install ok installed\n"})
	rec := &recorder{out: map[string]string{
		"apt-config dump": "APT::Periodic::Unattended-Upgrade \"0\";\n",
		"systemctl show --property=LoadState --value -- chrony.service":            "not-found\n",
		"systemctl show --property=LoadState --value -- systemd-timesyncd.service": "loaded\n",
		"systemctl is-enabled -- systemd-timesyncd.service":                        "disabled\n",
		"systemctl enable --now": "",
	}}
	sys.Run = rec.run
	p, err := PlanFix(context.Background(), sys, "UPDATES_AUTO_DISABLED", []string{""})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(sys.Root, AutoUpgradesFile))
	if !strings.Contains(string(b), `APT::Periodic::Unattended-Upgrade "1";`) {
		t.Fatalf("%s", b)
	}
	// Без пакета исправление невозможно — отказ до точки отката.
	sys2 := build(t, tree{"var/lib/dpkg/status": ""})
	sys2.Run = rec.run
	if _, err := PlanFix(context.Background(), sys2, "UPDATES_AUTO_DISABLED", []string{""}); !errors.Is(err, ErrPrecondition) {
		t.Fatal(err)
	}

	sys.Adjtimex = func() (int64, error) { return 16_000_000, nil }
	p, err = PlanFix(context.Background(), sys, "TIME_SYNC_OFF", []string{""})
	if err != nil {
		t.Fatal(err)
	}
	if u := p.State.Units; len(u) != 1 || u[0].Name != "systemd-timesyncd.service" || u[0].Enabled || u[0].Active {
		t.Fatalf("%+v", p.State)
	}
	_ = p.Apply(context.Background())
	if !strings.Contains(strings.Join(rec.calls, ";"), "systemctl enable --now -- systemd-timesyncd.service") {
		t.Fatalf("%v", rec.calls)
	}
}

func TestFail2banFix(t *testing.T) {
	sys := build(t, tree{"var/lib/dpkg/status": "", "etc/fail2ban/action.d/nftables-multiport.conf": ""})
	rec := &recorder{out: map[string]string{"apt-get install": "", "systemctl enable": "", "systemctl restart": "", "fail2ban-client status sshd": "Status for the jail: sshd"}}
	sys.Run = rec.run
	p, err := PlanFix(context.Background(), sys, "BRUTEFORCE_NO_PROTECTION", []string{""})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.State.Packages) != 1 || p.State.Packages[0] != "fail2ban" {
		t.Fatalf("пакет не помечен к удалению при откате: %+v", p.State)
	}
	if err := p.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(sys.Root, Fail2banJail))
	if !strings.Contains(string(b), "backend = systemd") || !strings.Contains(string(b), "banaction = nftables-multiport") {
		t.Fatalf("%s", b)
	}
	if err := p.Verify(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(rec.calls[len(rec.calls)-4], "apt-get install -y -q --no-install-recommends fail2ban") {
		t.Fatalf("%v", rec.calls)
	}
}

func TestPermFixKeepsSpecialBits(t *testing.T) {
	sys := build(t, tree{"usr/bin/tool": "bin"})
	p := filepath.Join(sys.Root, "usr/bin/tool")
	if err := os.Chmod(p, 0o777|os.ModeSetgid); err != nil {
		t.Fatal(err)
	}
	plan, err := PlanFix(context.Background(), sys, "PERM_WORLD_WRITABLE", []string{"/usr/bin/tool"})
	if err != nil {
		t.Fatal(err)
	}
	if err := plan.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(p)
	if st.Mode()&(os.ModePerm|os.ModeSetgid) != 0o775|os.ModeSetgid {
		t.Fatalf("%v", st.Mode())
	}
	if err := plan.Verify(context.Background()); err != nil {
		t.Fatal(err)
	}
}
