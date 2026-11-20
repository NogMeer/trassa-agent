// SPDX-License-Identifier: AGPL-3.0-only

package rollback

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Каталог и особые биты: исправление прав возвращается откатом точно.
func TestDirAndSpecialBits(t *testing.T) {
	root := t.TempDir()
	d := filepath.Join(root, "cron.d")
	f := filepath.Join(root, "tool")
	if err := os.Mkdir(d, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(d, 0o777|os.ModeSticky); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f, []byte("bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(f, 0o777|os.ModeSetgid); err != nil {
		t.Fatal(err)
	}
	s := &Store{Dir: filepath.Join(root, "rb")}
	m, err := s.Create(op, []string{d, f}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !m.Files[0].Dir || m.Files[0].Special != 0o1000 || m.Files[1].Special != 0o2000 {
		t.Fatalf("%+v", m.Files)
	}
	_ = os.Chmod(d, 0o755)
	_ = os.Chmod(f, 0o755)
	if _, err := s.Restore(op); err != nil {
		t.Fatal(err)
	}
	for p, want := range map[string]os.FileMode{d: 0o777 | os.ModeSticky, f: 0o777 | os.ModeSetgid} {
		st, _ := os.Stat(p)
		if st.Mode()&(os.ModePerm|os.ModeSticky|os.ModeSetgid) != want {
			t.Errorf("%s: %v, ждали %v", p, st.Mode(), want)
		}
	}
}

func TestStateRestore(t *testing.T) {
	root := t.TempDir()
	sys := filepath.Join(root, "sys")
	p := filepath.Join(sys, "net/ipv4/tcp_syncookies")
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var calls []string
	s := &Store{Dir: filepath.Join(root, "rb"), ProcSys: sys, Exec: func(name string, args ...string) error {
		calls = append(calls, name+" "+strings.Join(args, " "))
		return nil
	}}
	st := State{
		Sysctl:   map[string]string{"net.ipv4.tcp_syncookies": "0"},
		Units:    []UnitState{{Name: "fail2ban.service"}, {Name: "systemd-timesyncd.service", Enabled: true, Active: true}},
		Packages: []string{"fail2ban"},
	}
	if _, err := s.CreateState(op, nil, nil, st); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Restore(op); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p); strings.TrimSpace(string(b)) != "0" {
		t.Fatalf("sysctl: %q", b)
	}
	want := "systemctl disable -- fail2ban.service;systemctl stop -- fail2ban.service;systemctl enable -- systemd-timesyncd.service;" +
		"systemctl start -- systemd-timesyncd.service;apt-get purge -y -q fail2ban"
	if strings.Join(calls, ";") != want {
		t.Fatalf("%v", calls)
	}
	// Без Exec точку с состоянием создать нельзя (R13); кривые имена не проходят.
	if _, err := (&Store{Dir: filepath.Join(root, "rb2")}).CreateState(op, nil, nil, st); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	for _, n := range []string{"../../etc/shadow", "net/ipv4", "", "a b"} {
		if _, ok := SysctlPath(sys, n); ok {
			t.Errorf("%q принят", n)
		}
	}
	if validUnit("--now") || !validUnit("ssh@1-2.service") {
		t.Fatal("validUnit")
	}
}

// Каталог над файлом подменён ссылкой после точки отката (домашний каталог пользователя): возврат отказывает,
// ни запись, ни удаление, ни права не уходят за ссылку.
func TestRestoreRefusesSymlinkedDir(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	other := filepath.Join(root, "other")
	for _, d := range []string{home, other} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	keys := filepath.Join(home, "authorized_keys")
	created := filepath.Join(home, "new")
	if err := os.WriteFile(keys, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(other, "authorized_keys")
	if err := os.WriteFile(victim, []byte("victim"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(other, "new"), []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := &Store{Dir: filepath.Join(root, "rb")}
	if _, err := s.Create(op, []string{keys, created}, nil); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(home, home+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(other, home); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Restore(op); err == nil {
		t.Fatal("возврат через каталог-ссылку прошёл")
	}
	raw, _ := os.ReadFile(victim)
	st, _ := os.Stat(victim)
	if string(raw) != "victim" || st.Mode().Perm() != 0o644 {
		t.Fatalf("чужой файл изменён: %q %v", raw, st.Mode())
	}
	if _, err := os.Stat(filepath.Join(other, "new")); err != nil {
		t.Fatalf("чужой файл удалён: %v", err)
	}
}
