// SPDX-License-Identifier: AGPL-3.0-only

package security

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
)

func init() {
	register(Check{Code: "USER_UID0_EXTRA", Run: checkUID0})
	register(Check{Code: "USER_EMPTY_PASSWORD", Run: checkEmptyPassword})
	register(Check{Code: "USER_NO_ADMIN", Run: checkNoAdmin})
	register(Check{Code: "SUDO_NOPASSWD_ALL", Run: checkNopasswd})
	register(Check{Code: "USER_SERVICE_SHELL", Run: checkServiceShell})
	register(Check{Code: "PERM_SYSTEM_FILES", Run: checkSystemFiles})
	register(Check{Code: "PERM_USER_SSH_DIR", Run: checkUserSSHDir})
	register(Check{Code: "PERM_WORLD_WRITABLE", Run: checkWorldWritable})
	register(Check{Code: "PERM_CRON", Run: checkCron})
	register(Check{Code: "KERNEL_ASLR_OFF", Run: checkASLR})
	register(Check{Code: "SYSCTL_NETWORK", Run: checkSysctl})
	register(Check{Code: "REBOOT_REQUIRED", Run: checkReboot})
	register(Check{Code: "DISK_SPACE_LOW", Run: func(ctx context.Context, s *Scan) []Finding { return checkDisk(s, false) }})
	register(Check{Code: "DISK_INODES_LOW", Run: func(ctx context.Context, s *Scan) []Finding { return checkDisk(s, true) }})
}

func usersOr(s *Scan) ([]User, []Finding) {
	u, err := s.Users()
	if err != nil {
		return nil, []Finding{failed(ErrReadFailed, err)}
	}
	return u, nil
}

func checkUID0(_ context.Context, s *Scan) []Finding {
	users, f := usersOr(s)
	if f != nil {
		return f
	}
	var out []Finding
	for _, u := range users {
		if u.UID == 0 && u.Name != "root" {
			out = append(out, fail(u.Name, "учётная запись "+u.Name+" с UID 0"))
		}
	}
	return out
}

func checkEmptyPassword(_ context.Context, s *Scan) []Finding {
	users, f := usersOr(s)
	if f != nil {
		return f
	}
	if _, err := os.Stat(s.sys.path("/etc/shadow")); err != nil {
		return []Finding{failed(ErrReadFailed, err)}
	}
	var out []Finding
	for _, u := range users {
		if u.EmptyPassword {
			out = append(out, fail(u.Name, "у записи "+u.Name+" пустой пароль"))
		}
	}
	return out
}

// admins — пользователи (не root) с правом sudo: участники групп sudo и admin и записи в sudoers с ALL.
func admins(s *Scan) ([]string, error) {
	members, _, err := s.groupMembers()
	if err != nil {
		return nil, err
	}
	set := map[string]bool{}
	for _, g := range []string{"sudo", "admin", "wheel"} {
		for _, m := range members[g] {
			if m != "root" {
				set[m] = true
			}
		}
	}
	for _, r := range sudoRules(s.sys) {
		if r.user != "root" && !strings.HasPrefix(r.user, "%") && strings.Contains(r.spec, "ALL") {
			set[r.user] = true
		}
	}
	out := make([]string, 0, len(set))
	for n := range set {
		out = append(out, n)
	}
	return out, nil
}

func checkNoAdmin(_ context.Context, s *Scan) []Finding {
	a, err := admins(s)
	if err != nil {
		return []Finding{failed(ErrReadFailed, err)}
	}
	if len(a) == 0 {
		return []Finding{fail("", "нет пользователя с sudo, кроме root")}
	}
	return []Finding{pass("", strconv.Itoa(len(a))+" пользователей с sudo")}
}

type sudoRule struct {
	file, user, spec string
}

// sudoRules — строки правил /etc/sudoers и /etc/sudoers.d/* (без Defaults, алиасов и include).
func sudoRules(sys *System) []sudoRule {
	files := []string{"/etc/sudoers"}
	ents, _ := os.ReadDir(sys.path("/etc/sudoers.d"))
	for _, e := range ents {
		n := e.Name()
		// sudo пропускает файлы с точкой и оканчивающиеся на ~ (man sudoers, @includedir).
		if !e.IsDir() && !strings.Contains(n, ".") && !strings.HasSuffix(n, "~") {
			files = append(files, "/etc/sudoers.d/"+n)
		}
	}
	var out []sudoRule
	for _, f := range files {
		ls, err := sys.lines(f)
		if err != nil {
			continue
		}
		for _, l := range ls {
			if strings.HasPrefix(l, "Defaults") || strings.HasPrefix(l, "@") || strings.HasSuffix(l, "_Alias") ||
				strings.Contains(strings.SplitN(l, " ", 2)[0], "_Alias") {
				continue
			}
			user, spec, ok := strings.Cut(l, " ")
			if !ok {
				user, spec, ok = strings.Cut(l, "\t")
			}
			if ok {
				out = append(out, sudoRule{file: f, user: user, spec: strings.TrimSpace(spec)})
			}
		}
	}
	return out
}

func checkNopasswd(_ context.Context, s *Scan) []Finding {
	var out []Finding
	managed := s.sys.accessManaged()
	for _, r := range sudoRules(s.sys) {
		if r.user == "root" {
			continue
		}
		// Правило доступа Trassa (E16): пользователь из реестра с выданным sudo, файл trassa-<user> побайтно
		// равен правилу Trassa. Чужой файл под тем же префиксом или с другим содержимым — находка.
		if sudo, ok := managed[r.user]; ok && sudo && r.file == "/etc/sudoers.d/trassa-"+r.user && s.sys.accessSudoRule(r.user) {
			continue
		}
		spec := strings.ReplaceAll(r.spec, " ", "")
		if strings.Contains(spec, "NOPASSWD:ALL") {
			out = append(out, fail(r.user, fmt.Sprintf("%s: %s без пароля на все команды", r.file, r.user)))
		}
	}
	return out
}

func checkServiceShell(_ context.Context, s *Scan) []Finding {
	users, f := usersOr(s)
	if f != nil {
		return f
	}
	var out []Finding
	for _, u := range users {
		// Служебные записи: UID 1–999 (Debian: системные записи ниже 1000), кроме тех, что входят по своей природе.
		if u.UID > 0 && u.UID < 1000 && u.CanLogin() && u.Name != "sync" {
			out = append(out, fail(u.Name, "служебная запись "+u.Name+" с оболочкой "+u.Shell))
		}
	}
	return out
}

// fileMode — права, uid и gid файла; ссылка не проходится.
func (sys *System) fileMode(p string) (fs.FileMode, int, int, error) {
	fi, err := os.Lstat(sys.path(p))
	if err != nil {
		return 0, 0, 0, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fi.Mode(), -1, -1, nil
	}
	return fi.Mode(), int(st.Uid), int(st.Gid), nil
}

// permRule — файл не шире max и принадлежит root.
type permRule struct {
	path string
	max  fs.FileMode
}

func checkPerms(s *Scan, rules []permRule) []Finding {
	var out []Finding
	for _, r := range rules {
		mode, uid, _, err := s.sys.fileMode(r.path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			out = append(out, Finding{Subject: r.path, State: agentv1.CheckState_CHECK_STATE_ERROR, Error: ErrReadFailed, Evidence: err.Error()})
			continue
		}
		perm := mode.Perm()
		if perm&^r.max != 0 || uid != s.sys.RootUID {
			out = append(out, fail(r.path, fmt.Sprintf("%s: права %04o, владелец uid %d; нужно не шире %04o и root", r.path, perm, uid, r.max)))
		}
	}
	return out
}

func checkSystemFiles(_ context.Context, s *Scan) []Finding {
	return checkPerms(s, []permRule{
		{"/etc/passwd", 0o644}, {"/etc/group", 0o644}, {"/etc/shadow", 0o640}, {"/etc/gshadow", 0o640},
		{"/etc/passwd-", 0o644}, {"/etc/group-", 0o644}, {"/etc/shadow-", 0o640}, {"/etc/gshadow-", 0o640},
	})
}

func checkCron(_ context.Context, s *Scan) []Finding {
	return checkPerms(s, []permRule{
		{"/etc/crontab", 0o644}, {"/etc/cron.d", 0o755}, {"/etc/cron.hourly", 0o755}, {"/etc/cron.daily", 0o755},
		{"/etc/cron.weekly", 0o755}, {"/etc/cron.monthly", 0o755},
	})
}

func checkUserSSHDir(_ context.Context, s *Scan) []Finding {
	users, f := usersOr(s)
	if f != nil {
		return f
	}
	var out []Finding
	for _, u := range users {
		if u.Home == "" || u.Home == "/" || u.Home == "/nonexistent" {
			continue
		}
		for _, p := range []string{filepath.Join(u.Home, ".ssh"), filepath.Join(u.Home, ".ssh", "authorized_keys")} {
			mode, uid, _, err := s.sys.fileMode(p)
			if err != nil || mode&fs.ModeSymlink != 0 {
				continue
			}
			if mode.Perm()&0o022 != 0 || (uid != u.UID && uid != s.sys.RootUID) {
				out = append(out, fail(p, fmt.Sprintf("%s: права %04o, владелец uid %d — запись другим или чужой владелец", p, mode.Perm(), uid)))
			}
		}
	}
	return out
}

// Системные каталоги для PERM_WORLD_WRITABLE и предел обхода: тяжёлая проверка ограничена числом файлов.
var (
	worldWritableDirs = []string{"/etc", "/usr/bin", "/usr/sbin", "/usr/lib/systemd", "/bin", "/sbin", "/boot"}
	maxWalk           = 200000
)

func checkWorldWritable(ctx context.Context, s *Scan) []Finding {
	var out []Finding
	n := 0
	for _, d := range worldWritableDirs {
		root := s.sys.path(d)
		if fi, err := os.Lstat(root); err != nil || !fi.IsDir() {
			continue // /bin в новых системах — ссылка на /usr/bin
		}
		_ = filepath.WalkDir(root, func(p string, e fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			n++
			if n > maxWalk || ctx.Err() != nil {
				return filepath.SkipAll
			}
			if e.Type()&fs.ModeSymlink != 0 {
				return nil
			}
			fi, err := e.Info()
			if err != nil {
				return nil
			}
			// Каталог с липким битом (как /tmp) — допустим.
			if fi.Mode().Perm()&0o002 != 0 && !(fi.IsDir() && fi.Mode()&fs.ModeSticky != 0) {
				rel := "/" + strings.TrimPrefix(strings.TrimPrefix(p, s.sys.Root), "/")
				out = append(out, fail(rel, fmt.Sprintf("%s доступен всем на запись (%04o)", rel, fi.Mode().Perm())))
			}
			return nil
		})
	}
	if n > maxWalk {
		out = append(out, Finding{State: agentv1.CheckState_CHECK_STATE_ERROR, Error: ErrTimeout, Evidence: "файлов больше предела обхода"})
	}
	return out
}

func readSysctl(s *Scan, name string) (string, error) {
	b, err := os.ReadFile(s.sys.path("/proc/sys/" + strings.ReplaceAll(name, ".", "/")))
	return strings.TrimSpace(string(b)), err
}

func checkASLR(_ context.Context, s *Scan) []Finding {
	v, err := readSysctl(s, "kernel.randomize_va_space")
	if err != nil {
		return []Finding{failed(ErrReadFailed, err)}
	}
	if v != "2" {
		return []Finding{fail("kernel.randomize_va_space", "kernel.randomize_va_space = "+v+", нужно 2")}
	}
	return nil
}

// Сетевые параметры ядра и их безопасные значения. Пересылка пакетов (ip_forward) не проверяется: её
// включают Docker и приватная сеть.
var sysctlWant = []struct{ name, want string }{
	{"net.ipv4.conf.all.accept_redirects", "0"},
	{"net.ipv4.conf.default.accept_redirects", "0"},
	{"net.ipv4.conf.all.send_redirects", "0"},
	{"net.ipv4.conf.all.accept_source_route", "0"},
	{"net.ipv4.conf.all.log_martians", "1"},
	{"net.ipv4.icmp_echo_ignore_broadcasts", "1"},
	{"net.ipv4.icmp_ignore_bogus_error_responses", "1"},
	{"net.ipv4.tcp_syncookies", "1"},
	{"net.ipv6.conf.all.accept_redirects", "0"},
	{"net.ipv6.conf.all.accept_source_route", "0"},
}

func checkSysctl(_ context.Context, s *Scan) []Finding {
	var out []Finding
	for _, p := range sysctlWant {
		v, err := readSysctl(s, p.name)
		if os.IsNotExist(err) {
			continue // IPv6 выключен
		}
		if err != nil {
			out = append(out, Finding{Subject: p.name, State: agentv1.CheckState_CHECK_STATE_ERROR, Error: ErrReadFailed, Evidence: err.Error()})
			continue
		}
		if v != p.want {
			out = append(out, fail(p.name, fmt.Sprintf("%s = %s, рекомендуется %s", p.name, v, p.want)))
		}
	}
	return out
}

func checkReboot(_ context.Context, s *Scan) []Finding {
	if _, err := os.Stat(s.sys.path("/run/reboot-required")); err == nil {
		ev := "обновление ждёт перезагрузки"
		if b, err := os.ReadFile(s.sys.path("/run/reboot-required.pkgs")); err == nil {
			pkgs := strings.Fields(string(b))
			if len(pkgs) > 0 {
				ev += ": " + strings.Join(pkgs[:min(len(pkgs), 20)], ", ")
			}
		}
		return []Finding{fail("", ev)}
	}
	return nil
}

// checkDisk — разделы от 90% по месту или инодам; разделы — как у метрик (локальные ФС, одна точка на устройство).
func checkDisk(s *Scan, inodes bool) []Finding {
	if s.sys.Statfs == nil {
		return []Finding{failed(ErrUnsupported, fmt.Errorf("statfs недоступен"))}
	}
	mounts, err := diskMounts(s.sys)
	if err != nil {
		return []Finding{failed(ErrReadFailed, err)}
	}
	var out []Finding
	for _, m := range mounts {
		st, err := s.sys.Statfs(m)
		if err != nil {
			continue
		}
		var used float64
		switch {
		case inodes && st.Files > 0 && st.Files >= st.Ffree:
			used = 100 * float64(st.Files-st.Ffree) / float64(st.Files)
		case !inodes && st.Blocks >= st.Bfree && st.Blocks-st.Bfree+st.Bavail > 0:
			used = 100 * float64(st.Blocks-st.Bfree) / float64(st.Blocks-st.Bfree+st.Bavail)
		default:
			continue
		}
		if used > 90 {
			what := "место"
			if inodes {
				what = "inode"
			}
			out = append(out, fail(m, fmt.Sprintf("%s: занято %.1f%% (%s)", m, used, what)))
		}
	}
	return out
}
