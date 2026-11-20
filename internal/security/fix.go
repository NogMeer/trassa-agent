// SPDX-License-Identifier: AGPL-3.0-only

package security

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/fsutil"
	"github.com/NogMeer/trassa-agent/internal/rollback"
)

// Ошибки плана исправления (коды итога операции).
var (
	// ErrSubject — объекта нет среди текущих находок проверки: исправлять нечего или запрос устарел.
	ErrSubject = errors.New("FIX_SUBJECT_NOT_FOUND")
	// ErrPrecondition — исправление на этой системе невозможно (нет пакета, службы).
	ErrPrecondition = errors.New("FIX_PRECONDITION")
)

// FixPlan — что сделает исправление: файлы и состояние для точки отката, предпросмотр, применение, проверка.
type FixPlan struct {
	Summary  string
	Paths    []string
	Services []string
	State    rollback.State
	Changes  []*agentv1.FileChange
	Notes    []string
	Apply    func(ctx context.Context) error
	// Verify — проверка этого кода снова; объекты исправления больше не FAIL.
	Verify func(ctx context.Context) error
}

// Fix — исправление одного кода каталога (security.fix.<код>). Класс риска — в ops.
type Fix struct {
	Code string
	Plan func(ctx context.Context, s *Scan, subjects []string) (*FixPlan, error)
}

var fixes = map[string]Fix{}

func registerFix(f Fix) {
	// Что код есть среди проверок, сверяет тест: порядок init файлов пакета не гарантирует регистрацию раньше.
	if _, dup := fixes[f.Code]; dup {
		panic("security: исправление " + f.Code)
	}
	fixes[f.Code] = f
}

// FixCodes — коды, у которых есть исправление.
func FixCodes() []string {
	out := make([]string, 0, len(fixes))
	for c := range fixes {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// ValidateFix — схема security.fix: непустой список объектов (R1).
func ValidateFix(code string, p *agentv1.SecurityFixParams) error {
	if _, ok := fixes[code]; !ok {
		return fmt.Errorf("исправления для %q нет", code)
	}
	if len(p.GetSubjects()) == 0 || len(p.GetSubjects()) > MaxSubjects {
		return fmt.Errorf("subjects: от 1 до %d", MaxSubjects)
	}
	for _, s := range p.GetSubjects() {
		if len(s) > 4096 || strings.ContainsRune(s, 0) {
			return errors.New("subjects: длина или символы")
		}
	}
	return nil
}

// PlanFix строит план по текущему состоянию: объекты сверяются со свежим результатом проверки.
func PlanFix(ctx context.Context, sys *System, code string, subjects []string) (*FixPlan, error) {
	f, ok := fixes[code]
	if !ok {
		return nil, fmt.Errorf("%w: исправления для %s нет", ErrPrecondition, code)
	}
	s := newScan(sys)
	p, err := f.Plan(ctx, s, subjects)
	if err != nil {
		return nil, err
	}
	if p.Verify == nil {
		p.Verify = verifyCheck(sys, code, subjects)
	}
	return p, nil
}

// failing — объекты проверки code в состоянии FAIL сейчас.
func failing(ctx context.Context, s *Scan, code string) (map[string]Finding, error) {
	out := map[string]Finding{}
	for _, f := range runOne(ctx, s, registry[code]) {
		switch f.State {
		case agentv1.CheckState_CHECK_STATE_FAIL:
			out[f.Subject] = f
		case agentv1.CheckState_CHECK_STATE_ERROR:
			return nil, fmt.Errorf("%s: %s %s", code, f.Error, f.Evidence)
		}
	}
	return out, nil
}

// pick — запрошенные объекты, каждый должен быть среди текущих FAIL.
func pick(ctx context.Context, s *Scan, code string, subjects []string) ([]Finding, error) {
	cur, err := failing(ctx, s, code)
	if err != nil {
		return nil, err
	}
	var out []Finding
	seen := map[string]bool{}
	for _, sub := range subjects {
		f, ok := cur[sub]
		if !ok {
			return nil, fmt.Errorf("%w: %s %q", ErrSubject, code, sub)
		}
		if !seen[sub] {
			seen[sub] = true
			out = append(out, f)
		}
	}
	return out, nil
}

func verifyCheck(sys *System, code string, subjects []string) func(context.Context) error {
	return func(ctx context.Context) error {
		cur, err := failing(ctx, newScan(sys), code)
		if err != nil {
			return err
		}
		for _, sub := range subjects {
			if f, bad := cur[sub]; bad {
				return fmt.Errorf("%s %q всё ещё не проходит: %s", code, sub, f.Evidence)
			}
		}
		return nil
	}
}

// ---------- Права и владельцы ----------

type permTarget struct {
	path string
	mode fs.FileMode
	uid  int
}

func init() {
	for code, rules := range map[string]func(*Scan) map[string]fs.FileMode{
		"PERM_SYSTEM_FILES": func(*Scan) map[string]fs.FileMode {
			return rulesMap([]permRule{{"/etc/passwd", 0o644}, {"/etc/group", 0o644}, {"/etc/shadow", 0o640}, {"/etc/gshadow", 0o640},
				{"/etc/passwd-", 0o644}, {"/etc/group-", 0o644}, {"/etc/shadow-", 0o640}, {"/etc/gshadow-", 0o640}})
		},
		"PERM_CRON": func(*Scan) map[string]fs.FileMode {
			return rulesMap([]permRule{{"/etc/crontab", 0o644}, {"/etc/cron.d", 0o755}, {"/etc/cron.hourly", 0o755},
				{"/etc/cron.daily", 0o755}, {"/etc/cron.weekly", 0o755}, {"/etc/cron.monthly", 0o755}})
		},
		"SSH_CONFIG_PERMS": func(s *Scan) map[string]fs.FileMode {
			m := map[string]fs.FileMode{}
			for _, r := range sshPermRules(s) {
				m[r.path] = r.max
			}
			return m
		},
	} {
		registerFix(Fix{Code: code, Plan: func(ctx context.Context, s *Scan, subjects []string) (*FixPlan, error) {
			found, err := pick(ctx, s, code, subjects)
			if err != nil {
				return nil, err
			}
			max := rules(s)
			var targets []permTarget
			for _, f := range found {
				m, ok := max[f.Subject]
				if !ok {
					return nil, fmt.Errorf("%w: %q", ErrSubject, f.Subject)
				}
				targets = append(targets, permTarget{path: f.Subject, mode: m, uid: s.sys.RootUID})
			}
			return permPlan(s.sys, targets, func(cur fs.FileMode, lim fs.FileMode) fs.FileMode { return cur & lim })
		}})
	}
	registerFix(Fix{Code: "PERM_WORLD_WRITABLE", Plan: func(ctx context.Context, s *Scan, subjects []string) (*FixPlan, error) {
		found, err := pick(ctx, s, "PERM_WORLD_WRITABLE", subjects)
		if err != nil {
			return nil, err
		}
		var targets []permTarget
		for _, f := range found {
			targets = append(targets, permTarget{path: f.Subject, uid: -1})
		}
		return permPlan(s.sys, targets, func(cur, _ fs.FileMode) fs.FileMode { return cur &^ 0o002 })
	}})
	registerFix(Fix{Code: "PERM_USER_SSH_DIR", Plan: func(ctx context.Context, s *Scan, subjects []string) (*FixPlan, error) {
		found, err := pick(ctx, s, "PERM_USER_SSH_DIR", subjects)
		if err != nil {
			return nil, err
		}
		users, err := s.Users()
		if err != nil {
			return nil, err
		}
		var targets []permTarget
		for _, f := range found {
			uid := -1
			for _, u := range users {
				if u.Home != "" && strings.HasPrefix(f.Subject, filepath.Join(u.Home, ".ssh")) {
					uid = u.UID
				}
			}
			if uid < 0 {
				return nil, fmt.Errorf("%w: владелец %q не найден", ErrSubject, f.Subject)
			}
			targets = append(targets, permTarget{path: f.Subject, uid: uid})
		}
		return permPlan(s.sys, targets, func(cur, _ fs.FileMode) fs.FileMode { return cur &^ 0o022 })
	}})
}

func rulesMap(rs []permRule) map[string]fs.FileMode {
	m := map[string]fs.FileMode{}
	for _, r := range rs {
		m[r.path] = r.max
	}
	return m
}

// permPlan — снять лишние права (newMode) и поставить владельца uid (−1 — не менять); особые биты сохраняются.
func permPlan(sys *System, targets []permTarget, newMode func(cur, lim fs.FileMode) fs.FileMode) (*FixPlan, error) {
	p := &FixPlan{}
	type step struct {
		real string
		mode fs.FileMode
		uid  int
		gid  int
	}
	var steps []step
	for _, t := range targets {
		real := sys.path(t.path)
		st, err := os.Lstat(real)
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %v", ErrSubject, t.path, err)
		}
		if st.Mode()&fs.ModeSymlink != 0 {
			return nil, fmt.Errorf("%w: %s — ссылка", ErrSubject, t.path)
		}
		special := st.Mode() & (fs.ModeSetuid | fs.ModeSetgid | fs.ModeSticky)
		m := newMode(st.Mode().Perm(), t.mode) | special
		_, uid, gid, _ := sys.fileMode(t.path)
		to := uid
		if t.uid >= 0 {
			to = t.uid
		}
		p.Paths = append(p.Paths, real)
		steps = append(steps, step{real: real, mode: m, uid: to, gid: gid})
		diff := fmt.Sprintf("права %04o → %04o", st.Mode().Perm(), m.Perm())
		if to != uid {
			diff += fmt.Sprintf(", владелец uid %d → %d", uid, to)
		}
		p.Changes = append(p.Changes, &agentv1.FileChange{Path: t.path, Kind: agentv1.FileChangeKind_FILE_CHANGE_KIND_MODIFY, Diff: diff})
	}
	p.Summary = fmt.Sprintf("Исправить права: объектов %d", len(steps))
	p.Apply = func(context.Context) error {
		for _, s := range steps {
			if err := os.Lchown(s.real, s.uid, s.gid); err != nil {
				return err
			}
			// chown снимает setuid и setgid — права ставятся после владельца.
			if err := os.Chmod(s.real, s.mode); err != nil {
				return err
			}
		}
		return nil
	}
	return p, nil
}

// ---------- Параметры ядра ----------

// SysctlFile — файл параметров Trassa. Его значения применяются при загрузке; при Docker и приватной сети
// пересылка пакетов в нём не трогается.
const SysctlFile = "/etc/sysctl.d/90-trassa-security.conf"

func init() {
	want := map[string]string{"kernel.randomize_va_space": "2"}
	for _, p := range sysctlWant {
		want[p.name] = p.want
	}
	for _, code := range []string{"SYSCTL_NETWORK", "KERNEL_ASLR_OFF"} {
		registerFix(Fix{Code: code, Plan: func(ctx context.Context, s *Scan, subjects []string) (*FixPlan, error) {
			found, err := pick(ctx, s, code, subjects)
			if err != nil {
				return nil, err
			}
			vals := map[string]string{}
			for _, f := range found {
				v, ok := want[f.Subject]
				if !ok {
					return nil, fmt.Errorf("%w: %q", ErrSubject, f.Subject)
				}
				vals[f.Subject] = v
			}
			return sysctlPlan(s.sys, vals)
		}})
	}
}

func sysctlPlan(sys *System, vals map[string]string) (*FixPlan, error) {
	conf := sys.path(SysctlFile)
	old, err := os.ReadFile(conf)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	merged := map[string]string{}
	for _, l := range strings.Split(string(old), "\n") {
		if k, v, ok := strings.Cut(l, "="); ok && !strings.HasPrefix(strings.TrimSpace(l), "#") {
			merged[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	prev := map[string]string{}
	for k, v := range vals {
		merged[k] = v
		cur, err := os.ReadFile(sys.path("/proc/sys/" + strings.ReplaceAll(k, ".", "/")))
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %v", ErrPrecondition, k, err)
		}
		prev[k] = strings.TrimSpace(string(cur))
	}
	keys := make([]string, 0, len(merged))
	for k := range merged {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString("# Trassa: параметры ядра центра безопасности. Файл пишет Trassa; откат — из панели.\n")
	for _, k := range keys {
		fmt.Fprintf(&b, "%s = %s\n", k, merged[k])
	}
	content := b.String()
	kind := agentv1.FileChangeKind_FILE_CHANGE_KIND_MODIFY
	if old == nil {
		kind = agentv1.FileChangeKind_FILE_CHANGE_KIND_CREATE
	}
	var diff strings.Builder
	for _, k := range sortedKeys(vals) {
		fmt.Fprintf(&diff, "%s: %s → %s\n", k, prev[k], vals[k])
	}
	return &FixPlan{
		Summary: fmt.Sprintf("Параметры ядра: %d", len(vals)),
		Paths:   []string{conf},
		State:   rollback.State{Sysctl: prev},
		Changes: []*agentv1.FileChange{{Path: SysctlFile, Kind: kind, Diff: diff.String()}},
		Apply: func(context.Context) error {
			if err := os.MkdirAll(filepath.Dir(conf), 0o755); err != nil {
				return err
			}
			if err := fsutil.WriteFileAtomic(conf, []byte(content), 0o644, fsutil.Keep); err != nil {
				return err
			}
			for _, k := range sortedKeys(vals) {
				p, ok := rollback.SysctlPath(sys.path("/proc/sys"), k)
				if !ok {
					return fmt.Errorf("параметр %q", k)
				}
				if err := os.WriteFile(p, []byte(vals[k]+"\n"), 0o644); err != nil {
					return fmt.Errorf("%s: %w", k, err)
				}
			}
			return nil
		},
	}, nil
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
