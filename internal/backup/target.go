// SPDX-License-Identifier: AGPL-3.0-only

package backup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/fsutil"
)

// Файлы цели SERVER.
const (
	SSHDropInDir = "/etc/ssh/sshd_config.d"
	TargetKeyDir = "/etc/ssh/trassa-bk"
	// TargetStateDir — что Trassa настроила на цели: каталог репозитория и версии программ (для remove и prune).
	TargetStateDir = "/etc/trassa/backup-target"
	sshdMain       = "/etc/ssh/sshd_config"
	hostKeyFile    = "/etc/ssh/ssh_host_ed25519_key.pub"
	// targetShell — принудительная команда sshd запускается через оболочку пользователя; других команд ключ
	// не выполнит (ForceCommand и restrict), пароля у пользователя нет.
	targetShell = "/bin/sh"
)

// ErrTargetPrecondition — сервер-цель не готов (BACKUP_TARGET_PRECONDITION).
var ErrTargetPrecondition = errors.New("BACKUP_TARGET_PRECONDITION")

var includeRe = regexp.MustCompile(`(?mi)^\s*Include\s+/etc/ssh/sshd_config\.d/\*\.conf\s*$`)

// Target — цель под корнем Root ("/" на сервере). BinDir — программы цели, доступные пользователю цели
// (/usr/local/lib/trassa, 0755); StageDir — куда агент скачал архивы операции.
type Target struct {
	Root     string
	BinDir   string
	StageDir func(op string) string
	Run      func(ctx context.Context, name string, args ...string) ([]byte, error)
}

type targetState struct {
	Path   string `json:"path"`
	Rclone string `json:"rclone"`
	Restic string `json:"restic"`
}

func (t *Target) path(p string) string { return filepath.Join(t.Root, p) }

func dropIn(u string) string    { return filepath.Join(SSHDropInDir, u+".conf") }
func keyFile(u string) string   { return filepath.Join(TargetKeyDir, u+".keys") }
func stateFile(u string) string { return filepath.Join(TargetStateDir, u+".json") }

// Paths — файлы, которые меняет цель: настройки sshd, ключ, состояние, учётные записи (точка отката CONFIG).
func (t *Target) Paths(u string) []string {
	out := []string{t.path(dropIn(u)), t.path(keyFile(u)), t.path(stateFile(u))}
	for _, f := range []string{"/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow"} {
		if _, err := os.Stat(t.path(f)); err == nil {
			out = append(out, t.path(f))
		}
	}
	return out
}

// RcloneCommand — принудительная команда ключа источника: только добавление в каталог цели.
func RcloneCommand(rclone, repo string) string {
	return rclone + " serve restic --stdio --append-only " + repo
}

func dropInText(u, keys, command string) string {
	return fmt.Sprintf(`# Trassa: цель бэкапов %[1]s — ключ источника только добавляет копии (rclone serve restic --append-only).
# Файл пишет Trassa.
Match User %[1]s
	AuthorizedKeysFile %[2]s
	ForceCommand %[3]s
	PasswordAuthentication no
	KbdInteractiveAuthentication no
	AllowTcpForwarding no
	AllowStreamLocalForwarding no
	X11Forwarding no
	AllowAgentForwarding no
	PermitTTY no
	PermitTunnel no
	PermitUserRC no
`, u, keys, command)
}

func (t *Target) loadState(u string) (*targetState, error) {
	raw, err := fsutil.ReadLimited(t.path(stateFile(u)), 64<<10)
	if err != nil {
		return nil, fmt.Errorf("%w: цели %s нет: %v", ErrTargetPrecondition, u, err)
	}
	var st targetState
	if err := json.Unmarshal(raw, &st); err != nil || !AllowedPath(st.Path) || !versionRe.MatchString(st.Restic) {
		return nil, fmt.Errorf("%w: состояние цели %s повреждено", ErrTargetPrecondition, u)
	}
	return &st, nil
}

// lookupUser — uid и gid пользователя цели; учётная запись обязана быть нашей (имя trassa-bk-*).
func lookupUser(u string) (int, int, error) {
	acc, err := user.Lookup(u)
	if err != nil {
		return 0, 0, err
	}
	uid, err := strconv.Atoi(acc.Uid)
	if err != nil {
		return 0, 0, err
	}
	gid, err := strconv.Atoi(acc.Gid)
	if err != nil {
		return 0, 0, err
	}
	if uid == 0 || gid == 0 {
		return 0, 0, fmt.Errorf("%w: %s с uid или gid 0", ErrTargetPrecondition, u)
	}
	return uid, gid, nil
}

// repoDir — каталог репозитория: создаётся владельцем-пользователем 0700; существующий — только пустой
// каталог root или уже его каталог (повтор операции). Ссылки на пути не проходятся.
func (t *Target) repoDir(p string, uid, gid int) error {
	full := t.path(p)
	parent := filepath.Dir(full)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return err
	}
	if err := os.Mkdir(full, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	f, err := fsutil.OpenNoFollow(full, unix.O_RDONLY|unix.O_DIRECTORY)
	if err != nil {
		return fmt.Errorf("%w: %s: %v", ErrTargetPrecondition, p, err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	sys, _ := st.Sys().(*syscall.Stat_t)
	owner := -1
	if sys != nil {
		owner = int(sys.Uid)
	}
	if owner != uid {
		names, _ := f.Readdirnames(1)
		if owner != 0 && owner != os.Getuid() || len(names) > 0 {
			return fmt.Errorf("%w: каталог %s уже занят (владелец %d, не пуст или чужой)", ErrTargetPrecondition, p, owner)
		}
	}
	id, err := fsutil.IDOf(f)
	if err != nil {
		return err
	}
	return fsutil.ChmodChownNoFollow(full, id, 0o700, uid, gid)
}

// Ensure — программы цели (rclone и restic, sha256 из подписанной операции), пользователь без пароля,
// каталог репозитория пользователя, ключ источника с restrict,from=, блок Match с принудительной командой;
// sshd -t и перечитывание настроек.
func (t *Target) Ensure(ctx context.Context, op string, p *agentv1.BackupTargetEnsureParams) (*agentv1.BackupTargetEnsureResult, error) {
	main, err := os.ReadFile(t.path(sshdMain))
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrTargetPrecondition, sshdMain, err)
	}
	if !includeRe.Match(main) {
		return nil, fmt.Errorf("%w: в %s нет Include %s/*.conf", ErrTargetPrecondition, sshdMain, SSHDropInDir)
	}
	hostKey, err := os.ReadFile(t.path(hostKeyFile))
	if err != nil {
		return nil, fmt.Errorf("%w: ключ хоста ed25519: %v", ErrTargetPrecondition, err)
	}
	if err := os.MkdirAll(t.BinDir, 0o755); err != nil {
		return nil, err
	}
	// UMask помощника 0077: каталог программ цели должен быть доступен пользователю цели.
	if err := os.Chmod(t.BinDir, 0o755); err != nil {
		return nil, err
	}
	stage := t.StageDir(op)
	rclone, err := InstallRclone(ctx, stage, p.GetRclone().GetSha256(), p.GetRclone().GetVersion(), t.BinDir)
	if err != nil {
		return nil, err
	}
	if _, err := InstallRestic(ctx, stage, p.GetRestic().GetSha256(), p.GetRestic().GetVersion(), t.BinDir); err != nil {
		return nil, err
	}
	u := p.GetUnixUser()
	if _, err := user.Lookup(u); err != nil {
		var unknown user.UnknownUserError
		if !errors.As(err, &unknown) {
			return nil, err
		}
		if out, err := t.Run(ctx, "useradd", "--system", "--user-group", "--no-create-home", "--home-dir", "/nonexistent", "--shell", targetShell, u); err != nil {
			return nil, fmt.Errorf("useradd: %v %s", err, firstLine(out))
		}
	}
	// Пароль «*» — входа по паролю нет, а по ключу есть. «!» (useradd без пароля, usermod --lock) при UsePAM no
	// закрывает и вход по ключу (sshd считает учётную запись заблокированной).
	if out, err := t.Run(ctx, "usermod", "--shell", targetShell, "--password", "*", u); err != nil {
		return nil, fmt.Errorf("usermod: %v %s", err, firstLine(out))
	}
	uid, gid, err := lookupUser(u)
	if err != nil {
		return nil, err
	}
	if err := t.repoDir(p.GetPath(), uid, gid); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(t.path(TargetKeyDir), 0o755); err != nil {
		return nil, err
	}
	if err := os.Chmod(t.path(TargetKeyDir), 0o755); err != nil {
		return nil, err
	}
	keyLine := fmt.Sprintf("restrict,from=%q %s\n", p.GetSourceAddress(), p.GetSourcePublicKey())
	if err := fsutil.WriteFileAtomic(t.path(keyFile(u)), []byte(keyLine), 0o644, fsutil.Keep); err != nil {
		return nil, err
	}
	cmd := RcloneCommand(rclone, p.GetPath())
	if err := fsutil.WriteFileAtomic(t.path(dropIn(u)), []byte(dropInText(u, keyFile(u), cmd)), 0o644, fsutil.Keep); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(t.path(TargetStateDir), 0o700); err != nil {
		return nil, err
	}
	st, _ := json.Marshal(targetState{Path: p.GetPath(), Rclone: p.GetRclone().GetVersion(), Restic: p.GetRestic().GetVersion()})
	if err := fsutil.WriteFileAtomic(t.path(stateFile(u)), st, 0o600, fsutil.Keep); err != nil {
		return nil, err
	}
	if err := t.reloadSSHD(ctx); err != nil {
		return nil, err
	}
	res := &agentv1.BackupTargetEnsureResult{
		Access: agentv1.BackupAccess_BACKUP_ACCESS_APPEND_ONLY, RepoPath: p.GetPath(),
		HostPublicKey: hostKeyLine(hostKey),
	}
	if free, err := FreeBytes(t.path(p.GetPath())); err == nil {
		res.FreeBytes = free
	}
	return res, nil
}

// hostKeyLine — «ssh-ed25519 AAAA…» без комментария.
func hostKeyLine(b []byte) string {
	f := strings.Fields(string(b))
	if len(f) < 2 {
		return ""
	}
	return f[0] + " " + f[1]
}

// Check — sshd применяет к пользователю принудительную команду «только добавление» и запреты.
func (t *Target) Check(ctx context.Context, p *agentv1.BackupTargetEnsureParams) error {
	out, err := t.Run(ctx, "sshd", "-T", "-C", fmt.Sprintf("user=%s,host=trassa,addr=%s", p.GetUnixUser(), p.GetSourceAddress()))
	if err != nil {
		return fmt.Errorf("sshd -T: %v", err)
	}
	s := strings.ToLower(string(out))
	cmd := strings.ToLower(RcloneCommand(RclonePath(t.BinDir, p.GetRclone().GetVersion()), p.GetPath()))
	for _, want := range []string{"forcecommand " + cmd, "permittty no", "allowtcpforwarding no", "passwordauthentication no"} {
		if !strings.Contains(s, want+"\n") {
			return fmt.Errorf("sshd не применяет %q к %s", want, p.GetUnixUser())
		}
	}
	return nil
}

func (t *Target) reloadSSHD(ctx context.Context) error {
	if out, err := t.Run(ctx, "sshd", "-t"); err != nil {
		return fmt.Errorf("sshd -t: %v %s", err, firstLine(out))
	}
	// Активный ssh.service (или sshd.service) перечитывает настройки; при ssh.socket sshd читает их на каждое
	// соединение сам.
	for _, unit := range []string{"ssh.service", "sshd.service"} {
		if _, err := t.Run(ctx, "systemctl", "is-active", "--quiet", unit); err == nil {
			if out, err := t.Run(ctx, "systemctl", "reload", unit); err != nil {
				return fmt.Errorf("systemctl reload %s: %v %s", unit, err, firstLine(out))
			}
			return nil
		}
	}
	return nil
}

// Remove — снять цель: путь обязан совпадать с каталогом из состояния Trassa (иначе это не наша цель и
// данные не удаляются); ключ, блок sshd, состояние и пользователь удаляются, данные — только при deleteData.
func (t *Target) Remove(ctx context.Context, p *agentv1.BackupTargetRemoveParams) error {
	u := p.GetUnixUser()
	st, err := t.loadState(u)
	if err != nil {
		return err
	}
	if st.Path != p.GetPath() {
		return fmt.Errorf("%w: путь %s не совпадает с каталогом цели %s", ErrTargetPrecondition, p.GetPath(), u)
	}
	for _, f := range []string{dropIn(u), keyFile(u), stateFile(u)} {
		if err := fsutil.RemoveSync(t.path(f)); err != nil {
			return err
		}
	}
	if err := t.reloadSSHD(ctx); err != nil {
		return err
	}
	if _, err := user.Lookup(u); err == nil {
		if out, err := t.Run(ctx, "userdel", u); err != nil {
			return fmt.Errorf("userdel: %v %s", err, firstLine(out))
		}
	}
	if p.GetDeleteData() {
		return os.RemoveAll(t.path(p.GetPath()))
	}
	return nil
}

// PruneRestic — restic для чистки репозитория цели на самой цели: от пользователя цели (файлы остаются его,
// rclone продолжает их читать), пароль — во временном файле пользователя на время операции.
func (t *Target) PruneRestic(u string, password []byte) (*Restic, func(), error) {
	st, err := t.loadState(u)
	if err != nil {
		return nil, nil, err
	}
	uid, gid, err := lookupUser(u)
	if err != nil {
		return nil, nil, err
	}
	work, err := os.MkdirTemp(t.path("/var/tmp"), "trassa-prune-")
	if err != nil {
		return nil, nil, err
	}
	cleanup := func() { _ = os.RemoveAll(work) }
	pw, _, err := TempPasswordFile(work, password)
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	for _, p := range []string{work, pw} {
		if err := os.Lchown(p, uid, gid); err != nil {
			cleanup()
			return nil, nil, err
		}
	}
	r := &Restic{
		Bin: ResticPath(t.BinDir, st.Restic), CacheDir: filepath.Join(work, "cache"), TmpDir: work,
		Repo: &Repo{URL: t.path(st.Path), Password: password, Env: map[string]string{}}, PasswordFile: pw, Nice: 10,
		Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)},
	}
	return r, cleanup, nil
}
