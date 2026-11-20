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
	"time"

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
	// Reader — пользователь-читатель (если выдан).
	Reader string `json:"reader,omitempty"`
}

func (t *Target) path(p string) string { return filepath.Join(t.Root, p) }

func dropIn(u string) string    { return filepath.Join(SSHDropInDir, u+".conf") }
func keyFile(u string) string   { return filepath.Join(TargetKeyDir, u+".keys") }
func stateFile(u string) string { return filepath.Join(TargetStateDir, u+".json") }

// Paths — файлы, которые меняет цель: настройки sshd, ключ, состояние, учётные записи (точка отката CONFIG).
func (t *Target) Paths(u string) []string {
	r := ReaderUser(u)
	out := []string{t.path(dropIn(u)), t.path(keyFile(u)), t.path(stateFile(u)), t.path(dropIn(r)), t.path(keyFile(r))}
	for _, f := range []string{"/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow"} {
		if _, err := os.Stat(t.path(f)); err == nil {
			out = append(out, t.path(f))
		}
	}
	return out
}

// RcloneCommand — принудительная команда ключа источника: только добавление в каталог цели.
// umask 0027: новые файлы репозитория читаемы группой владельца — пользователь-читатель (в этой группе) может
// их читать, прочие — нет.
func RcloneCommand(rclone, repo string) string {
	return "umask 0027 && exec " + rclone + " serve restic --stdio --append-only " + repo
}

// ReaderUser — пользователь-читатель цели: trassa-bk-<id> → trassa-bkr-<id>.
func ReaderUser(u string) string { return "trassa-bkr-" + strings.TrimPrefix(u, "trassa-bk-") }

func dropInText(u, keys, command string) string {
	return fmt.Sprintf(`# Trassa: цель бэкапов %[1]s — ключ только добавляет копии (rclone serve restic --append-only); читатель
# (trassa-bkr-*) к тому же не может писать: права файлов.
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

// repoDir — каталог репозитория: владелец — пользователь цели, 0750 (группа — для читателя); существующий — только пустой
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
	return fsutil.ChmodChownNoFollow(full, id, 0o750, uid, gid)
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
	reader := ""
	if p.GetReaderPublicKey() != "" {
		reader = ReaderUser(u)
		if err := t.ensureReader(ctx, u, reader, p, rclone, gid); err != nil {
			return nil, err
		}
	} else if err := t.removeReader(ctx, u); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(t.path(TargetStateDir), 0o700); err != nil {
		return nil, err
	}
	st, _ := json.Marshal(targetState{Path: p.GetPath(), Rclone: p.GetRclone().GetVersion(), Restic: p.GetRestic().GetVersion(), Reader: reader})
	if err := fsutil.WriteFileAtomic(t.path(stateFile(u)), st, 0o600, fsutil.Keep); err != nil {
		return nil, err
	}
	if err := t.reloadSSHD(ctx); err != nil {
		return nil, err
	}
	res := &agentv1.BackupTargetEnsureResult{
		Access: agentv1.BackupAccess_BACKUP_ACCESS_APPEND_ONLY, RepoPath: p.GetPath(),
		HostPublicKey: hostKeyLine(hostKey), ReaderUnixUser: reader,
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
	if p.GetReaderPublicKey() == "" {
		return nil
	}
	reader := ReaderUser(p.GetUnixUser())
	out, err = t.Run(ctx, "sshd", "-T", "-C", fmt.Sprintf("user=%s,host=trassa,addr=%s", reader, p.GetReaderAddress()))
	if err != nil {
		return fmt.Errorf("sshd -T: %v", err)
	}
	s = strings.ToLower(string(out))
	for _, want := range []string{"forcecommand " + cmd, "permittty no", "allowtcpforwarding no", "passwordauthentication no"} {
		if !strings.Contains(s, want+"\n") {
			return fmt.Errorf("sshd не применяет %q к %s", want, reader)
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
	if err := t.removeReader(ctx, u); err != nil {
		return err
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

// ensureReader — пользователь-читатель: без пароля («*»), в группе владельца репозитория, ключ с
// restrict,from=,expiry-time=, та же принудительная команда. Писать он не может правами файлов: каталоги и
// файлы репозитория принадлежат владельцу, группе — только чтение. Уже записанные файлы получают g+r(x) — обход
// по дескрипторам без ссылок.
func (t *Target) ensureReader(ctx context.Context, owner, reader string, p *agentv1.BackupTargetEnsureParams, rclone string, ownerGID int) error {
	group := strconv.Itoa(ownerGID)
	if _, err := user.Lookup(reader); err != nil {
		var unknown user.UnknownUserError
		if !errors.As(err, &unknown) {
			return err
		}
		if out, err := t.Run(ctx, "useradd", "--system", "--no-user-group", "--gid", group, "--no-create-home", "--home-dir", "/nonexistent", "--shell", targetShell, reader); err != nil {
			return fmt.Errorf("useradd: %v %s", err, firstLine(out))
		}
	}
	if out, err := t.Run(ctx, "usermod", "--shell", targetShell, "--password", "*", "--gid", group, reader); err != nil {
		return fmt.Errorf("usermod: %v %s", err, firstLine(out))
	}
	if _, _, err := lookupUser(reader); err != nil {
		return err
	}
	if err := t.groupReadable(p.GetPath()); err != nil {
		return fmt.Errorf("права репозитория для читателя: %w", err)
	}
	if err := fsutil.WriteFileAtomic(t.path(keyFile(reader)), []byte(readerKeyLine(p)), 0o644, fsutil.Keep); err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(t.path(dropIn(reader)), []byte(dropInText(reader, keyFile(reader), RcloneCommand(rclone, p.GetPath()))), 0o644, fsutil.Keep)
}

// removeReader — снять читателя цели owner (нет — не ошибка).
func (t *Target) removeReader(ctx context.Context, owner string) error {
	reader := ReaderUser(owner)
	for _, f := range []string{dropIn(reader), keyFile(reader)} {
		if err := fsutil.RemoveSync(t.path(f)); err != nil {
			return err
		}
	}
	if _, err := user.Lookup(reader); err == nil {
		// Его сеансы (rclone) завершаются вместе с пользователем.
		_, _ = t.Run(ctx, "pkill", "-KILL", "-u", reader)
		if out, err := t.Run(ctx, "userdel", reader); err != nil {
			return fmt.Errorf("userdel %s: %v %s", reader, err, firstLine(out))
		}
	}
	return nil
}

// RevokeReader — backup.target.revoke_reader: читатель снимается до срока.
func (t *Target) RevokeReader(ctx context.Context, owner string) error {
	st, err := t.loadState(owner)
	if err != nil {
		return err
	}
	if err := t.removeReader(ctx, owner); err != nil {
		return err
	}
	if err := t.reloadSSHD(ctx); err != nil {
		return err
	}
	st.Reader = ""
	raw, _ := json.Marshal(st)
	return fsutil.WriteFileAtomic(t.path(stateFile(owner)), raw, 0o600, fsutil.Keep)
}

// groupReadable — каталоги репозитория g+rx, файлы g+r; обход по дескрипторам без ссылок, ссылки и прочее не
// трогаются. Запись группе не даётся.
func (t *Target) groupReadable(p string) error {
	dp, err := fsutil.OpenDirNoFollow(t.path(filepath.Dir(p)))
	if err != nil {
		return err
	}
	defer unix.Close(dp)
	return groupReadableAt(dp, filepath.Base(p))
}

func groupReadableAt(dir int, name string) error {
	var st unix.Stat_t
	if err := unix.Fstatat(dir, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	switch uint32(st.Mode) & unix.S_IFMT {
	case unix.S_IFDIR:
		fd, err := unix.Openat(dir, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		f := os.NewFile(uintptr(fd), name)
		defer f.Close()
		if err := unix.Fchmod(fd, (uint32(st.Mode)&0o7777|0o050)&^0o022); err != nil {
			return err
		}
		names, err := f.Readdirnames(-1)
		if err != nil {
			return err
		}
		for _, n := range names {
			if err := groupReadableAt(fd, n); err != nil {
				return err
			}
		}
	case unix.S_IFREG:
		fd, err := unix.Openat(dir, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		defer unix.Close(fd)
		return unix.Fchmod(fd, (uint32(st.Mode)&0o7777|0o040)&^0o022)
	}
	return nil
}

// readerKeyLine — ключ читателя: без переадресаций и PTY, только с адреса получателя и до срока (sshd сам
// перестаёт принимать ключ после expiry-time).
func readerKeyLine(p *agentv1.BackupTargetEnsureParams) string {
	exp := time.UnixMilli(p.GetReaderExpiresAtMs()).UTC().Format("200601021504Z")
	return fmt.Sprintf("restrict,from=%q,expiry-time=%q %s\n", p.GetReaderAddress(), exp, p.GetReaderPublicKey())
}
