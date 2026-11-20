// SPDX-License-Identifier: AGPL-3.0-only

package backup

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/fsutil"
)

// Файлы цели SERVER (decisions E13 п. 14).
const (
	SSHDropInDir = "/etc/ssh/sshd_config.d"
	TargetKeyDir = "/etc/ssh/trassa-bk"
	sshdMain     = "/etc/ssh/sshd_config"
	// RepoSubdir — каталог репозитория внутри chroot: chroot принадлежит root, репозиторий — пользователю.
	RepoSubdir = "repo"
)

// ErrTargetPrecondition — сервер-цель не готов (BACKUP_TARGET_PRECONDITION).
var ErrTargetPrecondition = errors.New("BACKUP_TARGET_PRECONDITION")

var includeRe = regexp.MustCompile(`(?mi)^\s*Include\s+/etc/ssh/sshd_config\.d/\*\.conf\s*$`)

// Target — файлы и команды цели под корнем Root ("/" на сервере).
type Target struct {
	Root string
	Run  func(ctx context.Context, name string, args ...string) ([]byte, error)
}

func (t *Target) path(p string) string { return filepath.Join(t.Root, p) }

func dropIn(u string) string  { return filepath.Join(SSHDropInDir, u+".conf") }
func keyFile(u string) string { return filepath.Join(TargetKeyDir, u+".keys") }

// Paths — файлы, которые меняет цель: настройки sshd, ключ, учётные записи (точка отката CONFIG).
func (t *Target) Paths(u string) []string {
	out := []string{t.path(dropIn(u)), t.path(keyFile(u))}
	for _, f := range []string{"/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow"} {
		if _, err := os.Stat(t.path(f)); err == nil {
			out = append(out, t.path(f))
		}
	}
	return out
}

func dropInText(p *agentv1.BackupTargetEnsureParams) string {
	return fmt.Sprintf(`# Trassa: цель бэкапов %[1]s — только SFTP в своём каталоге. Файл пишет Trassa.
Match User %[1]s
	ChrootDirectory %[2]s
	ForceCommand internal-sftp -d /%[3]s
	AuthorizedKeysFile %[4]s
	PasswordAuthentication no
	KbdInteractiveAuthentication no
	AllowTcpForwarding no
	AllowStreamLocalForwarding no
	X11Forwarding no
	AllowAgentForwarding no
	PermitTTY no
	PermitTunnel no
`, p.GetUnixUser(), p.GetPath(), RepoSubdir, keyFile(p.GetUnixUser()))
}

// chrootReady — каждый компонент пути принадлежит root и не доступен на запись группе и прочим, ссылок нет
// (требование ChrootDirectory sshd).
func (t *Target) chrootReady(p string) error {
	cur := t.Root
	for _, c := range strings.Split(strings.TrimPrefix(p, "/"), "/") {
		cur = filepath.Join(cur, c)
		st, err := os.Lstat(cur)
		if errors.Is(err, os.ErrNotExist) {
			return nil // дальше создаст Ensure
		}
		if err != nil {
			return err
		}
		if !st.IsDir() {
			return fmt.Errorf("%w: %s не каталог", ErrTargetPrecondition, cur)
		}
		sys, ok := st.Sys().(*syscall.Stat_t)
		if (t.Root == "/" && ok && sys.Uid != 0) || st.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("%w: %s должен принадлежать root без записи для группы и прочих", ErrTargetPrecondition, cur)
		}
	}
	return nil
}

// Ensure — пользователь без оболочки, chroot root, репозиторий пользователя 0700, ключ источника с
// restrict,from=, блок Match в sshd_config.d; sshd -t и перечитывание настроек.
func (t *Target) Ensure(ctx context.Context, p *agentv1.BackupTargetEnsureParams) error {
	main, err := os.ReadFile(t.path(sshdMain))
	if err != nil {
		return fmt.Errorf("%w: %s: %v", ErrTargetPrecondition, sshdMain, err)
	}
	if !includeRe.Match(main) {
		return fmt.Errorf("%w: в %s нет Include %s/*.conf", ErrTargetPrecondition, sshdMain, SSHDropInDir)
	}
	if err := t.chrootReady(p.GetPath()); err != nil {
		return err
	}
	u := p.GetUnixUser()
	if _, err := user.Lookup(u); err != nil {
		var unknown user.UnknownUserError
		if !errors.As(err, &unknown) {
			return err
		}
		if out, err := t.Run(ctx, "useradd", "--system", "--user-group", "--no-create-home", "--home-dir", "/", "--shell", "/usr/sbin/nologin", u); err != nil {
			return fmt.Errorf("useradd: %v %s", err, firstLine(out))
		}
	}
	acc, err := user.Lookup(u)
	if err != nil {
		return err
	}
	uid, _ := strconv.Atoi(acc.Uid)
	gid, _ := strconv.Atoi(acc.Gid)
	chroot := t.path(p.GetPath())
	if err := os.MkdirAll(chroot, 0o755); err != nil {
		return err
	}
	// UMask помощника 0077: каталог создан 0700, а пользователю после chroot нужен проход в repo.
	if err := fsutil.ChmodChownNoFollow(chroot, fsutil.FileID{}, 0o755, -1, -1); err != nil {
		return err
	}
	if err := t.chrootReady(p.GetPath()); err != nil {
		return err
	}
	repo := filepath.Join(chroot, RepoSubdir)
	if err := os.Mkdir(repo, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	if err := fsutil.ChmodChownNoFollow(repo, fsutil.FileID{}, 0o700, uid, gid); err != nil {
		return err
	}
	if err := os.MkdirAll(t.path(TargetKeyDir), 0o755); err != nil {
		return err
	}
	keyLine := fmt.Sprintf("restrict,from=%q %s\n", p.GetSourceAddress(), p.GetSourcePublicKey())
	if err := fsutil.WriteFileAtomic(t.path(keyFile(u)), []byte(keyLine), 0o644, fsutil.Keep); err != nil {
		return err
	}
	if err := fsutil.WriteFileAtomic(t.path(dropIn(u)), []byte(dropInText(p)), 0o644, fsutil.Keep); err != nil {
		return err
	}
	return t.reloadSSHD(ctx)
}

// Check — sshd применяет к пользователю chroot и только SFTP.
func (t *Target) Check(ctx context.Context, p *agentv1.BackupTargetEnsureParams) error {
	out, err := t.Run(ctx, "sshd", "-T", "-C", fmt.Sprintf("user=%s,host=trassa,addr=%s", p.GetUnixUser(), p.GetSourceAddress()))
	if err != nil {
		return fmt.Errorf("sshd -T: %v", err)
	}
	s := strings.ToLower(string(out))
	for _, want := range []string{
		"chrootdirectory " + strings.ToLower(p.GetPath()), "forcecommand internal-sftp -d /" + RepoSubdir,
		"permittty no", "allowtcpforwarding no",
	} {
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

var chrootLine = regexp.MustCompile(`(?m)^\s*ChrootDirectory\s+(\S+)\s*$`)

// Remove — снять цель: путь обязан совпадать с chroot из файла Trassa (иначе это не наша цель и данные не
// удаляются); ключ, блок sshd и пользователь удаляются, данные — только при deleteData.
func (t *Target) Remove(ctx context.Context, p *agentv1.BackupTargetRemoveParams) error {
	u := p.GetUnixUser()
	raw, err := os.ReadFile(t.path(dropIn(u)))
	if err != nil {
		return fmt.Errorf("%w: цели %s нет: %v", ErrTargetPrecondition, u, err)
	}
	m := chrootLine.FindSubmatch(raw)
	if m == nil || string(m[1]) != p.GetPath() {
		return fmt.Errorf("%w: путь %s не совпадает с каталогом цели %s", ErrTargetPrecondition, p.GetPath(), u)
	}
	for _, f := range []string{dropIn(u), keyFile(u)} {
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
