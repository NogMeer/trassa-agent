// SPDX-License-Identifier: AGPL-3.0-only

package backup

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/backupstatus"
	"github.com/NogMeer/trassa-agent/internal/dockerapi"
	"github.com/NogMeer/trassa-agent/internal/fsutil"
)

// MaxWindow — предел окна бэкапа без deadline_ms (windowMinutes панели — до 720).
const MaxWindow = 12 * time.Hour

// Env — зависимости бэкапов в помощнике.
type Env struct {
	Store    Store
	BinDir   string // /var/lib/trassa/helper/bin: restic-<версия>
	CacheDir string // /var/cache/trassa/restic/<plan_id>
	WorkDir  string // /var/lib/trassa/backup: restore-test/<op>, restore/<op>, localcopy/<op>
	// StatusPath — время успешных бэкапов для метрики агента (backupstatus); "" — не вести.
	StatusPath string
	Docker     *dockerapi.Client
	// Run — команда хоста без оболочки (psql, useradd, sshd); Exec — для дампов в потоке: путь программы.
	Run  func(ctx context.Context, name string, args ...string) ([]byte, error)
	Look func(name string) (string, error)
	Now  func() time.Time
}

func (e *Env) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

// Restic — запуск restic для сохранённого плана.
func (e *Env) Restic(planID string) (*Restic, error) {
	repo, err := e.Store.Load(planID)
	if err != nil {
		return nil, err
	}
	return e.resticFor(planID, repo, "")
}

func (e *Env) resticFor(planID string, repo *Repo, passwordFile string) (*Restic, error) {
	d, err := e.Store.PlanDir(planID)
	if err != nil {
		return nil, err
	}
	bin := ResticPath(e.BinDir, repo.ResticVersion)
	if st, err := os.Stat(bin); err != nil || !st.Mode().IsRegular() {
		return nil, fmt.Errorf("restic %s не установлен (нужен backup.init)", repo.ResticVersion)
	}
	if passwordFile == "" {
		passwordFile = filepath.Join(d, passwordFile0)
	}
	cache := filepath.Join(e.CacheDir, strings.ToLower(planID))
	if err := os.MkdirAll(cache, 0o700); err != nil {
		return nil, err
	}
	return &Restic{
		Bin: bin, CacheDir: cache, TmpDir: os.TempDir(), Repo: repo, PasswordFile: passwordFile,
		SSHKey: filepath.Join(d, SSHKeyFile), KnownHosts: filepath.Join(d, knownHostsFile), Nice: 10,
	}, nil
}

const passwordFile0 = passwordFile

// Deadline — конец окна из параметров: 0 — MaxWindow от начала; дальше MaxWindow — обрезается.
func (e *Env) Deadline(ms int64) time.Time {
	limit := e.now().Add(MaxWindow)
	if ms <= 0 {
		return limit
	}
	d := time.UnixMilli(ms)
	if d.After(limit) {
		return limit
	}
	return d
}

// EnsureSSHKey — пара ed25519 плана для цели SERVER: закрытый ключ (0600) не покидает сервер, открытый — в
// панель. Есть пара — возвращается открытый ключ без изменений.
func (e *Env) EnsureSSHKey(planID string) (string, error) {
	d, err := e.Store.PlanDir(planID)
	if err != nil {
		return "", err
	}
	return ensureKeyPair(d)
}

// ensureKeyPair — пара ed25519 в каталоге d (0700): есть — открытый ключ без изменений.
func ensureKeyPair(d string) (string, error) {
	priv, pub := filepath.Join(d, SSHKeyFile), filepath.Join(d, SSHKeyFile+".pub")
	if raw, err := fsutil.ReadLimited(pub, 4096); err == nil {
		if _, err := os.Stat(priv); err == nil {
			return strings.TrimSpace(string(raw)), nil
		}
	}
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	block, err := ssh.MarshalPrivateKey(sk, "trassa-backup")
	if err != nil {
		return "", err
	}
	spk, err := ssh.NewPublicKey(pk)
	if err != nil {
		return "", err
	}
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(spk))) + " trassa-backup"
	if err := os.MkdirAll(d, 0o700); err != nil {
		return "", err
	}
	if err := fsutil.WriteFileAtomic(priv, pem.EncodeToMemory(block), 0o600, fsutil.Keep); err != nil {
		return "", err
	}
	if err := fsutil.WriteFileAtomic(pub, []byte(line+"\n"), 0o600, fsutil.Keep); err != nil {
		return "", err
	}
	return line, nil
}

// SSHKeyPaths — файлы пары и known_hosts плана (для точки отката backup.init).
func (e *Env) SSHKeyPaths(planID string) ([]string, error) {
	d, err := e.Store.PlanDir(planID)
	if err != nil {
		return nil, err
	}
	return []string{filepath.Join(d, SSHKeyFile), filepath.Join(d, SSHKeyFile+".pub"), filepath.Join(d, knownHostsFile)}, nil
}

// FreeBytes — свободное место под path (для root).
func FreeBytes(path string) (uint64, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return 0, err
	}
	return uint64(st.Bavail) * uint64(st.Bsize), nil
}

// VolumeMountpoint — каталог данных тома Docker (Mountpoint из /volumes/<имя>).
func (e *Env) VolumeMountpoint(ctx context.Context, name string) (string, error) {
	if e.Docker == nil {
		return "", dockerapi.ErrNoDocker
	}
	var v struct {
		Name       string `json:"Name"`
		Mountpoint string `json:"Mountpoint"`
		Driver     string `json:"Driver"`
	}
	if err := e.dockerJSON(ctx, "/volumes/"+url.PathEscape(name), &v); err != nil {
		return "", err
	}
	if v.Name != name || v.Driver != "local" || !filepath.IsAbs(v.Mountpoint) || filepath.Clean(v.Mountpoint) != v.Mountpoint {
		return "", fmt.Errorf("том %s: драйвер %q или каталог %q не поддерживается", name, v.Driver, v.Mountpoint)
	}
	return v.Mountpoint, nil
}

// dockerJSON — GET Docker API с разбором ответа не больше 8 МиБ.
func (e *Env) dockerJSON(ctx context.Context, path string, v any) error {
	if e.Docker == nil {
		return dockerapi.ErrNoDocker
	}
	resp, err := e.Docker.Get(ctx, path)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("api docker %s: HTTP %d", path, resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(v)
}

// DumpCommand — команда логического дампа базы потоком в restic (decisions E13 п. 12–13): PostgreSQL —
// pg_dump -Fc от postgres (в контейнере — локальный trust, на хосте — peer); MySQL/MariaDB — с транзакцией,
// процедурами, событиями и триггерами; пароль root в контейнере — из его окружения, через MYSQL_PWD, а не в
// аргументах. Имя базы — позиционным аргументом, не частью скрипта.
func (e *Env) DumpCommand(engine string, d *agentv1.DatabaseSource) ([]string, string, error) {
	look := e.Look
	if look == nil {
		look = func(string) (string, error) { return "", errors.New("нет поиска программ") }
	}
	if strings.HasPrefix(d.GetDatabase(), "-") {
		return nil, "", fmt.Errorf("имя базы %q", d.GetDatabase())
	}
	name := engine + "-" + d.GetDatabase()
	switch {
	case engine == "postgres" && d.GetContainer() != "":
		docker, err := look("docker")
		if err != nil {
			return nil, "", fmt.Errorf("docker: %w", err)
		}
		return []string{docker, "exec", "-u", "postgres", d.GetContainer(), "pg_dump", "-Fc", "--", d.GetDatabase()}, name + ".pgdump", nil
	case engine == "postgres":
		runuser, err := look("runuser")
		if err != nil {
			return nil, "", err
		}
		pgdump, err := look("pg_dump")
		if err != nil {
			return nil, "", fmt.Errorf("pg_dump: %w", err)
		}
		return []string{runuser, "-u", "postgres", "--", pgdump, "-Fc", "--", d.GetDatabase()}, name + ".pgdump", nil
	case engine == "mysql" && d.GetContainer() != "":
		docker, err := look("docker")
		if err != nil {
			return nil, "", fmt.Errorf("docker: %w", err)
		}
		return []string{docker, "exec", d.GetContainer(), "sh", "-c", mysqlContainerScript, "sh", d.GetDatabase()}, name + ".sql", nil
	case engine == "mysql":
		dump, err := look("mariadb-dump")
		if err != nil {
			if dump, err = look("mysqldump"); err != nil {
				return nil, "", fmt.Errorf("mysqldump: %w", err)
			}
		}
		return []string{dump, "--single-transaction", "--routines", "--events", "--triggers", "--databases", d.GetDatabase()}, name + ".sql", nil
	}
	return nil, "", fmt.Errorf("движок %q", engine)
}

// mysqlContainerScript — постоянный текст: имя базы приходит в $1, пароль — из окружения контейнера.
const mysqlContainerScript = `p="${MYSQL_ROOT_PASSWORD:-${MARIADB_ROOT_PASSWORD:-}}"; ` +
	`f="${MYSQL_ROOT_PASSWORD_FILE:-${MARIADB_ROOT_PASSWORD_FILE:-}}"; ` +
	`if [ -n "$f" ]; then p="$(cat "$f")"; fi; ` +
	`d=mysqldump; if command -v mariadb-dump >/dev/null 2>&1; then d=mariadb-dump; fi; ` +
	`MYSQL_PWD="$p" exec "$d" -uroot --single-transaction --routines --events --triggers --databases "$1"`

// Prune — backup.prune ключами обслуживания: пароль — во временном файле на время операции, после — удаляется;
// освобождённое место — разница объёма до и после (если restic его сообщил).
func (e *Env) Prune(ctx context.Context, planID string, maint *Repo, ret *agentv1.Retention, deadline time.Time) (*agentv1.BackupPruneResult, error) {
	d, err := e.Store.PlanDir(planID)
	if err != nil {
		return nil, err
	}
	pw, cleanup, err := TempPasswordFile(d, maint.Password)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	r, err := e.resticFor(planID, maint, pw)
	if err != nil {
		return nil, err
	}
	before, berr := Stats(ctx, r)
	removed, err := Forget(ctx, r, ret, deadline)
	if err != nil {
		return nil, err
	}
	out := &agentv1.BackupPruneResult{RemovedSnapshots: removed}
	if after, aerr := Stats(ctx, r); berr == nil && aerr == nil && before > after {
		out.FreedBytes = before - after
	}
	return out, nil
}

// systemPath — каталоги программ: помощник не берёт PATH из окружения.
var systemPath = []string{"/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"}

// LookPath — программа в системных каталогах (обычный исполняемый файл).
func LookPath(name string) (string, error) {
	if strings.ContainsRune(name, '/') {
		return "", fmt.Errorf("имя программы %q", name)
	}
	for _, d := range systemPath {
		p := filepath.Join(d, name)
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() && st.Mode().Perm()&0o111 != 0 {
			return p, nil
		}
	}
	return "", fmt.Errorf("%s: не найден", name)
}

// RunCommand — команда без оболочки, с чистым окружением; вывод stdout до 4 МиБ, ошибка — с началом stderr.
func RunCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	bin := name
	if !filepath.IsAbs(name) {
		p, err := LookPath(name)
		if err != nil {
			return nil, err
		}
		bin = p
	}
	c := exec.CommandContext(ctx, bin, args...)
	c.Env = cleanEnv()
	var out, stderr tail
	c.Stdout, c.Stderr = &limitWriter{w: &out, n: 4 << 20}, &stderr
	if err := c.Run(); err != nil {
		return out.Bytes(), fmt.Errorf("%s: %v: %s", name, err, firstLine(stderr.Bytes()))
	}
	return out.Bytes(), nil
}

// limitWriter — пишет не больше n байт, остальное отбрасывает.
type limitWriter struct {
	w io.Writer
	n int
}

func (l *limitWriter) Write(p []byte) (int, error) {
	if l.n > 0 {
		k := min(len(p), l.n)
		l.n -= k
		if _, err := l.w.Write(p[:k]); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

// PinHostKey — known_hosts плана: ключ хоста цели из подписанной операции закрепляется за хостом из адреса
// репозитория; restic ходит к цели только с ним (StrictHostKeyChecking=yes).
func (e *Env) PinHostKey(planID, repoURL, key string) error {
	d, err := e.Store.PlanDir(planID)
	if err != nil {
		return err
	}
	return pinHostKey(d, repoURL, key)
}

func pinHostKey(d, repoURL, key string) error {
	rest := strings.TrimPrefix(strings.TrimPrefix(repoURL, "sftp:"), "rclone:")
	at, colon := strings.IndexByte(rest, '@'), strings.IndexByte(rest, ':')
	if rest == repoURL || at < 0 || colon < at {
		return errors.New("ключ хоста — только для адресов sftp и rclone")
	}
	host := rest[at+1 : colon]
	return fsutil.WriteFileAtomic(filepath.Join(d, knownHostsFile), []byte(host+" "+key+"\n"), 0o600, fsutil.Keep)
}

// RestoreKeyDir — ключи получателя для восстановления на другой сервер: <Store.Dir>/../backup-restore/<plan>
// (root, 0700). Пара живёт от backup.restore с ssh_keypair до успешного восстановления.
func (e *Env) RestoreKeyDir(planID string) (string, error) {
	d, err := e.Store.PlanDir(planID)
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(e.Store.Dir), "backup-restore", filepath.Base(d)), nil
}

// EnsureRestoreKey — пара ключей получателя (backup.restore с ssh_keypair): открытый ключ — читателю цели
// SERVER или клиенту для своего SFTP.
func (e *Env) EnsureRestoreKey(planID string) (string, error) {
	d, err := e.RestoreKeyDir(planID)
	if err != nil {
		return "", err
	}
	return ensureKeyPair(d)
}

// RemoteRestic — restic получателя для репозитория из операции: пароль — во временном файле каталога ключей
// (удаляется cleanup), ключ хоста цели закреплён там же; только чтение (--no-lock). cleanup(true) удаляет и
// пару ключей (после успешного восстановления).
func (e *Env) RemoteRestic(planID string, repo *Repo, hostKey string) (*Restic, func(dropKeys bool), error) {
	d, err := e.RestoreKeyDir(planID)
	if err != nil {
		return nil, nil, err
	}
	if err := os.MkdirAll(d, 0o700); err != nil {
		return nil, nil, err
	}
	pw, rmPw, err := TempPasswordFile(d, repo.Password)
	if err != nil {
		return nil, nil, err
	}
	known := filepath.Join(d, knownHostsFile)
	cleanup := func(dropKeys bool) {
		rmPw()
		_ = os.Remove(known)
		_ = os.RemoveAll(filepath.Join(e.CacheDir, "restore-"+filepath.Base(d)))
		if dropKeys {
			_ = os.RemoveAll(d)
		}
	}
	if hostKey != "" {
		if err := pinHostKey(d, repo.URL, hostKey); err != nil {
			cleanup(false)
			return nil, nil, err
		}
	} else {
		_ = os.Remove(known)
	}
	bin := ResticPath(e.BinDir, repo.ResticVersion)
	if st, err := os.Stat(bin); err != nil || !st.Mode().IsRegular() {
		cleanup(false)
		return nil, nil, fmt.Errorf("restic %s не установлен", repo.ResticVersion)
	}
	cache := filepath.Join(e.CacheDir, "restore-"+filepath.Base(d))
	if err := os.MkdirAll(cache, 0o700); err != nil {
		cleanup(false)
		return nil, nil, err
	}
	r := &Restic{Bin: bin, CacheDir: cache, TmpDir: os.TempDir(), Repo: repo, PasswordFile: pw,
		SSHKey: filepath.Join(d, SSHKeyFile), KnownHosts: known, Nice: 10, NoLock: true}
	return r, cleanup, nil
}

// PruneTarget — backup.prune на сервере-цели: полный доступ к репозиторию — только здесь, у root цели
// (ключ источника — «только добавление»).
func (e *Env) PruneTarget(ctx context.Context, t *Target, unixUser string, password []byte, ret *agentv1.Retention, deadline time.Time) (*agentv1.BackupPruneResult, error) {
	r, cleanup, err := t.PruneRestic(unixUser, password)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	before, berr := Stats(ctx, r)
	removed, err := Forget(ctx, r, ret, deadline)
	if err != nil {
		return nil, err
	}
	out := &agentv1.BackupPruneResult{RemovedSnapshots: removed}
	if after, aerr := Stats(ctx, r); berr == nil && aerr == nil && before > after {
		out.FreedBytes = before - after
	}
	return out, nil
}

// MarkStatus — учёт времени бэкапов плана: настроен (init), успешный запуск (run), удалён (unconfigure).
func (e *Env) MarkStatus(planID string, fn func(p *backupstatus.Plan) bool) error {
	if e.StatusPath == "" {
		return nil
	}
	id := strings.ToLower(planID)
	return backupstatus.Update(e.StatusPath, func(f *backupstatus.File) {
		p := f.Plans[id]
		if fn(&p) {
			f.Plans[id] = p
		} else {
			delete(f.Plans, id)
		}
	})
}
