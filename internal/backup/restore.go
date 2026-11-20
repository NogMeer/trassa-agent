// SPDX-License-Identifier: AGPL-3.0-only

package backup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/fsutil"
)

// Ошибки восстановления.
var (
	ErrRollbackUnavailable = errors.New("BACKUP_ROLLBACK_UNAVAILABLE")
	ErrRestoreVerify       = errors.New("BACKUP_RESTORE_VERIFY_FAILED")
)

// LocalCopyTTL — сколько хранится локальная копия заменённых путей и базы (E13 раздел 6).
const LocalCopyTTL = 72 * time.Hour

// RestoreJob — параметры восстановления.
type RestoreJob struct {
	OpID     string
	Params   *agentv1.BackupRestoreParams
	Rollback agentv1.RollbackKind
	Deadline time.Time
	Progress func(Status)
	Log      func(string)
}

// RestoreOutcome — итог: результат, и был ли выполнен самостоятельный откат.
type RestoreOutcome struct {
	Result     *agentv1.BackupRestoreResult
	RolledBack bool
}

// localCopy — что сохранено до восстановления на место.
type localCopy struct {
	Paths     []copiedPath `json:"paths"`
	Database  string       `json:"database,omitempty"`
	Engine    string       `json:"engine,omitempty"`
	Container string       `json:"container,omitempty"`
}

type copiedPath struct {
	Path    string `json:"path"`
	Existed bool   `json:"existed"`
}

// LocalCopyDir — каталог локальной копии операции.
func (e *Env) LocalCopyDir(op string) string {
	return filepath.Join(e.WorkDir, "localcopy", strings.ToLower(op))
}

// findSnapshot — снимок Trassa по полному id или префиксу.
func findSnapshot(snaps []Snapshot, id string) (*Snapshot, error) {
	for i := range snaps {
		if strings.HasPrefix(snaps[i].ID, id) {
			return &snaps[i], nil
		}
	}
	return nil, fmt.Errorf("%w: снимок %s", ErrSnapshotMissing, id)
}

// under — p равен base или лежит под ним.
func under(p, base string) bool {
	return p == base || strings.HasPrefix(p, strings.TrimSuffix(base, "/")+"/")
}

// Restore — backup.restore: файлы во временный каталог, на место или в каталог на этом сервере; дамп базы — во
// временный каталог файлом или на место загрузкой в базу. Перед заменой на место — локальная копия (LOCAL_COPY);
// провал проверки после замены возвращает её сам (ROLLED_BACK). При SNAPSHOT откат — снапшотом хостера (панель).
func (e *Env) Restore(ctx context.Context, r *Restic, j RestoreJob) (*RestoreOutcome, error) {
	p := j.Params
	snaps, err := Snapshots(ctx, r)
	if err != nil {
		return nil, err
	}
	snap, err := findSnapshot(snaps, p.GetSnapshotId())
	if err != nil {
		return nil, err
	}
	if snap.IsDump() && p.GetMode() == agentv1.RestoreMode_RESTORE_MODE_IN_PLACE {
		return e.restoreDatabase(ctx, r, snap, j)
	}
	return e.restoreFiles(ctx, r, snap, j)
}

func (e *Env) restoreFiles(ctx context.Context, r *Restic, snap *Snapshot, j RestoreJob) (*RestoreOutcome, error) {
	p := j.Params
	sel := p.GetSelection()
	paths := sel.GetPaths()
	if sel.GetAll() {
		paths = snap.Paths
	}
	if len(sel.GetDatabases()) > 0 && !snap.IsDump() {
		return nil, errors.New("selection.databases: снимок не дамп базы")
	}
	if snap.IsDump() {
		paths = snap.Paths
	}
	for _, x := range paths {
		ok := false
		for _, sp := range snap.Paths {
			ok = ok || under(x, sp)
		}
		if !ok {
			return nil, fmt.Errorf("%s: нет в снимке", x)
		}
		// Путь из снимка: в чужом репозитории мог оказаться любой — восстановление не пишет в каталоги Trassa.
		if !AllowedPath(x) && !snap.IsDump() {
			return nil, fmt.Errorf("%w: %s", ErrPathForbidden, x)
		}
	}
	var target string
	switch p.GetMode() {
	case agentv1.RestoreMode_RESTORE_MODE_TEMP_DIR:
		target = filepath.Join(e.WorkDir, "restore", strings.ToLower(j.OpID))
	case agentv1.RestoreMode_RESTORE_MODE_IN_PLACE:
		target = "/"
	case agentv1.RestoreMode_RESTORE_MODE_OTHER_SERVER:
		target = p.GetDestPath()
	}
	dest := func(x string) string { return filepath.Join(target, x) }
	nodes, truncated, err := List(ctx, r, snap.ID, maxListNodes)
	if err != nil {
		return nil, err
	}
	if truncated {
		return nil, fmt.Errorf("в снимке больше %d записей: восстановление по частям", maxListNodes)
	}
	var want []Node
	var need uint64
	for _, n := range nodes {
		for _, x := range paths {
			if under(n.Path, x) {
				want = append(want, n)
				if n.Type == "file" {
					need += n.Size
				}
				break
			}
		}
	}
	if err := os.MkdirAll(target, 0o700); err != nil {
		return nil, err
	}
	if free, err := FreeBytes(target); err == nil && free < need+need/20+(64<<20) {
		return nil, fmt.Errorf("%w: нужно %d байт, свободно %d", ErrNoSpace, need, free)
	}
	var lc *localCopy
	if p.GetMode() != agentv1.RestoreMode_RESTORE_MODE_TEMP_DIR && j.Rollback == agentv1.RollbackKind_ROLLBACK_KIND_LOCAL_COPY {
		dsts := make([]string, 0, len(paths))
		for _, x := range paths {
			dsts = append(dsts, dest(x))
		}
		if lc, err = e.saveLocalCopy(j.OpID, dsts); err != nil {
			return nil, err
		}
		j.log("Сохранена локальная копия заменяемых путей: %d", len(lc.Paths))
	}
	var includes []string
	if !sel.GetAll() {
		includes = paths
	}
	sum, err := Restore(ctx, r, RestoreSpec{Snapshot: snap.ID, Target: target, Includes: includes, Deadline: j.Deadline, Progress: j.Progress})
	verr := err
	if verr == nil {
		verr = checkRestored(want, dest)
	}
	if verr != nil {
		if p.GetMode() == agentv1.RestoreMode_RESTORE_MODE_TEMP_DIR {
			_ = os.RemoveAll(target)
			return nil, verr
		}
		if lc != nil {
			if rerr := e.restoreLocalCopy(j.OpID, lc); rerr != nil {
				return nil, fmt.Errorf("%w: %v; возврат локальной копии не удался: %v", ErrRestoreVerify, verr, rerr)
			}
			return &RestoreOutcome{RolledBack: true}, fmt.Errorf("%w: %v", ErrRestoreVerify, verr)
		}
		return nil, fmt.Errorf("%w: %v", ErrRestoreVerify, verr)
	}
	out := &agentv1.BackupRestoreResult{RestoredFiles: sum.FilesRestored, RestoredBytes: sum.BytesRestored, Path: target}
	return &RestoreOutcome{Result: out}, nil
}

// checkRestored — каждый файл и каталог списка снимка на месте, размер файлов совпал.
func checkRestored(want []Node, dest func(string) string) error {
	for _, n := range want {
		st, err := os.Lstat(dest(n.Path))
		if err != nil {
			return fmt.Errorf("%s: %v", n.Path, err)
		}
		switch n.Type {
		case "file":
			if !st.Mode().IsRegular() || uint64(st.Size()) != n.Size {
				return fmt.Errorf("%s: размер %d, в снимке %d", n.Path, st.Size(), n.Size)
			}
		case "dir":
			if !st.IsDir() {
				return fmt.Errorf("%s: не каталог", n.Path)
			}
		}
	}
	return nil
}

func (j *RestoreJob) log(format string, a ...any) {
	if j.Log != nil {
		j.Log(fmt.Sprintf(format, a...))
	}
}

// saveLocalCopy — копия путей, которые заменит восстановление, в localcopy/<op>/data. Места нет — отказ до
// замены (R13: без точки отката на место не восстанавливаем).
func (e *Env) saveLocalCopy(op string, dsts []string) (*localCopy, error) {
	dir := e.LocalCopyDir(op)
	var need uint64
	for _, d := range dsts {
		n, err := treeSize(d)
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %v", ErrRollbackUnavailable, d, err)
		}
		need += n
	}
	if err := os.MkdirAll(filepath.Join(dir, "data"), 0o700); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRollbackUnavailable, err)
	}
	if free, err := FreeBytes(dir); err != nil || free < need+need/20+(64<<20) {
		_ = os.RemoveAll(dir)
		return nil, fmt.Errorf("%w: для локальной копии нужно %d байт, свободно %d", ErrRollbackUnavailable, need, free)
	}
	lc := &localCopy{}
	for _, d := range dsts {
		_, err := os.Lstat(d)
		existed := err == nil
		if existed {
			to := filepath.Join(dir, "data", d)
			if err := os.MkdirAll(filepath.Dir(to), 0o700); err != nil {
				return nil, fmt.Errorf("%w: %v", ErrRollbackUnavailable, err)
			}
			if err := copyTree(d, to); err != nil {
				_ = os.RemoveAll(dir)
				return nil, fmt.Errorf("%w: копия %s: %v", ErrRollbackUnavailable, d, err)
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: %v", ErrRollbackUnavailable, err)
		}
		lc.Paths = append(lc.Paths, copiedPath{Path: d, Existed: existed})
	}
	raw, _ := json.Marshal(lc)
	if err := fsutil.WriteFileAtomic(filepath.Join(dir, "manifest.json"), raw, 0o600, fsutil.Keep); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRollbackUnavailable, err)
	}
	return lc, nil
}

// restoreLocalCopy — пути как до восстановления: созданные им удаляются, заменённые возвращаются из копии.
func (e *Env) restoreLocalCopy(op string, lc *localCopy) error {
	var errs []error
	for _, c := range lc.Paths {
		if !c.Existed {
			if err := os.RemoveAll(c.Path); err != nil {
				errs = append(errs, err)
			}
			continue
		}
		if err := copyBack(filepath.Join(e.LocalCopyDir(op), "data", c.Path), c.Path); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// PruneLocalCopies — удалить локальные копии старше LocalCopyTTL (задача помощника, E13 раздел 6).
func (e *Env) PruneLocalCopies() error {
	root := filepath.Join(e.WorkDir, "localcopy")
	ents, err := os.ReadDir(root)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var errs []error
	for _, d := range ents {
		info, err := d.Info()
		if err != nil {
			continue
		}
		if e.now().Sub(info.ModTime()) > LocalCopyTTL {
			if err := os.RemoveAll(filepath.Join(root, d.Name())); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

// restoreDatabase — дамп из снимка загружается в базу источника. До этого (LOCAL_COPY) свежий дамп текущей базы
// сохраняется в локальную копию; база не отвечает после загрузки — загружается копия.
func (e *Env) restoreDatabase(ctx context.Context, r *Restic, snap *Snapshot, j RestoreJob) (*RestoreOutcome, error) {
	engine, container, db := snap.Tag(TagKindPrefix), snap.Tag(TagContainerPrefix), snap.Tag(TagDatabasePrefix)
	sel := j.Params.GetSelection()
	if !dbNameRe.MatchString(db) || (container != "" && !containerRe.MatchString(container)) {
		return nil, errors.New("метки снимка базы повреждены")
	}
	if !sel.GetAll() && !contains(sel.GetDatabases(), db) {
		return nil, fmt.Errorf("в снимке база %s, а выбраны %v", db, sel.GetDatabases())
	}
	if len(snap.Paths) != 1 {
		return nil, errors.New("в снимке дампа не один файл")
	}
	src := &agentv1.DatabaseSource{Container: container, Database: db}
	var copyFile string
	if j.Rollback == agentv1.RollbackKind_ROLLBACK_KIND_LOCAL_COPY {
		dir := e.LocalCopyDir(j.OpID)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrRollbackUnavailable, err)
		}
		cmd, _, err := e.DumpCommand(engine, src)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrRollbackUnavailable, err)
		}
		copyFile = filepath.Join(dir, "database.dump")
		if err := runToFile(ctx, cmd, copyFile); err != nil {
			_ = os.RemoveAll(dir)
			return nil, fmt.Errorf("%w: дамп текущей базы: %v", ErrRollbackUnavailable, Clean(err.Error(), r.Repo.Secrets()))
		}
		raw, _ := json.Marshal(localCopy{Database: db, Engine: engine, Container: container})
		_ = fsutil.WriteFileAtomic(filepath.Join(dir, "manifest.json"), raw, 0o600, fsutil.Keep)
		j.log("Сохранён дамп текущей базы %s", db)
	}
	load, err := e.loadCommand(engine, src)
	if err != nil {
		return nil, err
	}
	pr, pw := io.Pipe()
	var lerr error
	done := make(chan struct{})
	go func() {
		lerr = runFromReader(ctx, load, pr)
		pr.CloseWithError(lerr)
		close(done)
	}()
	derr := Dump(ctx, r, snap.ID, snap.Paths[0], pw)
	pw.CloseWithError(derr)
	<-done
	verr := errors.Join(derr, lerr)
	if verr == nil {
		verr = e.pingDatabase(ctx, engine, src)
	}
	if verr == nil {
		return &RestoreOutcome{Result: &agentv1.BackupRestoreResult{RestoredFiles: 1, Path: "db:" + db}}, nil
	}
	msg := Clean(verr.Error(), r.Repo.Secrets())
	if copyFile == "" {
		return nil, fmt.Errorf("%w: %s", ErrRestoreVerify, msg)
	}
	f, err := os.Open(copyFile)
	if err != nil {
		return nil, fmt.Errorf("%w: %s; копия базы не открылась: %v", ErrRestoreVerify, msg, err)
	}
	defer f.Close()
	if rerr := runFromReader(ctx, load, f); rerr != nil {
		return nil, fmt.Errorf("%w: %s; возврат копии базы не удался: %v", ErrRestoreVerify, msg, rerr)
	}
	return &RestoreOutcome{RolledBack: true}, fmt.Errorf("%w: %s", ErrRestoreVerify, msg)
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// loadCommand — загрузка дампа из stdin в базу: PostgreSQL — pg_restore --clean --if-exists (формат -Fc),
// MySQL — клиент mysql (дамп с --databases сам выбирает базу).
func (e *Env) loadCommand(engine string, d *agentv1.DatabaseSource) ([]string, error) {
	look := e.Look
	if look == nil {
		return nil, errors.New("нет поиска программ")
	}
	pgArgs := []string{"pg_restore", "--clean", "--if-exists", "--no-owner", "-d", d.GetDatabase()}
	switch {
	case engine == KindPostgres && d.GetContainer() != "":
		docker, err := look("docker")
		if err != nil {
			return nil, err
		}
		return append([]string{docker, "exec", "-i", "-u", "postgres", d.GetContainer()}, pgArgs...), nil
	case engine == KindPostgres:
		runuser, err := look("runuser")
		if err != nil {
			return nil, err
		}
		pr, err := look("pg_restore")
		if err != nil {
			return nil, err
		}
		return append([]string{runuser, "-u", "postgres", "--", pr}, pgArgs[1:]...), nil
	case engine == KindMySQL && d.GetContainer() != "":
		docker, err := look("docker")
		if err != nil {
			return nil, err
		}
		return []string{docker, "exec", "-i", d.GetContainer(), "sh", "-c", mysqlLoadScript}, nil
	case engine == KindMySQL:
		cli, err := look("mariadb")
		if err != nil {
			if cli, err = look("mysql"); err != nil {
				return nil, err
			}
		}
		return []string{cli}, nil
	}
	return nil, fmt.Errorf("движок %q", engine)
}

const mysqlLoadScript = `p="${MYSQL_ROOT_PASSWORD:-${MARIADB_ROOT_PASSWORD:-}}"; ` +
	`f="${MYSQL_ROOT_PASSWORD_FILE:-${MARIADB_ROOT_PASSWORD_FILE:-}}"; ` +
	`if [ -n "$f" ]; then p="$(cat "$f")"; fi; ` +
	`c=mysql; if command -v mariadb >/dev/null 2>&1; then c=mariadb; fi; ` +
	`MYSQL_PWD="$p" exec "$c" -uroot`

// pingDatabase — база отвечает на простой запрос после загрузки.
func (e *Env) pingDatabase(ctx context.Context, engine string, d *agentv1.DatabaseSource) error {
	var err error
	switch {
	case engine == KindPostgres && d.GetContainer() != "":
		_, err = e.query(ctx, "docker", "exec", "-u", "postgres", d.GetContainer(), "psql", "-X", "-At", "-d", d.GetDatabase(), "-c", "SELECT 1")
	case engine == KindPostgres:
		_, err = e.query(ctx, "runuser", "-u", "postgres", "--", "psql", "-X", "-At", "-d", d.GetDatabase(), "-c", "SELECT 1")
	case engine == KindMySQL && d.GetContainer() != "":
		_, err = e.query(ctx, "docker", "exec", d.GetContainer(), "sh", "-c", mysqlLoadScript+` -e 'SELECT 1' "$1"`, "sh", d.GetDatabase())
	case engine == KindMySQL:
		_, err = e.query(ctx, "mysql", "-e", "SELECT 1", d.GetDatabase())
	default:
		err = fmt.Errorf("движок %q", engine)
	}
	if err != nil {
		return fmt.Errorf("база %s не отвечает после восстановления: %w", d.GetDatabase(), err)
	}
	return nil
}

func cleanEnv() []string { return []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"} }

// runToFile — вывод команды в файл (0600); ненулевой код — ошибка.
func runToFile(ctx context.Context, argv []string, path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	c := exec.CommandContext(ctx, argv[0], argv[1:]...)
	c.Env, c.Stdout = cleanEnv(), f
	var stderr tail
	c.Stderr = &stderr
	err = c.Run()
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("%v: %s", err, firstLine(stderr.Bytes()))
	}
	return nil
}

// runFromReader — команда со stdin из r; ненулевой код — ошибка с началом stderr.
func runFromReader(ctx context.Context, argv []string, r io.Reader) error {
	c := exec.CommandContext(ctx, argv[0], argv[1:]...)
	c.Env, c.Stdin = cleanEnv(), r
	var stderr tail
	c.Stdout, c.Stderr = io.Discard, &stderr
	if err := c.Run(); err != nil {
		return fmt.Errorf("%s: %v: %s", filepath.Base(argv[0]), err, firstLine(stderr.Bytes()))
	}
	return nil
}

// RecoverLocalCopy — помощник перезапустился посреди восстановления на место: вернуть локальную копию (пути или
// базу). false — копии нет (восстановление шло во временный каталог или со снапшотом хостера).
func (e *Env) RecoverLocalCopy(ctx context.Context, op string) (bool, error) {
	dir := e.LocalCopyDir(op)
	raw, err := fsutil.ReadLimited(filepath.Join(dir, "manifest.json"), 4<<20)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var lc localCopy
	if err := json.Unmarshal(raw, &lc); err != nil {
		return false, err
	}
	if lc.Database == "" {
		return true, e.restoreLocalCopy(op, &lc)
	}
	load, err := e.loadCommand(lc.Engine, &agentv1.DatabaseSource{Container: lc.Container, Database: lc.Database})
	if err != nil {
		return true, err
	}
	f, err := os.Open(filepath.Join(dir, "database.dump"))
	if err != nil {
		return true, err
	}
	defer f.Close()
	return true, runFromReader(ctx, load, f)
}
