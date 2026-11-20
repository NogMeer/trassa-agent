// SPDX-License-Identifier: AGPL-3.0-only

package backup

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
)

// ErrNoSpace — во временном каталоге или на месте восстановления не хватает места (BACKUP_DEST_NO_SPACE).
var ErrNoSpace = errors.New("BACKUP_DEST_NO_SPACE")

// maxListNodes — предел узлов снимка, который читает выборка проверки и оценка восстановления.
const maxListNodes = 2_000_000

// mysqlTrailer — последняя строка полного дампа mysqldump/mariadb-dump: дамп, оборванный на середине, её не имеет.
var mysqlTrailer = []byte("-- Dump completed")

// LatestPerSource — последний снимок каждого источника.
func LatestPerSource(snaps []Snapshot) []Snapshot {
	last := map[string]Snapshot{}
	for _, s := range snaps {
		src := s.Tag(TagSourcePrefix)
		if cur, ok := last[src]; !ok || s.Time.After(cur.Time) {
			last[src] = s
		}
	}
	out := make([]Snapshot, 0, len(last))
	for _, s := range last {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Tag(TagSourcePrefix) < out[j].Tag(TagSourcePrefix) })
	return out
}

// pick — снимки проверки: заданные id (по полному id или префиксу) или последние по источникам.
func pick(snaps []Snapshot, ids []string) ([]Snapshot, error) {
	if len(ids) == 0 {
		return LatestPerSource(snaps), nil
	}
	var out []Snapshot
	for _, id := range ids {
		found := false
		for _, s := range snaps {
			if strings.HasPrefix(s.ID, id) {
				out = append(out, s)
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("%w: снимок %s", ErrSnapshotMissing, id)
		}
	}
	return out, nil
}

// sample — равномерная выборка файлов: не больше n штук и maxBytes байт (0 — без предела).
func sample(nodes []Node, n int, maxBytes uint64) []Node {
	var files []Node
	for _, x := range nodes {
		if x.Type == "file" {
			files = append(files, x)
		}
	}
	if n <= 0 || len(files) == 0 {
		return nil
	}
	step := max(1, len(files)/n)
	var out []Node
	var total uint64
	for i := 0; i < len(files) && len(out) < n; i += step {
		f := files[i]
		if maxBytes > 0 && total+f.Size > maxBytes {
			continue
		}
		total += f.Size
		out = append(out, f)
	}
	return out
}

// VerifySpec — параметры проверки.
type VerifySpec struct {
	OpID     string
	Params   *agentv1.BackupVerifyParams
	Deadline time.Time
}

// Verify — три части (E13 раздел 6): целостность репозитория (check --read-data-subset), пробное восстановление
// выборки во временный каталог со сверкой размеров, читаемость каждого дампа утилитой своей базы без загрузки в
// рабочую базу. Временный каталог удаляется всегда.
func (e *Env) Verify(ctx context.Context, r *Restic, s VerifySpec) (*agentv1.BackupVerifyResult, error) {
	p := s.Params
	res := &agentv1.BackupVerifyResult{}
	ok, detail, err := Check(ctx, r, p.GetReadDataSubset(), s.Deadline)
	if err != nil {
		return nil, err
	}
	res.RepoCheckOk = ok
	snaps, err := Snapshots(ctx, r)
	if err != nil {
		return nil, err
	}
	chosen, err := pick(snaps, p.GetSnapshotIds())
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(e.WorkDir, "restore-test", strings.ToLower(s.OpID))
	defer os.RemoveAll(dir)
	res.FilesOk, res.DumpsOk = true, true
	if !ok {
		res.Dumps = append(res.Dumps, &agentv1.DumpCheck{Source: "repository", Ok: false, Detail: detail})
	}
	for _, snap := range chosen {
		if snap.IsDump() {
			dc := e.checkDump(ctx, r, snap)
			res.DumpsOk = res.DumpsOk && dc.Ok
			res.Dumps = append(res.Dumps, dc)
			continue
		}
		nodes, _, err := List(ctx, r, snap.ID, maxListNodes)
		if err != nil {
			return nil, err
		}
		pickN := sample(nodes, int(p.GetSampleFiles()), p.GetMaxBytes())
		if len(pickN) == 0 {
			continue
		}
		var need uint64
		for _, n := range pickN {
			need += n.Size
		}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
		if free, err := FreeBytes(dir); err == nil && free < need+need/10+(64<<20) {
			return nil, fmt.Errorf("%w: нужно %d байт, свободно %d", ErrNoSpace, need, free)
		}
		target := filepath.Join(dir, snap.ID[:8])
		includes := make([]string, 0, len(pickN))
		for _, n := range pickN {
			includes = append(includes, n.Path)
		}
		if _, err := Restore(ctx, r, RestoreSpec{Snapshot: snap.ID, Target: target, Includes: includes, Deadline: s.Deadline}); err != nil {
			return nil, err
		}
		for _, n := range pickN {
			st, err := os.Lstat(filepath.Join(target, n.Path))
			if err != nil || !st.Mode().IsRegular() || uint64(st.Size()) != n.Size {
				res.FilesOk = false
				continue
			}
			res.CheckedFiles++
			res.CheckedBytes += n.Size
		}
		_ = os.RemoveAll(target)
	}
	return res, nil
}

// checkDump — дамп читается потоком из репозитория: PostgreSQL — pg_restore --list (в контейнере источника, если
// база была там), MySQL — дамп дочитан до строки завершения.
func (e *Env) checkDump(ctx context.Context, r *Restic, snap Snapshot) *agentv1.DumpCheck {
	src := snap.Tag(TagSourcePrefix)
	dc := &agentv1.DumpCheck{Source: src}
	if len(snap.Paths) != 1 {
		dc.Detail = "в снимке дампа не один файл"
		return dc
	}
	file := snap.Paths[0]
	switch snap.Tag(TagKindPrefix) {
	case KindPostgres:
		cmd, err := e.pgRestoreList(snap.Tag(TagContainerPrefix))
		if err != nil {
			dc.Detail = err.Error()
			return dc
		}
		c := exec.CommandContext(ctx, cmd[0], cmd[1:]...)
		c.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C"}
		in, err := c.StdinPipe()
		if err != nil {
			dc.Detail = err.Error()
			return dc
		}
		var out bytes.Buffer
		c.Stdout, c.Stderr = &out, &out
		if err := c.Start(); err != nil {
			dc.Detail = err.Error()
			return dc
		}
		derr := Dump(ctx, r, snap.ID, file, in)
		in.Close()
		werr := c.Wait()
		switch {
		case derr != nil:
			dc.Detail = "дамп не прочитан из репозитория: " + derr.Error()
		case werr != nil:
			dc.Detail = "pg_restore --list: " + Clean(firstLine(out.Bytes()), r.Repo.Secrets())
		default:
			dc.Ok = true
		}
	case KindMySQL:
		var tail lastBytes
		if err := Dump(ctx, r, snap.ID, file, &tail); err != nil {
			dc.Detail = "дамп не прочитан из репозитория: " + err.Error()
			return dc
		}
		if !bytes.Contains(tail.b, mysqlTrailer) {
			dc.Detail = "дамп MySQL оборван: нет строки завершения"
			return dc
		}
		dc.Ok = true
	}
	return dc
}

// pgRestoreList — pg_restore --list из stdin: в контейнере источника (те же версии) или на хосте.
func (e *Env) pgRestoreList(container string) ([]string, error) {
	look := e.Look
	if look == nil {
		return nil, errors.New("нет поиска программ")
	}
	if container != "" {
		docker, err := look("docker")
		if err != nil {
			return nil, err
		}
		return []string{docker, "exec", "-i", "-u", "postgres", container, "pg_restore", "--list"}, nil
	}
	pr, err := look("pg_restore")
	if err != nil {
		return nil, fmt.Errorf("pg_restore: %w", err)
	}
	return []string{pr, "--list"}, nil
}

// lastBytes — последние 4 КиБ потока.
type lastBytes struct{ b []byte }

func (l *lastBytes) Write(p []byte) (int, error) {
	l.b = append(l.b, p...)
	if len(l.b) > 4096 {
		l.b = append([]byte(nil), l.b[len(l.b)-4096:]...)
	}
	return len(p), nil
}
