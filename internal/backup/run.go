// SPDX-License-Identifier: AGPL-3.0-only

package backup

import (
	"context"
	"errors"
	"os"
	"time"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
)

// Коды итога backup.run.
const (
	CodeSourceFailed   = "BACKUP_SOURCE_FAILED"
	CodeDumpFailed     = "BACKUP_DUMP_FAILED"
	CodeWindowExceeded = "BACKUP_WINDOW_EXCEEDED"
)

// RunJob — параметры запуска плана.
type RunJob struct {
	Params   *agentv1.BackupRunParams
	Deadline time.Time
	Progress func(source string, st Status)
}

// RunPlan — снимок на каждый источник (decisions E13 п. 2): пути и тома — файлами, базы — дампом потоком без
// файла на диске. Сбой источника не останавливает остальные; срок окна останавливает всё (следующий запуск
// дозагрузит недостающее). Ошибка — только когда нельзя продолжать (репозиторий, срок).
func (e *Env) RunPlan(ctx context.Context, r *Restic, j RunJob) (*agentv1.BackupRunResult, string, error) {
	res := &agentv1.BackupRunResult{}
	code := ""
	for _, src := range j.Params.GetSources() {
		sr := &agentv1.SourceResult{Name: src.GetName()}
		res.Sources = append(res.Sources, sr)
		spec := BackupSpec{Source: src.GetName(), Deadline: j.Deadline, LimitKiB: j.Params.GetRateLimitKibps()}
		if j.Progress != nil {
			name := src.GetName()
			spec.Progress = func(st Status) { j.Progress(name, st) }
		}
		failCode := CodeSourceFailed
		switch v := src.GetSource().(type) {
		case *agentv1.BackupSource_Path:
			if _, err := os.Lstat(v.Path.GetPath()); err != nil {
				sr.Error = "путь недоступен: " + err.Error()
				code = firstCode(code, failCode)
				continue
			}
			spec.Kind, spec.Paths, spec.Excludes = KindPath, []string{v.Path.GetPath()}, v.Path.GetExcludes()
		case *agentv1.BackupSource_DockerVolume:
			mp, err := e.VolumeMountpoint(ctx, v.DockerVolume)
			if err != nil {
				sr.Error = "том " + v.DockerVolume + ": " + err.Error()
				code = firstCode(code, failCode)
				continue
			}
			spec.Kind, spec.Paths = KindVolume, []string{mp}
		case *agentv1.BackupSource_Postgres, *agentv1.BackupSource_Mysql:
			failCode = CodeDumpFailed
			engine, db := KindPostgres, src.GetPostgres()
			if src.GetMysql() != nil {
				engine, db = KindMySQL, src.GetMysql()
			}
			cmd, file, err := e.DumpCommand(engine, db)
			if err != nil {
				sr.Error = err.Error()
				code = firstCode(code, failCode)
				continue
			}
			spec.Kind, spec.StdinCommand, spec.StdinName = engine, cmd, file
			spec.Container, spec.Database = db.GetContainer(), db.GetDatabase()
		}
		sum, warning, err := Backup(ctx, r, spec)
		if errors.Is(err, ErrDeadline) {
			sr.Error = "срок окна вышел"
			return res, CodeWindowExceeded, nil
		}
		if errors.Is(err, ErrRepoPassword) || errors.Is(err, ErrRepoLocked) || errors.Is(err, ErrTargetDown) {
			sr.Error = err.Error()
			return res, "", err
		}
		if err != nil {
			sr.Error = err.Error()
			code = firstCode(code, failCode)
			continue
		}
		sr.Ok, sr.SnapshotId, sr.Warning = true, sum.SnapshotID, warning
		sr.BytesAdded, sr.BytesProcessed, sr.FilesNew, sr.FilesChanged = sum.DataAdded, sum.BytesProcessed, sum.FilesNew, sum.FilesChanged
	}
	return res, code, nil
}

func firstCode(cur, next string) string {
	if cur != "" {
		return cur
	}
	return next
}
