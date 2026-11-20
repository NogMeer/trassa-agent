// SPDX-License-Identifier: AGPL-3.0-only

package backup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
)

// Метки снимков Trassa: план и источник. По метке источника восстановление и чистка находят его снимки.
const (
	TagTrassa       = "trassa"
	TagSourcePrefix = "source="
	// TagKindPrefix — вид источника: path, volume, postgres, mysql (дамп — один файл потока).
	TagKindPrefix = "kind="
	// TagContainerPrefix — контейнер базы: проверка и восстановление дампа идут в нём (те же версии утилит).
	TagContainerPrefix = "container="
	// TagDatabasePrefix — имя базы дампа.
	TagDatabasePrefix = "database="
)

// Виды источников в метке kind=.
const (
	KindPath     = "path"
	KindVolume   = "volume"
	KindPostgres = "postgres"
	KindMySQL    = "mysql"
)

// Tag — значение метки prefix у снимка ("" — нет).
func (s *Snapshot) Tag(prefix string) string {
	for _, t := range s.Tags {
		if strings.HasPrefix(t, prefix) {
			return strings.TrimPrefix(t, prefix)
		}
	}
	return ""
}

// IsDump — снимок дампа базы (один файл потока).
func (s *Snapshot) IsDump() bool {
	k := s.Tag(TagKindPrefix)
	return k == KindPostgres || k == KindMySQL
}

// Ошибки репозитория (коды для итога операции).
var (
	ErrRepoExists      = errors.New("BACKUP_REPO_EXISTS")
	ErrRepoPassword    = errors.New("BACKUP_REPO_PASSWORD_INVALID")
	ErrRepoLocked      = errors.New("BACKUP_REPO_LOCKED")
	ErrTargetDown      = errors.New("BACKUP_TARGET_UNREACHABLE")
	ErrSnapshotMissing = errors.New("BACKUP_SNAPSHOT_PRUNED")
)

// InitRepo — backup.init (decisions E13 п. 1.9): `cat config` 0 — репозиторий наш, 10 — нет (init),
// 12 — чужой или неверный пароль, 11 — заблокирован. По тексту ошибки не ветвимся.
func InitRepo(ctx context.Context, r *Restic) (existed bool, err error) {
	err = r.Run(ctx, Command{Args: []string{"cat", "config"}})
	if err == nil {
		return true, nil
	}
	switch ExitCode(err) {
	case ExitNoRepo:
	case ExitBadPassword:
		return false, fmt.Errorf("%w: %v", ErrRepoExists, err)
	case ExitLocked:
		return false, fmt.Errorf("%w: %v", ErrRepoLocked, err)
	default:
		return false, fmt.Errorf("%w: %v", ErrTargetDown, err)
	}
	var initialized bool
	err = r.Run(ctx, Command{Args: []string{"init"}, Line: func(b []byte) {
		var m struct {
			Type string `json:"message_type"`
		}
		if json.Unmarshal(b, &m) == nil && m.Type == "initialized" {
			initialized = true
		}
	}})
	if err != nil {
		return false, fmt.Errorf("%w: init: %v", ErrTargetDown, err)
	}
	if !initialized {
		return false, errors.New("init: restic не сообщил о создании репозитория")
	}
	return false, nil
}

// Snapshot — снимок из `snapshots --json`.
type Snapshot struct {
	ID    string    `json:"id"`
	Time  time.Time `json:"time"`
	Paths []string  `json:"paths"`
	Tags  []string  `json:"tags"`
}

// Snapshots — снимки Trassa в репозитории.
func Snapshots(ctx context.Context, r *Restic) ([]Snapshot, error) {
	var raw []byte
	err := r.Run(ctx, Command{Args: []string{"snapshots", "--tag", TagTrassa}, Line: func(b []byte) {
		if len(raw) < 32<<20 {
			raw = append(raw, b...)
		}
	}})
	if err != nil {
		return nil, repoErr(err)
	}
	var out []Snapshot
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("snapshots: вывод restic не разобран: %v", err)
	}
	return out, nil
}

// repoErr — ошибка открытия репозитория в код итога.
func repoErr(err error) error {
	switch ExitCode(err) {
	case ExitBadPassword:
		return fmt.Errorf("%w: %v", ErrRepoPassword, err)
	case ExitLocked:
		return fmt.Errorf("%w: %v", ErrRepoLocked, err)
	case ExitNoRepo:
		return fmt.Errorf("%w: %v", ErrTargetDown, err)
	}
	return err
}

// Browse — содержимое каталога снимка, до limit записей (`ls --json`): только прямые потомки path.
func Browse(ctx context.Context, r *Restic, snapshot, path string, limit int) ([]*agentv1.BrowseEntry, bool, error) {
	var entries []*agentv1.BrowseEntry
	truncated := false
	parent := strings.TrimSuffix(path, "/")
	err := r.Run(ctx, Command{Args: []string{"ls", snapshot, path}, Line: func(b []byte) {
		var n struct {
			Type     string    `json:"message_type"`
			Struct   string    `json:"struct_type"`
			Name     string    `json:"name"`
			NodeType string    `json:"type"`
			Path     string    `json:"path"`
			Size     uint64    `json:"size"`
			Mtime    time.Time `json:"mtime"`
		}
		if json.Unmarshal(b, &n) != nil || (n.Type != "node" && n.Struct != "node") {
			return
		}
		// ls выводит и сам каталог, и его поддерево: берём прямых потомков.
		dir := n.Path[:max(0, strings.LastIndexByte(n.Path, '/'))]
		if dir != parent {
			return
		}
		if len(entries) >= limit {
			truncated = true
			return
		}
		entries = append(entries, &agentv1.BrowseEntry{Name: n.Name, Type: n.NodeType, Size: n.Size, MtimeMs: n.Mtime.UnixMilli()})
	}})
	if err != nil {
		if ExitCode(err) == ExitFailed && strings.Contains(err.Error(), "no matching ID") {
			return nil, false, fmt.Errorf("%w: %v", ErrSnapshotMissing, err)
		}
		return nil, false, repoErr(err)
	}
	return entries, truncated, nil
}

// Summary — итог `backup --json`.
type Summary struct {
	SnapshotID     string `json:"snapshot_id"`
	FilesNew       uint64 `json:"files_new"`
	FilesChanged   uint64 `json:"files_changed"`
	DataAdded      uint64 `json:"data_added"`
	BytesProcessed uint64 `json:"total_bytes_processed"`
}

// Status — ход `backup --json` и `restore --json`.
type Status struct {
	BytesDone  uint64 `json:"bytes_done"`
	TotalBytes uint64 `json:"total_bytes"`
	FilesDone  uint64 `json:"files_done"`
	// restore
	BytesRestored uint64 `json:"bytes_restored"`
	FilesRestored uint64 `json:"files_restored"`
}

// BackupSpec — один снимок: пути или поток команды.
type BackupSpec struct {
	Source string
	Kind   string
	// Container и Database — для дампа базы (метки снимка).
	Container string
	Database  string
	Paths     []string
	Excludes  []string
	// StdinCommand — команда дампа (без оболочки), StdinName — имя файла в снимке.
	StdinCommand []string
	StdinName    string
	Deadline     time.Time
	LimitKiB     uint32
	Progress     func(Status)
}

// Backup — снимок с меткой источника. Код 3 (часть файлов не прочитана) — снимок есть, но с предупреждением.
func Backup(ctx context.Context, r *Restic, s BackupSpec) (*Summary, string, error) {
	args := []string{"backup", "--tag", TagTrassa, "--tag", TagSourcePrefix + s.Source, "--tag", TagKindPrefix + s.Kind}
	if s.Container != "" {
		args = append(args, "--tag", TagContainerPrefix+s.Container)
	}
	if s.Database != "" {
		args = append(args, "--tag", TagDatabasePrefix+s.Database)
	}
	if len(s.StdinCommand) > 0 {
		args = append(args, "--stdin-from-command", "--stdin-filename", s.StdinName, "--")
		args = append(args, s.StdinCommand...)
	} else {
		for _, e := range s.Excludes {
			args = append(args, "--exclude", e)
		}
		args = append(args, "--")
		args = append(args, s.Paths...)
	}
	var sum Summary
	var got bool
	err := r.Run(ctx, Command{Args: args, Deadline: s.Deadline, LimitUploadKiB: s.LimitKiB, Line: func(b []byte) {
		var m struct {
			Type string `json:"message_type"`
		}
		if json.Unmarshal(b, &m) != nil {
			return
		}
		switch m.Type {
		case "status":
			var st Status
			if s.Progress != nil && json.Unmarshal(b, &st) == nil {
				s.Progress(st)
			}
		case "summary":
			got = json.Unmarshal(b, &sum) == nil
		}
	}})
	warning := ""
	if ExitCode(err) == ExitPartial && got && sum.SnapshotID != "" {
		warning = "часть файлов не прочитана: " + err.Error()
		err = nil
	}
	if err != nil {
		return nil, "", repoErr(err)
	}
	if !got || sum.SnapshotID == "" {
		return nil, "", errors.New("restic не сообщил снимок")
	}
	return &sum, warning, nil
}

// CheckResult — итог `check --json`.
type CheckResult struct {
	NumErrors   int      `json:"num_errors"`
	BrokenPacks []string `json:"broken_packs"`
}

// Check — целостность репозитория с чтением доли данных (--read-data-subset).
func Check(ctx context.Context, r *Restic, subset string, deadline time.Time) (bool, string, error) {
	var res CheckResult
	got := false
	err := r.Run(ctx, Command{Args: []string{"check", "--read-data-subset=" + subset}, Deadline: deadline, Line: func(b []byte) {
		var m struct {
			Type string `json:"message_type"`
		}
		if json.Unmarshal(b, &m) == nil && m.Type == "summary" {
			got = json.Unmarshal(b, &res) == nil
		}
	}})
	switch {
	case err == nil:
		return true, "", nil
	case ExitCode(err) == ExitFailed:
		detail := err.Error()
		if got {
			detail = fmt.Sprintf("ошибок %d, повреждённых pack %d: %s", res.NumErrors, len(res.BrokenPacks), detail)
		}
		return false, detail, nil
	}
	return false, "", repoErr(err)
}

// RestoreSpec — восстановление снимка в каталог.
type RestoreSpec struct {
	Snapshot string
	Target   string
	Includes []string
	Deadline time.Time
	Progress func(Status)
}

// RestoreSummary — итог `restore --json`.
type RestoreSummary struct {
	TotalFiles    uint64 `json:"total_files"`
	FilesRestored uint64 `json:"files_restored"`
	TotalBytes    uint64 `json:"total_bytes"`
	BytesRestored uint64 `json:"bytes_restored"`
}

// Restore — `restore <snapshot> --target <каталог>`; restic 0.20.0 не пишет за пределы каталога по ссылкам
// (#22180). Владельцы — по числовым id (без --ownership-by-name, #22178).
func Restore(ctx context.Context, r *Restic, s RestoreSpec) (*RestoreSummary, error) {
	args := []string{"restore", s.Snapshot, "--target", s.Target}
	for _, inc := range s.Includes {
		args = append(args, "--include", inc)
	}
	var sum RestoreSummary
	got := false
	err := r.Run(ctx, Command{Args: args, Deadline: s.Deadline, Line: func(b []byte) {
		var m struct {
			Type string `json:"message_type"`
		}
		if json.Unmarshal(b, &m) != nil {
			return
		}
		switch m.Type {
		case "status":
			var st Status
			if s.Progress != nil && json.Unmarshal(b, &st) == nil {
				s.Progress(st)
			}
		case "summary":
			got = json.Unmarshal(b, &sum) == nil
		}
	}})
	if err != nil {
		return nil, repoErr(err)
	}
	if !got {
		return nil, errors.New("restic не сообщил итог восстановления")
	}
	return &sum, nil
}

// Dump — файл снимка в w (`dump`): дамп базы потоком, без файла на диске.
func Dump(ctx context.Context, r *Restic, snapshot, file string, w io.Writer) error {
	err := r.Run(ctx, Command{Args: []string{"dump", snapshot, file}, Stdout: w, Raw: true})
	if err != nil {
		return repoErr(err)
	}
	return nil
}

// Forget — чистка по политике с освобождением места (`forget --prune`), по группам источников. Сроки
// keep-within — для хранилищ «только добавление» (decisions E13, развилка 2).
func Forget(ctx context.Context, r *Restic, ret *agentv1.Retention, deadline time.Time) (removed uint32, err error) {
	args := []string{"forget", "--prune", "--tag", TagTrassa, "--group-by", "host,tags"}
	if ret.GetKeepLast() > 0 {
		args = append(args, "--keep-last", strconv.FormatUint(uint64(ret.GetKeepLast()), 10))
	}
	for _, kv := range [][2]string{
		{"--keep-within-daily", ret.GetKeepWithinDaily()}, {"--keep-within-weekly", ret.GetKeepWithinWeekly()},
		{"--keep-within-monthly", ret.GetKeepWithinMonthly()},
	} {
		if kv[1] != "" {
			args = append(args, kv[0], kv[1])
		}
	}
	err = r.Run(ctx, Command{Args: args, Deadline: deadline, Line: func(b []byte) {
		var groups []struct {
			Remove []json.RawMessage `json:"remove"`
		}
		if json.Unmarshal(b, &groups) == nil {
			for _, g := range groups {
				removed += uint32(len(g.Remove))
			}
		}
	}})
	if err != nil {
		return removed, repoErr(err)
	}
	return removed, nil
}

// Node — файл снимка из `ls --json`.
type Node struct {
	Path string
	Type string
	Size uint64
}

// List — все узлы снимка (рекурсивно), не больше max: выборка для проверки и объём для восстановления.
func List(ctx context.Context, r *Restic, snapshot string, max int) ([]Node, bool, error) {
	var out []Node
	truncated := false
	err := r.Run(ctx, Command{Args: []string{"ls", snapshot}, Line: func(b []byte) {
		var n struct {
			Type     string `json:"message_type"`
			Struct   string `json:"struct_type"`
			NodeType string `json:"type"`
			Path     string `json:"path"`
			Size     uint64 `json:"size"`
		}
		if json.Unmarshal(b, &n) != nil || (n.Type != "node" && n.Struct != "node") {
			return
		}
		if len(out) >= max {
			truncated = true
			return
		}
		out = append(out, Node{Path: n.Path, Type: n.NodeType, Size: n.Size})
	}})
	if err != nil {
		return nil, false, repoErr(err)
	}
	return out, truncated, nil
}

// Stats — объём данных репозитория (`stats --mode raw-data`, поле total_size).
func Stats(ctx context.Context, r *Restic) (uint64, error) {
	var total uint64
	got := false
	err := r.Run(ctx, Command{Args: []string{"stats", "--mode", "raw-data"}, Line: func(b []byte) {
		var m struct {
			TotalSize *uint64 `json:"total_size"`
		}
		if json.Unmarshal(b, &m) == nil && m.TotalSize != nil {
			total, got = *m.TotalSize, true
		}
	}})
	if err != nil {
		return 0, repoErr(err)
	}
	if !got {
		return 0, errors.New("stats: нет total_size")
	}
	return total, nil
}
