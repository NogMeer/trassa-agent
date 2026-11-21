// SPDX-License-Identifier: AGPL-3.0-only

package remedy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/url"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
)

// Каталоги журнала systemd: постоянный и в памяти.
var journalDirs = []string{"/var/log/journal", "/run/log/journal"}

const aptArchives = "/var/cache/apt/archives"

// ValidateCleanup — disk.cleanup: категории из перечня без повторов, пусто — отказ (R1).
func ValidateCleanup(p *agentv1.DiskCleanupParams) error {
	if len(p.GetCategories()) == 0 {
		return errors.New("categories: пусто")
	}
	seen := map[agentv1.DiskCleanupCategory]bool{}
	for _, c := range p.GetCategories() {
		if c <= agentv1.DiskCleanupCategory_DISK_CLEANUP_CATEGORY_UNSPECIFIED || c > agentv1.DiskCleanupCategory_DISK_CLEANUP_CATEGORY_DOCKER_BUILD_CACHE || seen[c] {
			return fmt.Errorf("categories: %v", c)
		}
		seen[c] = true
	}
	if p.GetJournalKeepDays() > 365 || p.GetDockerUnusedOlderThanHours() > 8760 {
		return errors.New("journal_keep_days до 365, docker_unused_older_than_hours до 8760")
	}
	if m := p.GetMount(); m != "" && (!strings.HasPrefix(m, "/") || path.Clean(m) != m || len(m) > 256 || strings.ContainsAny(m, "\x00\n")) {
		return errors.New("mount")
	}
	return nil
}

func keepDays(p *agentv1.DiskCleanupParams) int {
	if d := p.GetJournalKeepDays(); d > 0 {
		return int(d)
	}
	return 7
}

func olderHours(p *agentv1.DiskCleanupParams) int {
	if h := p.GetDockerUnusedOlderThanHours(); h > 0 {
		return int(h)
	}
	return 24
}

// archivedJournal — архивный файл журнала: system@….journal или повреждённый ….journal~ (активный — без «@»).
func archivedJournal(name string) bool {
	return strings.HasSuffix(name, ".journal~") || (strings.HasSuffix(name, ".journal") && strings.Contains(name, "@"))
}

// journalSize — байт в архивных файлах журнала (older — только старше срока; нуль — все файлы журнала).
func (e *Env) journalSize(older time.Time, archivedOnly bool) uint64 {
	var n uint64
	for _, d := range journalDirs {
		_ = filepath.WalkDir(e.path(d), func(p string, de fs.DirEntry, err error) error {
			if err != nil || de.IsDir() || !de.Type().IsRegular() {
				return nil
			}
			if archivedOnly && !archivedJournal(de.Name()) {
				return nil
			}
			info, err := de.Info()
			if err != nil {
				return nil
			}
			if !older.IsZero() && !info.ModTime().Before(older) {
				return nil
			}
			n += uint64(info.Size())
			return nil
		})
	}
	return n
}

func (e *Env) aptSize() uint64 {
	var n uint64
	_ = filepath.WalkDir(e.path(aptArchives), func(p string, de fs.DirEntry, err error) error {
		if err != nil || de.IsDir() || !de.Type().IsRegular() || de.Name() == "lock" {
			return nil
		}
		if info, err := de.Info(); err == nil {
			n += uint64(info.Size())
		}
		return nil
	})
	return n
}

type dfImage struct {
	ID          string            `json:"Id"`
	Created     int64             `json:"Created"`
	Size        int64             `json:"Size"`
	Containers  int64             `json:"Containers"`
	Labels      map[string]string `json:"Labels"`
	RepoTags    []string          `json:"RepoTags"`
	RepoDigests []string          `json:"RepoDigests"`
}

type dfCache struct {
	InUse      bool   `json:"InUse"`
	Size       int64  `json:"Size"`
	LastUsedAt string `json:"LastUsedAt"`
}

type systemDF struct {
	Images     []dfImage `json:"Images"`
	BuildCache []dfCache `json:"BuildCache"`
}

// releaseIDs — id образов релизов Trassa: ссылки state.json разрешаются через Engine API (у Docker тег может быть
// записан иначе: docker.io/library/x и x). Любая ошибка, кроме «образа уже нет», — ошибка категории.
func (e *Env) releaseIDs(ctx context.Context) (map[string]bool, error) {
	ids := map[string]bool{}
	if e.TrassaImages == nil {
		return ids, nil
	}
	refs, err := e.TrassaImages()
	if err != nil {
		return nil, fmt.Errorf("образы релизов Trassa не прочитаны: %w", err)
	}
	for ref := range refs {
		var im struct {
			ID string `json:"Id"`
		}
		code, err := e.docker(ctx, http.MethodGet, "/images/"+ref+"/json", &im)
		if code == http.StatusNotFound {
			continue
		}
		if err != nil || im.ID == "" {
			return nil, fmt.Errorf("образ релиза %s: %v", ref, err)
		}
		ids[im.ID] = true
	}
	return ids, nil
}

// unusedImages — кандидаты DOCKER_UNUSED (решение E18, развилка 2а): без контейнеров (и остановленных), старше
// срока, без метки Trassa и не образы релизов приложений Trassa (точки отката E17), сравнение по id.
func unusedImages(df *systemDF, older time.Time, keep map[string]bool) []dfImage {
	var out []dfImage
	for _, im := range df.Images {
		if im.Containers != 0 || im.Labels[labelApp] != "" || time.Unix(im.Created, 0).After(older) || keep[im.ID] {
			continue
		}
		out = append(out, im)
	}
	return out
}

func staleCache(df *systemDF, older time.Time) uint64 {
	var n uint64
	for _, c := range df.BuildCache {
		t, err := time.Parse(time.RFC3339Nano, c.LastUsedAt)
		if c.InUse || (err == nil && t.After(older)) || c.Size < 0 {
			continue
		}
		n += uint64(c.Size)
	}
	return n
}

// Cleanup — disk.cleanup; dryRun — только оценка. Ошибка категории не останавливает остальные.
func (e *Env) Cleanup(ctx context.Context, p *agentv1.DiskCleanupParams, dryRun bool) (*agentv1.DiskCleanupResult, error) {
	mount := p.GetMount()
	if mount == "" {
		mount = "/"
	}
	res := &agentv1.DiskCleanupResult{}
	if e.Free != nil {
		if f, total, err := e.Free(e.path(mount)); err == nil {
			res.FreeBeforeBytes, res.TotalBytes = f, total
		}
	}
	now := e.now()
	var df *systemDF
	loadDF := func() (*systemDF, error) {
		if df != nil {
			return df, nil
		}
		var d systemDF
		if _, err := e.docker(ctx, http.MethodGet, "/system/df", &d); err != nil {
			return nil, err
		}
		df = &d
		return df, nil
	}
	failed := 0
	for _, c := range p.GetCategories() {
		fr := &agentv1.DiskCleanupFreed{Category: c}
		res.Freed = append(res.Freed, fr)
		var err error
		switch c {
		case agentv1.DiskCleanupCategory_DISK_CLEANUP_CATEGORY_JOURNAL:
			older := now.Add(-time.Duration(keepDays(p)) * 24 * time.Hour)
			if dryRun {
				fr.Bytes = e.journalSize(older, true)
				break
			}
			before := e.journalSize(time.Time{}, false)
			var out []byte
			if out, err = e.Run(ctx, "journalctl", "--vacuum-time="+strconv.Itoa(keepDays(p))+"d"); err != nil {
				err = fmt.Errorf("journalctl: %v %s", err, tail(out))
				break
			}
			if after := e.journalSize(time.Time{}, false); before > after {
				fr.Bytes = before - after
			}
		case agentv1.DiskCleanupCategory_DISK_CLEANUP_CATEGORY_APT_CACHE:
			if e.PackagesBusy != nil {
				if who := e.PackagesBusy(ctx); who != "" {
					err = fmt.Errorf("%w: %s", ErrPackageBusy, who)
					break
				}
			}
			before := e.aptSize()
			if dryRun {
				fr.Bytes = before
				break
			}
			var out []byte
			if out, err = e.Run(ctx, "apt-get", "clean"); err != nil {
				err = fmt.Errorf("apt-get clean: %v %s", err, tail(out))
				break
			}
			if after := e.aptSize(); before > after {
				fr.Bytes = before - after
			}
		case agentv1.DiskCleanupCategory_DISK_CLEANUP_CATEGORY_DOCKER_UNUSED:
			var d *systemDF
			if d, err = loadDF(); err != nil {
				break
			}
			var keep map[string]bool
			if keep, err = e.releaseIDs(ctx); err != nil {
				break // без списка точек отката не удаляется ничего
			}
			for _, im := range unusedImages(d, now.Add(-time.Duration(olderHours(p))*time.Hour), keep) {
				if dryRun {
					fr.Bytes += uint64(max(im.Size, 0))
					continue
				}
				// Без force: занятый (появился контейнер) образ Docker не удалит — 409, пропуск.
				code, derr := e.docker(ctx, http.MethodDelete, "/images/"+url.PathEscape(im.ID), nil)
				if code == http.StatusConflict || code == http.StatusNotFound {
					continue
				}
				if derr != nil {
					err = derr
					break
				}
				fr.Bytes += uint64(max(im.Size, 0))
			}
		case agentv1.DiskCleanupCategory_DISK_CLEANUP_CATEGORY_DOCKER_BUILD_CACHE:
			hours := olderHours(p)
			if dryRun {
				var d *systemDF
				if d, err = loadDF(); err == nil {
					fr.Bytes = staleCache(d, now.Add(-time.Duration(hours)*time.Hour))
				}
				break
			}
			f, _ := json.Marshal(map[string][]string{"until": {strconv.Itoa(hours) + "h"}})
			var out struct {
				SpaceReclaimed uint64 `json:"SpaceReclaimed"`
			}
			if _, err = e.docker(ctx, http.MethodPost, "/build/prune?filters="+url.QueryEscape(string(f)), &out); err == nil {
				fr.Bytes = out.SpaceReclaimed
			}
		}
		if err != nil {
			fr.Error = tail([]byte(err.Error()))
			failed++
		}
	}
	if e.Free != nil && !dryRun {
		if f, _, err := e.Free(e.path(mount)); err == nil {
			res.FreeAfterBytes = f
		}
	}
	if failed == len(res.Freed) {
		return res, errors.New("ни одна категория не очищена")
	}
	return res, nil
}
