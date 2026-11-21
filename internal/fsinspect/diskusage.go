// SPDX-License-Identifier: AGPL-3.0-only

// Package fsinspect — чтение для ИИ-оператора (E20): disk.usage и config.read. Списки разрешённых путей зашиты
// здесь (decisions/E20-agent.md); Root — корень файловой системы (в тестах — временный каталог).
package fsinspect

import (
	"container/heap"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
)

// Коды отказа.
const (
	CodeDiskPathForbidden   = "DISK_PATH_FORBIDDEN"
	CodeDiskPathNotFound    = "DISK_PATH_NOT_FOUND"
	CodeConfigPathForbidden = "CONFIG_PATH_FORBIDDEN"
	CodeConfigNotFound      = "CONFIG_NOT_FOUND"
	CodeConfigTooLarge      = "CONFIG_TOO_LARGE"
	CodeConfigNotText       = "CONFIG_NOT_TEXT"
)

// Ошибки с кодом: errors.Is(err, ErrX) и Code(err).
var (
	ErrDiskPathForbidden   = errors.New(CodeDiskPathForbidden)
	ErrDiskPathNotFound    = errors.New(CodeDiskPathNotFound)
	ErrConfigPathForbidden = errors.New(CodeConfigPathForbidden)
	ErrConfigNotFound      = errors.New(CodeConfigNotFound)
	ErrConfigTooLarge      = errors.New(CodeConfigTooLarge)
	ErrConfigNotText       = errors.New(CodeConfigNotText)
	codes                  = []error{ErrDiskPathForbidden, ErrDiskPathNotFound, ErrConfigPathForbidden, ErrConfigNotFound,
		ErrConfigTooLarge, ErrConfigNotText}
)

// Code — код отказа или "".
func Code(err error) string {
	for _, c := range codes {
		if errors.Is(err, c) {
			return c.Error()
		}
	}
	return ""
}

// Пределы disk.usage.
const (
	MaxDepth     = 3
	MaxTop       = 20
	WalkTimeout  = 60 * time.Second
	MaxEntries   = 5_000_000
	maxDirs      = 200_000
	maxMounts    = 50
	maxPathBytes = 1024
)

// diskRoots — где можно начинать: «/» только сам, остальные — с подкаталогами.
var diskRoots = []string{"/var", "/home", "/opt", "/srv", "/tmp", "/usr", "/root", "/mnt", "/media", "/data", "/backup"}

// Env — корень и часы.
type Env struct {
	Root string
	Now  func() time.Time
}

func (e *Env) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

func (e *Env) real(p string) string { return filepath.Join(e.Root, filepath.FromSlash(p)) }

// cleanAbs — абсолютный путь без «..», «.», «//» и хвостового «/», без управляющих знаков, до 512 байт.
func cleanAbs(p string) bool {
	if p == "" || len(p) > 512 || !strings.HasPrefix(p, "/") || path.Clean(p) != p || !utf8.ValidString(p) {
		return false
	}
	for _, r := range p {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// ValidateDiskUsage — проверка параметров до запуска.
func ValidateDiskUsage(p *agentv1.DiskUsageParams) error {
	if p.GetDepth() < 1 || p.GetDepth() > MaxDepth {
		return errors.New("depth: 1–3")
	}
	if p.GetTop() < 1 || p.GetTop() > MaxTop {
		return errors.New("top: 1–20")
	}
	if !DiskPathAllowed(p.GetPath()) {
		return fmt.Errorf("%w: %s", ErrDiskPathForbidden, p.GetPath())
	}
	return nil
}

// DiskPathAllowed — «/» или путь внутри корня из списка.
func DiskPathAllowed(p string) bool {
	if !cleanAbs(p) {
		return false
	}
	if p == "/" {
		return true
	}
	for _, r := range diskRoots {
		if p == r || strings.HasPrefix(p, r+"/") {
			return true
		}
	}
	return false
}

// pseudo — каталоги ядра и времени работы: в обход от «/» не входят.
var pseudo = map[string]bool{"/proc": true, "/sys": true, "/dev": true, "/run": true}

type item struct {
	path  string
	bytes uint64
	dir   bool
	depth uint32
}

// minHeap — top самых больших файлов.
type minHeap []item

func (h minHeap) Len() int           { return len(h) }
func (h minHeap) Less(i, j int) bool { return h[i].bytes < h[j].bytes }
func (h minHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *minHeap) Push(x any)        { *h = append(*h, x.(item)) }
func (h *minHeap) Pop() any {
	old := *h
	x := old[len(old)-1]
	*h = old[:len(old)-1]
	return x
}

type inode struct{ dev, ino uint64 }

// DiskUsage — обход как `du -x`: та же файловая система, ссылки не раскрываются, жёсткие ссылки — один раз,
// размер — занятые блоки.
func (e *Env) DiskUsage(ctx context.Context, p *agentv1.DiskUsageParams) (*agentv1.DiskUsageResult, error) {
	if err := ValidateDiskUsage(p); err != nil {
		return nil, err
	}
	root := p.GetPath()
	rroot := e.real(root)
	// Путь через ссылку не обходится: иначе «/var/x → /etc» вывел бы обход за список корней.
	if resolved, err := filepath.EvalSymlinks(rroot); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s", ErrDiskPathNotFound, root)
		}
		return nil, err
	} else if base, berr := filepath.EvalSymlinks(e.Root); berr != nil || resolved != filepath.Join(base, filepath.FromSlash(root)) {
		return nil, fmt.Errorf("%w: %s — путь через ссылку", ErrDiskPathForbidden, root)
	}
	fi, err := os.Lstat(rroot)
	if err != nil {
		return nil, err
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("%w: %s — не каталог", ErrDiskPathNotFound, root)
	}
	rootDev := devOf(fi)
	res := &agentv1.DiskUsageResult{Path: root}
	var sfs syscall.Statfs_t
	if err := syscall.Statfs(rroot, &sfs); err == nil {
		bs := uint64(sfs.Bsize)
		res.FsSizeBytes, res.FsFreeBytes, res.FsAvailBytes = uint64(sfs.Blocks)*bs, uint64(sfs.Bfree)*bs, uint64(sfs.Bavail)*bs
	}
	maxDepth := p.GetDepth()
	deadline := e.now().Add(WalkTimeout)
	dirs := map[string]*item{}
	files := &minHeap{}
	seen := map[inode]bool{}
	top := int(p.GetTop())
	stop := errors.New("stop")
	walkErr := filepath.WalkDir(rroot, func(rp string, d fs.DirEntry, err error) error {
		rel := strings.TrimPrefix(filepath.ToSlash(strings.TrimPrefix(rp, rroot)), "/")
		if err != nil {
			res.Unreadable++
			if d != nil && d.IsDir() && rel != "" {
				return fs.SkipDir
			}
			return nil
		}
		if res.Files++; res.Files > MaxEntries || ctx.Err() != nil || (res.Files%4096 == 0 && e.now().After(deadline)) {
			res.Truncated = true
			return stop
		}
		vp := path.Join(root, rel)
		if d.IsDir() && rel != "" && (pseudo[vp]) {
			return fs.SkipDir
		}
		info, err := d.Info()
		if err != nil {
			res.Unreadable++
			return nil
		}
		if d.IsDir() && rel != "" && devOf(info) != rootDev {
			if len(res.OtherMounts) < maxMounts {
				res.OtherMounts = append(res.OtherMounts, printable(vp))
			}
			return fs.SkipDir
		}
		size := blocksOf(info)
		if st, ok := info.Sys().(*syscall.Stat_t); ok && !info.IsDir() && st.Nlink > 1 {
			k := inode{uint64(st.Dev), uint64(st.Ino)} //nolint:unconvert // Dev и Ino разного типа на linux и darwin
			if seen[k] {
				size = 0
			}
			seen[k] = true
		}
		res.TotalBytes += size
		depth := uint32(0)
		if rel != "" {
			depth = uint32(strings.Count(rel, "/") + 1)
		}
		// Размер — каталогам-предкам глубины 1…maxDepth.
		var parts []string
		if rel != "" {
			parts = strings.Split(rel, "/")
		}
		for k := 1; k <= len(parts) && k <= int(maxDepth); k++ {
			if k == len(parts) && !d.IsDir() {
				break
			}
			ap := path.Join(root, strings.Join(parts[:k], "/"))
			it := dirs[ap]
			if it == nil {
				if len(dirs) >= maxDirs {
					res.Truncated = true
					continue
				}
				it = &item{path: ap, dir: true, depth: uint32(k)}
				dirs[ap] = it
			}
			it.bytes += size
		}
		if !d.IsDir() && depth >= 1 && depth <= maxDepth {
			heap.Push(files, item{path: vp, bytes: size, depth: depth})
			if files.Len() > top {
				heap.Pop(files)
			}
		}
		return nil
	})
	if walkErr != nil && !errors.Is(walkErr, stop) {
		return nil, walkErr
	}
	all := append([]item{}, *files...)
	for _, it := range dirs {
		all = append(all, *it)
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].bytes != all[j].bytes {
			return all[i].bytes > all[j].bytes
		}
		return all[i].path < all[j].path
	})
	if len(all) > top {
		all = all[:top]
	}
	for _, it := range all {
		res.Entries = append(res.Entries, &agentv1.DiskUsageEntry{Path: printable(it.path), Bytes: it.bytes, Dir: it.dir, Depth: it.depth})
	}
	return res, nil
}

func devOf(fi fs.FileInfo) uint64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Dev) //nolint:unconvert // int32 на darwin
	}
	return 0
}

func blocksOf(fi fs.FileInfo) uint64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && st.Blocks > 0 {
		return uint64(st.Blocks) * 512
	}
	if fi.Mode().IsRegular() {
		return uint64(fi.Size())
	}
	return 0
}

// printable — имя файла для итога: proto требует UTF-8, управляющие знаки из имён не уходят (внедрение в вывод).
func printable(s string) string {
	s = strings.ToValidUTF8(s, "?")
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) || r == 0x2028 || r == 0x2029 || (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) {
			return '?'
		}
		return r
	}, s)
	if len(s) > maxPathBytes {
		cut := maxPathBytes
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut--
		}
		s = s[:cut]
	}
	return s
}
