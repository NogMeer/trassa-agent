// SPDX-License-Identifier: AGPL-3.0-only

package vpnprobe

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/fsutil"
	"github.com/NogMeer/trassa-agent/internal/tools"
	"github.com/NogMeer/trassa-agent/internal/update"
)

// Архив выпуска Xray — zip с бинарником xray в корне (Xray-linux-64.zip, Xray-linux-arm64-v8a.zip).
const (
	MaxArchive = 64 << 20
	MaxBinary  = 128 << 20
	// Staged — имя архива в каталоге операции (скачивает агент).
	Staged    = "vpn-probe-engine.zip"
	stateName = "engines.json"
)

// xrayVersionRe — первая строка `xray version`: «Xray 26.10.31 (Xray, Penetrates Everything.) …».
var xrayVersionRe = regexp.MustCompile(`^Xray (\d+\.\d+\.\d+) `)

// state — какая версия движка действует; файл — точка отката CONFIG у vpn.probe.ensure.
type state map[string]string

// StatePath — файл действующих версий (для точки отката).
func (e *Env) StatePath() string { return filepath.Join(e.Dir, stateName) }

func (e *Env) binPath(engine, version string) string {
	return filepath.Join(e.Dir, engine+"-"+version, engine)
}

func (e *Env) readState() (state, error) {
	raw, err := os.ReadFile(e.StatePath())
	if errors.Is(err, fs.ErrNotExist) {
		return state{}, nil
	}
	if err != nil {
		return nil, err
	}
	var s state
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("%s: %w", e.StatePath(), err)
	}
	if s == nil {
		s = state{}
	}
	return s, nil
}

// Installed — действующая версия движка и путь; не установлен — ErrEngineMissing.
func (e *Env) Installed(engine string) (version, bin string, err error) {
	s, err := e.readState()
	if err != nil {
		return "", "", err
	}
	v := s[engine]
	if v == "" {
		return "", "", fmt.Errorf("%w: %s не установлен (vpn.probe.ensure)", ErrEngineMissing, engine)
	}
	// Версия, которой больше нет в таблице этой сборки агента, не запускается: её сумма не подтверждена.
	if _, ok := tools.Known[engine][v][currentArch()]; !ok {
		return "", "", fmt.Errorf("%w: %s %s больше не в таблице агента", ErrEngineMissing, engine, v)
	}
	return v, e.binPath(engine, v), nil
}

// EnsurePlan — что поставит vpn.probe.ensure (предпросмотр): путь, прежняя версия.
func (e *Env) EnsurePlan(p *agentv1.VpnProbeEnsureParams) (*agentv1.VpnProbeEnsureResult, error) {
	if err := tools.Check(p.GetEngine(), p.GetVersion(), p.GetSha256()); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEngineUnknown, err)
	}
	s, err := e.readState()
	if err != nil {
		return nil, err
	}
	return &agentv1.VpnProbeEnsureResult{Engine: p.GetEngine(), Version: p.GetVersion(), Sha256: p.GetSha256(),
		PreviousVersion: s[p.GetEngine()]}, nil
}

// Ensure — поставить движок из архива, который скачал агент: sha256 архива = параметрам = таблице, в архиве ровно
// один файл движка в корне, не больше MaxBinary; бинарник root 0755 в своём каталоге версии; пробный запуск в
// песочнице вернул ту же версию; затем engines.json указывает на неё. Прежняя версия остаётся на диске для отката.
func (e *Env) Ensure(ctx context.Context, stageDir string, p *agentv1.VpnProbeEnsureParams) (*agentv1.VpnProbeEnsureResult, error) {
	res, err := e.EnsurePlan(p)
	if err != nil {
		return nil, err
	}
	raw, err := update.ReadStaged(stageDir, Staged, MaxArchive)
	if err != nil {
		return nil, fmt.Errorf("агент не скачал движок: %w", err)
	}
	sum := sha256.Sum256(raw)
	if got := hex.EncodeToString(sum[:]); got != p.GetSha256() {
		return nil, fmt.Errorf("%w: архив %s, ждали %s", ErrSHA256, got, p.GetSha256())
	}
	res.SizeBytes = uint64(len(raw))
	if e.EnsureUser != nil {
		if err := e.EnsureUser(ctx); err != nil {
			return nil, fmt.Errorf("%w: пользователь движка: %v", ErrSandboxUnavailable, err)
		}
	}
	bin, err := extract(raw, p.GetEngine())
	if err != nil {
		return nil, err
	}
	dst := e.binPath(p.GetEngine(), p.GetVersion())
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return nil, err
	}
	if err := fsutil.WriteFileAtomic(dst, bin, 0o755, fsutil.Keep); err != nil {
		return nil, err
	}
	v, err := e.Version(ctx, dst)
	if err != nil {
		return nil, fmt.Errorf("%w: пробный запуск: %v", ErrEngineFailed, err)
	}
	if v != p.GetVersion() {
		return nil, fmt.Errorf("%w: движок сообщает версию %s, ждали %s", ErrEngineFailed, v, p.GetVersion())
	}
	res.Version = v
	s, err := e.readState()
	if err != nil {
		return nil, err
	}
	s[p.GetEngine()] = v
	b, _ := json.Marshal(s)
	if err := fsutil.WriteFileAtomic(e.StatePath(), b, 0o644, fsutil.Keep); err != nil {
		return nil, err
	}
	return res, nil
}

// Prune — удалить каталоги версий кроме действующей и прежней (после успешной установки).
func (e *Env) Prune(engine string, keep ...string) error {
	entries, err := os.ReadDir(e.Dir)
	if err != nil {
		return err
	}
	k := map[string]bool{}
	for _, v := range keep {
		if v != "" {
			k[engine+"-"+v] = true
		}
	}
	var drop []string
	for _, d := range entries {
		n := d.Name()
		if d.IsDir() && len(n) > len(engine)+1 && n[:len(engine)+1] == engine+"-" && !k[n] {
			drop = append(drop, n)
		}
	}
	sort.Strings(drop)
	for _, n := range drop {
		if err := os.RemoveAll(filepath.Join(e.Dir, n)); err != nil {
			return err
		}
	}
	return nil
}

// extract — единственный обычный файл <engine> в корне архива.
func extract(raw []byte, engine string) ([]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return nil, fmt.Errorf("архив движка: %w", err)
	}
	var entry *zip.File
	for _, f := range zr.File {
		if f.Name == engine {
			if entry != nil || !f.FileInfo().Mode().IsRegular() {
				return nil, fmt.Errorf("архив движка: файл %s не один или не обычный", engine)
			}
			entry = f
		}
	}
	if entry == nil {
		return nil, fmt.Errorf("архив движка: нет файла %s", engine)
	}
	if entry.UncompressedSize64 > MaxBinary {
		return nil, fmt.Errorf("архив движка: %s больше %d байт", engine, MaxBinary)
	}
	rc, err := entry.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	bin, err := io.ReadAll(io.LimitReader(rc, MaxBinary+1))
	if err != nil {
		return nil, fmt.Errorf("архив движка: %w", err)
	}
	if len(bin) > MaxBinary {
		return nil, fmt.Errorf("архив движка: %s больше %d байт", engine, MaxBinary)
	}
	return bin, nil
}

// Version — версия движка из `xray version`, запуск в той же песочнице, что замер (без сети).
func (e *Env) Version(ctx context.Context, bin string) (string, error) {
	out, err := e.Sandbox.Run(ctx, Unit{Name: "trassa-vpnprobe-version-" + randHex(4), Exec: []string{bin, "version"},
		AllowIPs: nil, Timeout: 20})
	if err != nil {
		return "", err
	}
	m := xrayVersionRe.FindSubmatch(out)
	if m == nil {
		return "", fmt.Errorf("вывод version: %q", firstLine(out))
	}
	return string(m[1]), nil
}

func firstLine(b []byte) string {
	if i := bytes.IndexByte(b, '\n'); i >= 0 {
		b = b[:i]
	}
	if len(b) > 200 {
		b = b[:200]
	}
	return string(b)
}
