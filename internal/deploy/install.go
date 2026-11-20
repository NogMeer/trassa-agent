// SPDX-License-Identifier: AGPL-3.0-only

package deploy

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/fsutil"
	"github.com/NogMeer/trassa-agent/internal/tools"
	"github.com/NogMeer/trassa-agent/internal/update"
)

// Пределы скачанного агентом: архив или бинарник выпуска и распакованный бинарник.
const (
	MaxToolDownload = 160 << 20
	MaxToolBinary   = 256 << 20
)

// ErrChecksum — сумма скачанного не совпала с подписанной (DEPLOY_TOOL_CHECKSUM).
var ErrChecksum = errors.New("DEPLOY_TOOL_CHECKSUM")

// StagedName — имя файла, который агент кладёт в каталог операции для программы.
func StagedName(t *agentv1.DeployTool) string { return t.GetName() + ".download" }

// readTool — скачанное агентом (без ссылок, обычный файл), sha256 — из таблицы помощника и равна подписанной.
func readTool(stage string, t *agentv1.DeployTool) ([]byte, error) {
	if err := tools.Check(t.GetName(), t.GetVersion(), t.GetSha256()); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrToolUnknown, err)
	}
	raw, err := update.ReadStaged(stage, StagedName(t), MaxToolDownload)
	if err != nil {
		return nil, fmt.Errorf("агент не скачал %s: %w", t.GetName(), err)
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != t.GetSha256() {
		return nil, fmt.Errorf("%w: %s %s", ErrChecksum, t.GetName(), hex.EncodeToString(sum[:]))
	}
	return raw, nil
}

// installPlugin — плагин Docker CLI (docker-compose, docker-buildx: бинарник выпуска) в каталог плагинов.
func installPlugin(_ context.Context, stage string, t *agentv1.DeployTool, dir string) (string, error) {
	raw, err := readTool(stage, t)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		return "", err
	}
	dst := filepath.Join(dir, t.GetName())
	return dst, fsutil.WriteFileAtomic(dst, raw, 0o755, fsutil.Keep)
}

// untarOne — из .tar.gz только обычный файл name в корне архива (ссылки, каталоги и прочее не извлекаются).
func untarOne(raw []byte, name string) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("в архиве нет %s", name)
		}
		if err != nil {
			return nil, err
		}
		if path.Clean(h.Name) != name || h.Typeflag != tar.TypeReg {
			continue
		}
		b, err := io.ReadAll(io.LimitReader(tr, MaxToolBinary+1))
		if err != nil {
			return nil, err
		}
		if len(b) > MaxToolBinary {
			return nil, fmt.Errorf("%s больше %d байт", name, MaxToolBinary)
		}
		return b, nil
	}
}
