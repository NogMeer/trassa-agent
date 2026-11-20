// SPDX-License-Identifier: AGPL-3.0-only

package backup

import (
	"archive/zip"
	"bytes"
	"compress/bzip2"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"time"

	"github.com/NogMeer/trassa-agent/internal/fsutil"
	"github.com/NogMeer/trassa-agent/internal/update"
)

// Пределы загрузки restic: архив .bz2 выпуска (0.20.0 — около 12 МБ) и распакованный бинарник.
const (
	MaxResticArchive = 64 << 20
	MaxResticBinary  = 192 << 20
	// ResticStaged — имя файла, который агент кладёт в каталог операции.
	ResticStaged = "restic.bz2"
)

// ErrResticChecksum — сумма скачанного архива не совпала с подписанной (BACKUP_RESTIC_CHECKSUM).
var ErrResticChecksum = errors.New("BACKUP_RESTIC_CHECKSUM")

var versionLine = regexp.MustCompile(`^restic (\d+\.\d+\.\d+) `)

// ResticPath — путь установленного бинарника версии.
func ResticPath(binDir, version string) string { return filepath.Join(binDir, "restic-"+version) }

// InstallRestic ставит restic из архива, который скачал агент (помощник в сеть не выходит): sha256 архива равна
// подписанной в теле операции, распаковка не больше MaxResticBinary, бинарник root 0755, его версия совпадает.
// Та же версия уже стоит и запускается — архив всё равно сверяется, но бинарник не переписывается.
func InstallRestic(ctx context.Context, stageDir, wantSHA, version, binDir string) (string, error) {
	raw, err := update.ReadStaged(stageDir, ResticStaged, MaxResticArchive)
	if err != nil {
		return "", fmt.Errorf("агент не скачал restic: %w", err)
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != wantSHA {
		return "", fmt.Errorf("%w: архив restic %s, ждали %s", ErrResticChecksum, hex.EncodeToString(sum[:]), wantSHA)
	}
	dst := ResticPath(binDir, version)
	if v, err := ResticVersion(ctx, dst); err == nil && v == version {
		return dst, nil
	}
	bin, err := io.ReadAll(io.LimitReader(bzip2.NewReader(bytes.NewReader(raw)), MaxResticBinary+1))
	if err != nil {
		return "", fmt.Errorf("архив restic: %w", err)
	}
	if len(bin) > MaxResticBinary {
		return "", fmt.Errorf("архив restic: бинарник больше %d байт", MaxResticBinary)
	}
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		return "", err
	}
	if err := fsutil.WriteFileAtomic(dst, bin, 0o755, fsutil.Keep); err != nil {
		return "", err
	}
	v, err := ResticVersion(ctx, dst)
	if err != nil {
		_ = os.Remove(dst)
		return "", fmt.Errorf("restic не запускается: %w", err)
	}
	if v != version {
		_ = os.Remove(dst)
		return "", fmt.Errorf("restic сообщает версию %s, ждали %s", v, version)
	}
	return dst, nil
}

// ResticVersion — версия из `restic version`.
func ResticVersion(ctx context.Context, bin string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "version")
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C"}
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	m := versionLine.FindSubmatch(out)
	if m == nil {
		return "", fmt.Errorf("вывод restic version: %q", firstLine(out))
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

// Архив rclone выпуска — zip (rclone-v<версия>-linux-<arch>.zip) с бинарником в подкаталоге.
const (
	MaxRcloneArchive = 96 << 20
	MaxRcloneBinary  = 256 << 20
	RcloneStaged     = "rclone.zip"
)

var rcloneVersionLine = regexp.MustCompile(`^rclone v(\d+\.\d+\.\d+)\s`)

// RclonePath — путь установленного rclone версии.
func RclonePath(binDir, version string) string { return filepath.Join(binDir, "rclone-"+version) }

// InstallRclone ставит rclone из zip, который скачал агент: sha256 архива равна подписанной, в архиве ровно один
// файл …/rclone не больше MaxRcloneBinary, бинарник root 0755 (его запускает пользователь цели), версия совпадает.
func InstallRclone(ctx context.Context, stageDir, wantSHA, version, binDir string) (string, error) {
	raw, err := update.ReadStaged(stageDir, RcloneStaged, MaxRcloneArchive)
	if err != nil {
		return "", fmt.Errorf("агент не скачал rclone: %w", err)
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != wantSHA {
		return "", fmt.Errorf("%w: архив rclone %s, ждали %s", ErrResticChecksum, hex.EncodeToString(sum[:]), wantSHA)
	}
	dst := RclonePath(binDir, version)
	if v, err := RcloneVersion(ctx, dst); err == nil && v == version {
		return dst, nil
	}
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return "", fmt.Errorf("архив rclone: %w", err)
	}
	var entry *zip.File
	for _, f := range zr.File {
		if path.Base(f.Name) == "rclone" && f.FileInfo().Mode().IsRegular() {
			if entry != nil {
				return "", errors.New("архив rclone: два файла rclone")
			}
			entry = f
		}
	}
	if entry == nil {
		return "", errors.New("архив rclone: нет файла rclone")
	}
	rc, err := entry.Open()
	if err != nil {
		return "", err
	}
	bin, err := io.ReadAll(io.LimitReader(rc, MaxRcloneBinary+1))
	rc.Close()
	if err != nil {
		return "", fmt.Errorf("архив rclone: %w", err)
	}
	if len(bin) > MaxRcloneBinary {
		return "", fmt.Errorf("архив rclone: бинарник больше %d байт", MaxRcloneBinary)
	}
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		return "", err
	}
	if err := fsutil.WriteFileAtomic(dst, bin, 0o755, fsutil.Keep); err != nil {
		return "", err
	}
	v, err := RcloneVersion(ctx, dst)
	if err != nil || v != version {
		_ = os.Remove(dst)
		return "", fmt.Errorf("rclone сообщает версию %q (%v), ждали %s", v, err, version)
	}
	return dst, nil
}

// RcloneVersion — версия из `rclone version`.
func RcloneVersion(ctx context.Context, bin string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "version")
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "HOME=/nonexistent"}
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	m := rcloneVersionLine.FindSubmatch(out)
	if m == nil {
		return "", fmt.Errorf("вывод rclone version: %q", firstLine(out))
	}
	return string(m[1]), nil
}
