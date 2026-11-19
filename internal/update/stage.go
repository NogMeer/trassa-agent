// SPDX-License-Identifier: AGPL-3.0-only

package update

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"

	"github.com/NogMeer/trassa-agent/internal/fsutil"
)

// Файлы выпуска.
const (
	SumsName      = "SHA256SUMS"
	SignatureName = "SHA256SUMS.minisig"
	MaxSignature  = 4 << 10
	MaxSums       = 64 << 10
	MaxBinary     = 128 << 20
)

// BinaryName — имя файла бинарника в выпуске.
func BinaryName(bin, arch string) string { return bin + "-linux-" + arch }

// Stage скачивает выпуск в dir: подпись, SHA256SUMS (рядом с подписью) и бинарники (имя файла → адрес). Скачивает
// агент — процесс без прав: помощник (root) в сеть не выходит. Содержимому агент не доверяет никто: помощник
// проверяет подпись и суммы сам.
func Stage(ctx context.Context, c *http.Client, signatureURL string, binaries map[string]string, dir string) error {
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	get := func(url, name string, max int64) error {
		b, err := Fetch(ctx, c, url, max)
		if err != nil {
			return err
		}
		return fsutil.WriteFileAtomic(filepath.Join(dir, name), b, 0o600, fsutil.Keep)
	}
	if err := get(signatureURL, SignatureName, MaxSignature); err != nil {
		return err
	}
	if len(signatureURL) <= len(".minisig") {
		return errors.New("адрес подписи")
	}
	if err := get(signatureURL[:len(signatureURL)-len(".minisig")], SumsName, MaxSums); err != nil {
		return err
	}
	for name, url := range binaries {
		if filepath.Base(name) != name {
			return fmt.Errorf("имя %q", name)
		}
		if err := get(url, name, MaxBinary); err != nil {
			return err
		}
	}
	return nil
}

// ReadStaged читает файл, подготовленный агентом: каталог и файл открываются без перехода по ссылкам, файл
// обязан быть обычным и не больше max. Содержимое читается один раз в память — проверка и установка идут по
// одним и тем же байтам.
func ReadStaged(dir, name string, max int64) ([]byte, error) {
	if filepath.Base(name) != name || name == "." || name == ".." {
		return nil, fmt.Errorf("имя %q", name)
	}
	dfd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", dir, err)
	}
	defer unix.Close(dfd)
	fd, err := unix.Openat(dfd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Size() > max {
		return nil, fmt.Errorf("%s: не обычный файл или больше %d байт", name, max)
	}
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("%s: больше %d байт", name, max)
	}
	return b, nil
}
