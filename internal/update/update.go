// SPDX-License-Identifier: AGPL-3.0-only

// Package update — самообновление агента (E05-T22, R12, decisions п. 10).
//
// Выпуск подписан офлайн ключом minisign владельца: подписан файл SHA256SUMS, доверенный комментарий —
// «trassa-agent <версия>». Проверка обязательна: пустой список ключей, пустая подпись, подпись без
// предварительного хэша (алгоритм Ed) или чужой key_id — ошибка UPDATE_SIGNATURE_INVALID. Версия ниже текущей
// не ставится. Замена: копия текущих бинарников в bin.prev, новый файл во временный в том же каталоге, fsync,
// один rename(2), fsync каталога. Возврат — bin.prev обратно тем же способом.
package update

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"aead.dev/minisign"

	"github.com/NogMeer/trassa-agent/internal/fsutil"
)

// Коды ошибок итога операции.
const (
	CodeSignatureInvalid = "UPDATE_SIGNATURE_INVALID"
	CodeDowngrade        = "UPDATE_DOWNGRADE"
	CodeRolledBack       = "UPDATE_ROLLED_BACK"
	CodeArtifactMissing  = "UPDATE_ARTIFACT_MISSING"
	CodeDownloadFailed   = "UPDATE_DOWNLOAD_FAILED"
)

// ErrSignatureInvalid — подпись выпуска не прошла.
var ErrSignatureInvalid = errors.New(CodeSignatureInvalid)

// Verifier проверяет подпись SHA256SUMS. Ключей один или два (ротация).
type Verifier struct{ keys []minisign.PublicKey }

// NewVerifier разбирает открытые ключи minisign («RW…»). Пустой список — ошибка: без ключа ничего не ставится.
func NewVerifier(keys []string) (*Verifier, error) {
	if len(keys) == 0 {
		return nil, fmt.Errorf("%w: нет ключей выпуска", ErrSignatureInvalid)
	}
	v := &Verifier{}
	for _, k := range keys {
		var pk minisign.PublicKey
		if err := pk.UnmarshalText([]byte(strings.TrimSpace(k))); err != nil {
			return nil, fmt.Errorf("ключ выпуска: %w", err)
		}
		v.keys = append(v.keys, pk)
	}
	return v, nil
}

// VerifySums проверяет подпись sig файла sums и доверенный комментарий «trassa-agent <version>».
func (v *Verifier) VerifySums(sums, sig []byte, version string) error {
	if v == nil || len(v.keys) == 0 || len(sig) == 0 || len(sums) == 0 {
		return ErrSignatureInvalid
	}
	var s minisign.Signature
	if err := s.UnmarshalText(sig); err != nil {
		return fmt.Errorf("%w: %v", ErrSignatureInvalid, err)
	}
	// minisign.Verify принимает и вариант без хэша; разрешён только с BLAKE2b (ED), как подписывает minisign -S.
	if s.Algorithm != minisign.HashEdDSA {
		return fmt.Errorf("%w: алгоритм без предварительного хэша", ErrSignatureInvalid)
	}
	if s.TrustedComment != "trassa-agent "+version {
		return fmt.Errorf("%w: доверенный комментарий %q", ErrSignatureInvalid, s.TrustedComment)
	}
	for _, k := range v.keys {
		if k.ID() == s.KeyID && minisign.Verify(k, sums, sig) {
			return nil
		}
	}
	return ErrSignatureInvalid
}

var sumLine = regexp.MustCompile(`^([0-9a-f]{64}) [ *]([A-Za-z0-9._-]+)$`)

// ParseSums разбирает SHA256SUMS (формат sha256sum). Повтор имени или кривая строка — ошибка.
func ParseSums(raw []byte) (map[string]string, error) {
	out := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(raw))
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if line == "" {
			continue
		}
		m := sumLine.FindStringSubmatch(line)
		if m == nil {
			return nil, fmt.Errorf("SHA256SUMS: строка %q", line)
		}
		if _, dup := out[m[2]]; dup {
			return nil, fmt.Errorf("SHA256SUMS: %s дважды", m[2])
		}
		out[m[2]] = m[1]
	}
	if len(out) == 0 {
		return nil, errors.New("SHA256SUMS пуст")
	}
	return out, sc.Err()
}

// Compare сравнивает версии semver без метаданных сборки: -1, 0, 1. Предвыпуск младше выпуска.
func Compare(a, b string) (int, error) {
	pa, prea, err := parseSemver(a)
	if err != nil {
		return 0, err
	}
	pb, preb, err := parseSemver(b)
	if err != nil {
		return 0, err
	}
	for i := 0; i < 3; i++ {
		if pa[i] != pb[i] {
			if pa[i] < pb[i] {
				return -1, nil
			}
			return 1, nil
		}
	}
	switch {
	case prea == preb:
		return 0, nil
	case prea == "":
		return 1, nil
	case preb == "":
		return -1, nil
	case prea < preb:
		return -1, nil
	default:
		return 1, nil
	}
}

func parseSemver(s string) ([3]uint64, string, error) {
	var out [3]uint64
	core, pre, _ := strings.Cut(strings.TrimPrefix(s, "v"), "-")
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return out, "", fmt.Errorf("версия %q", s)
	}
	for i, p := range parts {
		n, err := strconv.ParseUint(p, 10, 64)
		if err != nil {
			return out, "", fmt.Errorf("версия %q", s)
		}
		out[i] = n
	}
	return out, pre, nil
}

// Fetch скачивает https-адрес не больше max байт.
func Fetch(ctx context.Context, c *http.Client, rawURL string, max int64) ([]byte, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" {
		return nil, fmt.Errorf("адрес %q: нужен https", rawURL)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d", u.Path, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("%s: больше %d байт", u.Path, max)
	}
	return b, nil
}

// SHA256Hex — шестнадцатеричный sha256.
func SHA256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// Install кладёт новые бинарники (имя → содержимое) в binDir, сохранив текущие в prevDir.
func Install(binDir, prevDir string, files map[string][]byte) error {
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	if err := SavePrev(binDir, prevDir, names); err != nil {
		return err
	}
	return InstallNew(binDir, files)
}

// SavePrev — копии текущих бинарников в prevDir. Делается до того, как заводится сторож обновления: сторож
// запускает помощника из prevDir, и systemd-run проверяет, что файл есть, уже при создании таймера.
func SavePrev(binDir, prevDir string, names []string) error {
	if err := os.MkdirAll(prevDir, 0o700); err != nil {
		return err
	}
	for _, name := range names {
		cur, err := os.ReadFile(filepath.Join(binDir, name))
		if err != nil {
			return fmt.Errorf("текущий %s: %w", name, err)
		}
		if err := fsutil.WriteFileAtomic(filepath.Join(prevDir, name), cur, 0o755, fsutil.Keep); err != nil {
			return err
		}
	}
	return nil
}

// InstallNew — новые бинарники на место (каждый атомарно).
func InstallNew(binDir string, files map[string][]byte) error {
	for name, b := range files {
		if err := fsutil.WriteFileAtomic(filepath.Join(binDir, name), b, 0o755, fsutil.Keep); err != nil {
			return err
		}
	}
	return nil
}

// RestorePrev возвращает бинарники из prevDir.
func RestorePrev(binDir, prevDir string, names []string) error {
	var errs []error
	for _, name := range names {
		b, err := os.ReadFile(filepath.Join(prevDir, name))
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if err := fsutil.WriteFileAtomic(filepath.Join(binDir, name), b, 0o755, fsutil.Keep); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
