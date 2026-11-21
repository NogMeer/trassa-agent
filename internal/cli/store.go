// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"

	"github.com/zalando/go-keyring"
)

// cliTokenRe — формат токена входа CLI (apps/api cli-codes.ts, CLI_TOKEN_RE).
var cliTokenRe = regexp.MustCompile(`^trc_[A-Za-z0-9_-]{43}$`)

// Keyring — системное хранилище секретов (go-keyring): Keychain macOS, Secret Service Linux, диспетчер учётных
// данных Windows. В тестах — подмена.
type Keyring interface {
	Get(service, user string) (string, error)
	Set(service, user, password string) error
	Delete(service, user string) error
}

// SystemKeyring — go-keyring.
type SystemKeyring struct{}

func (SystemKeyring) Get(s, u string) (string, error) { return keyring.Get(s, u) }
func (SystemKeyring) Set(s, u, p string) error        { return keyring.Set(s, u, p) }
func (SystemKeyring) Delete(s, u string) error        { return keyring.Delete(s, u) }

// ErrKeyringNotFound — записи нет (у подмены тоже).
var ErrKeyringNotFound = keyring.ErrNotFound

const (
	keyringService  = "trassa-cli"
	credentialsFile = "credentials.json"
)

// noToken — токена для адреса нет; cause — почему хранилище не ответило (если не ответило).
type noToken struct{ cause error }

func (e *noToken) Error() string {
	if e.cause != nil {
		return "no token: " + e.cause.Error()
	}
	return "no token"
}

// tokenStore — токен по адресу панели: в системном хранилище, а без него — в credentials.json с правами 0600
// (план E16-T19). Файл с правами шире 0600 не читается (как ключи у ssh).
type tokenStore struct {
	kr  Keyring
	dir string
}

// set — сохранить. inFile — токен лёг в файл, keyringErr — почему не в системное хранилище.
func (s *tokenStore) set(origin, token string) (inFile bool, keyringErr error, err error) {
	if !cliTokenRe.MatchString(token) {
		return false, nil, errors.New("token format")
	}
	keyringErr = s.kr.Set(keyringService, origin, token)
	if keyringErr == nil {
		// Копия в файле от прежнего входа больше не нужна.
		return false, nil, s.fileDelete(origin)
	}
	m, err := s.readFile()
	if err != nil {
		return true, keyringErr, err
	}
	m[origin] = token
	return true, keyringErr, s.writeFile(m)
}

func (s *tokenStore) get(origin string) (string, error) {
	t, kerr := s.kr.Get(keyringService, origin)
	if kerr == nil && cliTokenRe.MatchString(t) {
		return t, nil
	}
	m, err := s.readFile()
	if err != nil {
		return "", err
	}
	if t := m[origin]; cliTokenRe.MatchString(t) {
		return t, nil
	}
	if kerr != nil && !errors.Is(kerr, ErrKeyringNotFound) {
		// Хранилище есть, но не ответило, и в файле токена нет: причина видна человеку.
		return "", &noToken{cause: kerr}
	}
	return "", &noToken{}
}

func (s *tokenStore) delete(origin string) error {
	inFile := false
	if m, err := s.readFile(); err == nil {
		_, inFile = m[origin]
	}
	kerr := s.kr.Delete(keyringService, origin)
	if err := s.fileDelete(origin); err != nil {
		return err
	}
	// Хранилище не ответило, а токен был не в файле — значит, он остался в хранилище: это ошибка.
	if kerr != nil && !errors.Is(kerr, ErrKeyringNotFound) && !inFile {
		return kerr
	}
	return nil
}

func (s *tokenStore) path() string { return filepath.Join(s.dir, credentialsFile) }

func (s *tokenStore) readFile() (map[string]string, error) {
	f, err := os.Open(s.path())
	if errors.Is(err, fs.ErrNotExist) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if runtime.GOOS != "windows" && st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s: права %o шире 0600, файл не читается (chmod 600)", s.path(), st.Mode().Perm())
	}
	var m map[string]string
	if err := json.NewDecoder(f).Decode(&m); err != nil {
		return nil, fmt.Errorf("%s: %w", s.path(), err)
	}
	if m == nil {
		m = map[string]string{}
	}
	return m, nil
}

func (s *tokenStore) writeFile(m map[string]string) error {
	if len(m) == 0 {
		err := os.Remove(s.path())
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return writePrivate(s.dir, credentialsFile, append(b, '\n'))
}

func (s *tokenStore) fileDelete(origin string) error {
	m, err := s.readFile()
	if err != nil {
		return err
	}
	if _, ok := m[origin]; !ok {
		return nil
	}
	delete(m, origin)
	return s.writeFile(m)
}
