// SPDX-License-Identifier: AGPL-3.0-only

package backup

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/config"
	"github.com/NogMeer/trassa-agent/internal/fsutil"
	secretkey "github.com/NogMeer/trassa-agent/internal/sealed"
)

// Поля секретов в info HPKE (decisions E13): пароль, переменные окружения; у ключей обслуживания backup.prune —
// с префиксом maintenance:.
const (
	FieldPassword    = "password"
	FieldEnvPrefix   = "env:"
	FieldMaintPrefix = "maintenance:"
)

// ErrNoPlan — настроек плана на сервере нет (backup.init не выполнялся или был backup.unconfigure).
var ErrNoPlan = errors.New("BACKUP_NOT_CONFIGURED")

// Repo — открытый репозиторий: адрес и секреты. Живёт только в памяти помощника и в каталоге плана (root, 0600).
type Repo struct {
	URL      string
	Password []byte
	Env      map[string]string
	// ResticVersion — установленная backup.init версия restic (бинарник ResticPath).
	ResticVersion string
}

// OpenRepo расшифровывает секреты репозитория из тела операции. Секрет привязан к серверу, операции, типу, плану
// и полю: переложенный из другой операции или поля не откроется.
func OpenRepo(k *secretkey.Key, b *agentv1.OperationBody, planID string, r *agentv1.BackupRepo, prefix string) (*Repo, error) {
	if k == nil {
		return nil, errors.New("нет ключа секретов помощника")
	}
	open := func(s *agentv1.SealedSecret, field string) ([]byte, error) {
		info := secretkey.Info(b.GetServerId(), s.GetKid(), b.GetOperationId(), b.GetType(), planID, prefix+field)
		pt, err := k.Open(s, info)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", prefix+field, err)
		}
		return pt, nil
	}
	pw, err := open(r.GetPassword(), FieldPassword)
	if err != nil {
		return nil, err
	}
	if len(pw) == 0 {
		return nil, errors.New("пустой пароль репозитория")
	}
	out := &Repo{URL: r.GetUrl(), Password: pw, Env: map[string]string{}}
	for name, s := range r.GetEnv() {
		v, err := open(s, FieldEnvPrefix+name)
		if err != nil {
			return nil, err
		}
		if strings.ContainsAny(string(v), "\x00\n") {
			return nil, fmt.Errorf("env %s: недопустимые символы", name)
		}
		out.Env[name] = string(v)
	}
	return out, nil
}

// Store — каталоги планов: /etc/trassa/backup/<plan_id>/ (root, 0700; файлы 0600).
type Store struct{ Dir string }

// Файлы каталога плана.
const (
	planFile     = "plan.json"
	passwordFile = "password"
	envFile      = "env.json"
	// SSHKeyFile — закрытый ключ для цели SERVER (не покидает сервер), SSHKeyFile + ".pub" — открытый.
	SSHKeyFile     = "id_ed25519"
	knownHostsFile = "known_hosts"
)

type planJSON struct {
	URL    string `json:"url"`
	Restic string `json:"restic"`
}

// PlanDir — каталог плана; id проверен как UUID.
func (s *Store) PlanDir(planID string) (string, error) {
	if !config.IsUUID(planID) {
		return "", errors.New("plan_id")
	}
	return filepath.Join(s.Dir, strings.ToLower(planID)), nil
}

// Paths — файлы плана (для точки отката backup.init).
func (s *Store) Paths(planID string) ([]string, error) {
	d, err := s.PlanDir(planID)
	if err != nil {
		return nil, err
	}
	return []string{filepath.Join(d, planFile), filepath.Join(d, passwordFile), filepath.Join(d, envFile)}, nil
}

// Save записывает адрес и секреты плана (каждый файл атомарно, 0600).
func (s *Store) Save(planID string, r *Repo) error {
	d, err := s.PlanDir(planID)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(d, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(d, 0o700); err != nil {
		return err
	}
	if !versionRe.MatchString(r.ResticVersion) {
		return errors.New("версия restic")
	}
	pj, _ := json.Marshal(planJSON{URL: r.URL, Restic: r.ResticVersion})
	env, _ := json.Marshal(r.Env)
	for name, data := range map[string][]byte{planFile: pj, passwordFile: r.Password, envFile: env} {
		if err := fsutil.WriteFileAtomic(filepath.Join(d, name), data, 0o600, fsutil.Keep); err != nil {
			return err
		}
	}
	return nil
}

// Load читает настройки плана. Нет каталога — ErrNoPlan.
func (s *Store) Load(planID string) (*Repo, error) {
	d, err := s.PlanDir(planID)
	if err != nil {
		return nil, err
	}
	read := func(name string) ([]byte, error) { return fsutil.ReadLimited(filepath.Join(d, name), 64<<10) }
	pj, err := read(planFile)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNoPlan
	}
	if err != nil {
		return nil, err
	}
	var p planJSON
	if err := json.Unmarshal(pj, &p); err != nil || RepoURL(p.URL) != nil || !versionRe.MatchString(p.Restic) {
		return nil, fmt.Errorf("настройки плана повреждены")
	}
	pw, err := read(passwordFile)
	if err != nil {
		return nil, err
	}
	r := &Repo{URL: p.URL, Password: pw, Env: map[string]string{}, ResticVersion: p.Restic}
	raw, err := read(envFile)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, &r.Env); err != nil {
		return nil, fmt.Errorf("настройки плана повреждены")
	}
	for k := range r.Env {
		if !knownEnv(k) {
			return nil, fmt.Errorf("настройки плана: переменная %q", k)
		}
	}
	return r, nil
}

// Remove удаляет каталог плана целиком; нет каталога — не ошибка.
func (s *Store) Remove(planID string) error {
	d, err := s.PlanDir(planID)
	if err != nil {
		return err
	}
	if err := os.RemoveAll(d); err != nil {
		return err
	}
	if _, err := os.Stat(s.Dir); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return fsutil.SyncDir(s.Dir)
}

// Secrets — значения секретов плана: фильтр вывода restic и утилит их вырезает.
func (r *Repo) Secrets() []string {
	out := []string{string(r.Password)}
	names := make([]string, 0, len(r.Env))
	for n := range r.Env {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if n != "AWS_DEFAULT_REGION" {
			out = append(out, r.Env[n])
		}
	}
	return out
}
