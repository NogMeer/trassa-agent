// SPDX-License-Identifier: AGPL-3.0-only

package deploy

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	secretkey "github.com/NogMeer/trassa-agent/internal/sealed"
)

// Поля секретов в info HPKE (как в E13; на месте plan_id — app_id).
const (
	FieldRegistry = "registry_password"
	FieldGit      = "git_credential"
	FieldEnv      = "env:"
	FieldBuildEnv = "build_env:"
)

// Opener — расшифровка секретов операции ключом помощника.
type Opener struct {
	Key  *secretkey.Key
	Body *agentv1.OperationBody
	App  string
}

// Open — секрет поля field; переложенный из другой операции, приложения или поля не откроется.
func (o *Opener) Open(s *agentv1.SealedSecret, field string) (string, error) {
	if o == nil || o.Key == nil {
		return "", errors.New("нет ключа секретов помощника")
	}
	info := secretkey.Info(o.Body.GetServerId(), s.GetKid(), o.Body.GetOperationId(), o.Body.GetType(), o.App, field)
	pt, err := o.Key.Open(s, info)
	if err != nil {
		return "", fmt.Errorf("%s: %w", field, err)
	}
	if strings.ContainsRune(string(pt), 0) {
		return "", fmt.Errorf("%s: NUL в значении", field)
	}
	return string(pt), nil
}

// Env — окружение контейнера: открытые и секретные переменные «KEY=value», по имени.
func (o *Opener) Env(secret map[string]*agentv1.SealedSecret, plain map[string]string, prefix string) ([]string, []string, error) {
	var out, secrets []string
	for k, v := range plain {
		out = append(out, k+"="+v)
	}
	for k, s := range secret {
		v, err := o.Open(s, prefix+k)
		if err != nil {
			return nil, nil, err
		}
		out = append(out, k+"="+v)
		secrets = append(secrets, v)
	}
	sort.Strings(out)
	return out, secrets, nil
}

// RegistryAuth — заголовок X-Registry-Auth (base64url JSON) и пароль для вырезки из вывода.
func (o *Opener) RegistryAuth(r *agentv1.RegistryAuth) (string, string, error) {
	if r == nil {
		return "", "", nil
	}
	pw, err := o.Open(r.GetPassword(), FieldRegistry)
	if err != nil {
		return "", "", err
	}
	raw, _ := json.Marshal(map[string]string{"username": r.GetUsername(), "password": pw, "serveraddress": r.GetServer()})
	return base64.URLEncoding.EncodeToString(raw), pw, nil
}
