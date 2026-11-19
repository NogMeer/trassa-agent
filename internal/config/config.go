// SPDX-License-Identifier: AGPL-3.0-only

// Package config — версия сборки, пути на сервере и запись о регистрации агента.
//
// Привязка к панели задаётся при установке (раздел 11 E05, уроки Nezha): адрес шлюза, server_id и ключи панели
// лежат в /etc/trassa/enrollment.json (root:trassa, 0640). Агент читает его, но изменить не может; удалённо
// сменить адрес панели или её ключи нельзя.
package config

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"regexp"

	"github.com/NogMeer/trassa-agent/internal/fsutil"
	"github.com/NogMeer/trassa-agent/internal/verify"
)

// Version задаётся при сборке: -ldflags "-X github.com/NogMeer/trassa-agent/internal/config.Version=1.2.3".
var Version = "0.0.0-dev"

// ProtocolVersion — версия протокола канала (agent.proto, PROTOCOL_VERSION_1).
const ProtocolVersion = 1

// UserName — непривилегированный пользователь агента.
const UserName = "trassa"

// Paths — все пути агента и помощника. В проде — Default(), в тестах — Under(t.TempDir()).
type Paths struct {
	StateDir        string // /var/lib/trassa
	AgentDir        string // /var/lib/trassa/agent: единственный каталог, куда пишет агент (ReadWritePaths)
	AgentKey        string // /var/lib/trassa/agent/agent.key
	UpdateDir       string // /var/lib/trassa/agent/update/<operation_id>: выпуск, скачанный агентом
	HelperDir       string // /var/lib/trassa/helper (root, 0700)
	Nonces          string // /var/lib/trassa/helper/nonces
	OpsDir          string // /var/lib/trassa/helper/ops: состояние и итоги операций
	AutoRollbackDir string // /var/lib/trassa/helper/autorollback: сроки автооткатов
	HelperLock      string // /var/lib/trassa/helper/lock
	RollbackDir     string // /var/lib/trassa/rollback/<operation_id>/
	BinPrevDir      string // /var/lib/trassa/bin.prev
	EtcDir          string // /etc/trassa
	Enrollment      string // /etc/trassa/enrollment.json
	RunDir          string // /run/trassa
	Socket          string // /run/trassa/helper.sock
	BinDir          string // /usr/local/bin
	UnitDir         string // /etc/systemd/system
}

// Default — пути на сервере.
func Default() Paths { return Under("/") }

// Under — те же пути внутри root (для тестов и для проверки установки в каталоге).
func Under(root string) Paths {
	j := func(p ...string) string { return filepath.Join(append([]string{root}, p...)...) }
	return Paths{
		StateDir:        j("var/lib/trassa"),
		AgentDir:        j("var/lib/trassa/agent"),
		AgentKey:        j("var/lib/trassa/agent/agent.key"),
		UpdateDir:       j("var/lib/trassa/agent/update"),
		HelperDir:       j("var/lib/trassa/helper"),
		Nonces:          j("var/lib/trassa/helper/nonces"),
		OpsDir:          j("var/lib/trassa/helper/ops"),
		AutoRollbackDir: j("var/lib/trassa/helper/autorollback"),
		HelperLock:      j("var/lib/trassa/helper/lock"),
		RollbackDir:     j("var/lib/trassa/rollback"),
		BinPrevDir:      j("var/lib/trassa/bin.prev"),
		EtcDir:          j("etc/trassa"),
		Enrollment:      j("etc/trassa/enrollment.json"),
		RunDir:          j("run/trassa"),
		Socket:          j("run/trassa/helper.sock"),
		BinDir:          j("usr/local/bin"),
		UnitDir:         j("etc/systemd/system"),
	}
}

// PanelKey — открытый ключ подписи операций панели: kid и 32 байта Ed25519 в base64 (обычном или base64url).
type PanelKey struct {
	KeyID     string `json:"keyId"`
	PublicKey string `json:"publicKey"`
}

// Enrollment — итог регистрации (ответ POST /agent/v1/enroll).
type Enrollment struct {
	ServerID        string     `json:"serverId"`
	GatewayURL      string     `json:"gatewayUrl"`
	ProtocolVersion int        `json:"protocolVersion"`
	PanelKeys       []PanelKey `json:"panelKeys"`
}

var uuidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// IsUUID — строка вида 8-4-4-4-12 из шестнадцатеричных цифр.
func IsUUID(s string) bool { return uuidRe.MatchString(s) }

// ErrEnrollmentInvalid — запись о регистрации повреждена или неполна. Без неё агент и помощник не стартуют.
var ErrEnrollmentInvalid = errors.New("enrollment invalid")

// Validate проверяет запись и возвращает ключи для проверки подписи. Ключей один или два (ротация, E26);
// ноль — отказ (R1).
func (e Enrollment) Validate() ([]verify.PanelKey, error) {
	bad := func(format string, a ...any) error {
		return fmt.Errorf("%w: %s", ErrEnrollmentInvalid, fmt.Sprintf(format, a...))
	}
	if !IsUUID(e.ServerID) {
		return nil, bad("serverId")
	}
	u, err := url.Parse(e.GatewayURL)
	if err != nil || u.Scheme != "wss" || u.Host == "" || u.User != nil {
		return nil, bad("gatewayUrl: нужен wss://")
	}
	if e.ProtocolVersion != ProtocolVersion {
		return nil, bad("protocolVersion %d не поддерживается", e.ProtocolVersion)
	}
	if len(e.PanelKeys) < 1 || len(e.PanelKeys) > 2 {
		return nil, bad("panelKeys: нужно 1 или 2 ключа")
	}
	keys := make([]verify.PanelKey, 0, len(e.PanelKeys))
	seen := map[string]bool{}
	for _, k := range e.PanelKeys {
		if k.KeyID == "" || seen[k.KeyID] {
			return nil, bad("panelKeys: пустой или повторный keyId")
		}
		seen[k.KeyID] = true
		raw, err := DecodeKey(k.PublicKey)
		if err != nil || len(raw) != 32 {
			return nil, bad("panelKeys: ключ %q не 32 байта base64", k.KeyID)
		}
		keys = append(keys, verify.PanelKey{ID: k.KeyID, PublicKey: raw})
	}
	return keys, nil
}

// DecodeKey раскодирует ключ в base64: обычном или base64url, с дополнением или без. Шлюз отдаёт обычный
// base64, kid-ключи JWK — base64url; длину проверяет вызывающий.
func DecodeKey(s string) ([]byte, error) {
	var last error
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		b, err := enc.Strict().DecodeString(s)
		if err == nil {
			return b, nil
		}
		last = err
	}
	return nil, last
}

// DecodeStrict разбирает JSON без неизвестных полей и без хвоста.
func DecodeStrict(raw []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("лишние данные после JSON")
	}
	return nil
}

// LoadEnrollment читает и проверяет запись о регистрации.
func LoadEnrollment(path string) (Enrollment, []verify.PanelKey, error) {
	raw, err := fsutil.ReadLimited(path, 64<<10)
	if err != nil {
		return Enrollment{}, nil, err
	}
	var e Enrollment
	if err := DecodeStrict(raw, &e); err != nil {
		return Enrollment{}, nil, fmt.Errorf("%w: %v", ErrEnrollmentInvalid, err)
	}
	keys, err := e.Validate()
	if err != nil {
		return Enrollment{}, nil, err
	}
	return e, keys, nil
}

// SaveEnrollment записывает проверенную запись: владелец root, группа trassa, 0640.
func SaveEnrollment(path string, e Enrollment, owner fsutil.Owner) error {
	if _, err := e.Validate(); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(path, append(raw, '\n'), 0o640, owner)
}
