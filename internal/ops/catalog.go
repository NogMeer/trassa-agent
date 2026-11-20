// SPDX-License-Identifier: AGPL-3.0-only

// Package ops — зашитый в помощник список типов операций и проверки параметров (раздел 6 E05, R1, R7).
//
// Список собирается только из кода этой сборки: конфигурации, флага или поля, через которое его можно было бы
// расширить, нет. Тип test.config_write добавляется лишь сборкой с тегом testops (catalog_testops.go). Схемы
// параметров совпадают с apps/api/src/modules/operations/catalog.ts.
package ops

import (
	"errors"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/config"
)

// Коды отказа помощника (раздел 6, таблица проверок).
const (
	CodeSignatureInvalid = "SIGNATURE_INVALID"
	CodeServerMismatch   = "SERVER_MISMATCH"
	CodeExpired          = "EXPIRED"
	CodeNotAfterTooFar   = "NOT_AFTER_TOO_FAR"
	CodeReplay           = "REPLAY"
	CodeTypeUnknown      = "TYPE_UNKNOWN"
	CodeParamsInvalid    = "PARAMS_INVALID"
	CodePeerForbidden    = "PEER_FORBIDDEN"
)

// Class — класс риска. Помощнику он нужен для очереди: изменяющие операции идут строго по одной.
type Class int

const (
	Read Class = iota
	Change
	Destructive
)

// Mutating — операция может менять систему.
func (c Class) Mutating() bool { return c != Read }

// Типы операций E05.
const (
	TypeSystemInfo      = "system.info"
	TypeSystemInventory = "system.inventory"
	TypeAgentUpdate     = "agent.update"
	TypeAgentUninstall  = "agent.uninstall"
	TypeRollbackRestore = "rollback.restore"
)

// MaxConfirmWithin — предел автооткатa, как MAX_CONFIRM_WITHIN каталога панели.
const MaxConfirmWithin = 3600

// Spec — описание типа.
type Spec struct {
	Type  string
	Class Class
	// Rollback — какую точку отката требует тип; иное значение в теле — PARAMS_INVALID.
	Rollback agentv1.RollbackKind
	// AutoRollback — тип может требовать автооткат (confirm_within > 0).
	AutoRollback bool
	// Validate проверяет параметры (oneof уже совпал с типом).
	Validate func(*agentv1.OperationBody) error
	// match — вариант oneof, обязательный для типа.
	match func(*agentv1.OperationParams) bool
}

// Catalog — неизменяемый список типов.
type Catalog struct{ specs map[string]Spec }

// ErrEmptyCatalog — список типов пуст: помощник не стартует (R1).
var ErrEmptyCatalog = errors.New("ops: пустой список типов")

// NewCatalog собирает каталог. Пустой список и повтор типа — ошибка.
func NewCatalog(specs ...Spec) (*Catalog, error) {
	if len(specs) == 0 {
		return nil, ErrEmptyCatalog
	}
	m := make(map[string]Spec, len(specs))
	for _, s := range specs {
		if s.Type == "" || s.Validate == nil || s.match == nil {
			return nil, fmt.Errorf("ops: неполное описание типа %q", s.Type)
		}
		if _, dup := m[s.Type]; dup {
			return nil, fmt.Errorf("ops: тип %q дважды", s.Type)
		}
		m[s.Type] = s
	}
	return &Catalog{specs: m}, nil
}

// Lookup ищет тип. Пустой или nil каталог не знает ни одного типа.
func (c *Catalog) Lookup(t string) (Spec, bool) {
	if c == nil {
		return Spec{}, false
	}
	s, ok := c.specs[t]
	return s, ok
}

// Types — отсортированный список типов (Hello.capabilities).
func (c *Catalog) Types() []string {
	if c == nil {
		return nil
	}
	out := make([]string, 0, len(c.specs))
	for t := range c.specs {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// Builtin — список этой сборки.
func Builtin() *Catalog {
	c, err := NewCatalog(builtinSpecs()...)
	if err != nil {
		panic(err) // список зашит в код: ошибка здесь — ошибка сборки, тест её ловит
	}
	return c
}

func builtinSpecs() []Spec {
	return append([]Spec{
		{
			Type: TypeSystemInfo, Class: Read, Rollback: agentv1.RollbackKind_ROLLBACK_KIND_NONE,
			match:    func(p *agentv1.OperationParams) bool { return p.GetSystemInfo() != nil },
			Validate: func(*agentv1.OperationBody) error { return nil },
		},
		{
			Type: TypeSystemInventory, Class: Read, Rollback: agentv1.RollbackKind_ROLLBACK_KIND_NONE,
			match:    func(p *agentv1.OperationParams) bool { return p.GetSystemInventory() != nil },
			Validate: validateInventory,
		},
		{
			Type: TypeAgentUpdate, Class: Change, Rollback: agentv1.RollbackKind_ROLLBACK_KIND_NONE,
			match:    func(p *agentv1.OperationParams) bool { return p.GetAgentUpdate() != nil },
			Validate: validateUpdate,
		},
		{
			Type: TypeAgentUninstall, Class: Destructive, Rollback: agentv1.RollbackKind_ROLLBACK_KIND_NONE,
			match:    func(p *agentv1.OperationParams) bool { return p.GetAgentUninstall() != nil },
			Validate: func(*agentv1.OperationBody) error { return nil },
		},
		{
			// Класс — как у исходной операции; для очереди помощника это всегда изменение.
			Type: TypeRollbackRestore, Class: Change, Rollback: agentv1.RollbackKind_ROLLBACK_KIND_CONFIG,
			match: func(p *agentv1.OperationParams) bool { return p.GetRollbackRestore() != nil },
			Validate: func(b *agentv1.OperationBody) error {
				if !config.IsUUID(b.GetParams().GetRollbackRestore().GetTargetOperationId()) {
					return errors.New("target_operation_id")
				}
				return nil
			},
		},
	}, append(append(append(logsSpecs(), securitySpecs()...), wireguardSpecs()...), extraSpecs()...)...)
}

// CheckParams — проверка 6: вариант oneof совпадает с типом, точка отката и автооткат — как у типа, значения
// проходят схему.
func CheckParams(spec Spec, b *agentv1.OperationBody) error {
	if b.GetParams() == nil || !spec.match(b.GetParams()) {
		return errors.New("params не того типа")
	}
	if b.GetRollback() != spec.Rollback {
		return fmt.Errorf("rollback %v, тип требует %v", b.GetRollback(), spec.Rollback)
	}
	if !spec.AutoRollback && b.GetConfirmWithinSec() != 0 {
		return errors.New("confirm_within у типа без автооткатa")
	}
	return spec.Validate(b)
}

func validateInventory(b *agentv1.OperationBody) error {
	inc := b.GetParams().GetSystemInventory().GetInclude()
	if len(inc) < 1 || len(inc) > 3 {
		return errors.New("include: от 1 до 3 видов")
	}
	seen := map[agentv1.InventoryKind]bool{}
	for _, k := range inc {
		switch k {
		case agentv1.InventoryKind_INVENTORY_KIND_SERVICES, agentv1.InventoryKind_INVENTORY_KIND_CONTAINERS,
			agentv1.InventoryKind_INVENTORY_KIND_PORTS:
		default:
			return fmt.Errorf("include: неизвестный вид %v", k)
		}
		if seen[k] {
			return errors.New("include: повтор")
		}
		seen[k] = true
	}
	return nil
}

var (
	semverRe = regexp.MustCompile(`^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$`)
	sha256Re = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// IsSemver — версия вида 1.2.3 или 1.2.3-rc.1.
func IsSemver(s string) bool { return semverRe.MatchString(s) }

func httpsURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil
}

// ArtifactBinary — имя бинарника по адресу артефакта: trassa-agent-linux-<arch> или trassa-helper-linux-<arch>.
func ArtifactBinary(a *agentv1.ReleaseArtifact) (string, bool) {
	u, err := url.Parse(a.GetUrl())
	if err != nil {
		return "", false
	}
	base := path.Base(u.Path)
	for _, bin := range []string{"trassa-agent", "trassa-helper"} {
		if base == bin+"-"+a.GetOs()+"-"+a.GetArch() {
			return bin, true
		}
	}
	return "", false
}

func validateUpdate(b *agentv1.OperationBody) error {
	p := b.GetParams().GetAgentUpdate()
	if !IsSemver(p.GetVersion()) {
		return errors.New("version")
	}
	if n := len(p.GetArtifacts()); n < 1 || n > 4 {
		return errors.New("artifacts: от 1 до 4")
	}
	seen := map[string]bool{}
	for _, a := range p.GetArtifacts() {
		if a.GetOs() != "linux" || (a.GetArch() != "amd64" && a.GetArch() != "arm64") {
			return errors.New("artifacts: os или arch")
		}
		if !httpsURL(a.GetUrl()) || !sha256Re.MatchString(a.GetSha256()) {
			return errors.New("artifacts: url или sha256")
		}
		bin, ok := ArtifactBinary(a)
		if !ok || seen[bin+a.GetArch()] {
			return errors.New("artifacts: имя файла или повтор")
		}
		seen[bin+a.GetArch()] = true
	}
	if !httpsURL(p.GetSignatureUrl()) || !strings.HasSuffix(p.GetSignatureUrl(), ".minisig") {
		return errors.New("signature_url")
	}
	return nil
}
