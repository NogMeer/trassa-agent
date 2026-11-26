// SPDX-License-Identifier: AGPL-3.0-only

// Package imageupdate — container.update (E10, рекомендации обновлений): смена тега образа одного сервиса docker
// compose. Решения — docs/plan/decisions/E10-image-updates.md панели, раздел 7.
//
// Compose-файл не пересобирается из разобранного YAML (это стёрло бы комментарии и порядок): меняется только
// значение `image:` нужного сервиса в исходном тексте, а правильность правки проверяет сам compose — разрешённая
// конфигурация (`docker compose config --format json`) после правки обязана отличаться от прежней ровно образом этого
// сервиса. Всё, что строковый разбор не понимает однозначно (поток `{…}`, якоря, `<<:`, многострочные значения,
// табуляция, несколько документов, повтор ключа), — отказ IMAGE_TAG_NOT_EDITABLE, а не догадка.
package imageupdate

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Коды итога (имена — коды панели).
var (
	ErrNotFound      = errors.New("CONTAINER_NOT_FOUND")
	ErrNotCompose    = errors.New("CONTAINER_NOT_COMPOSE")
	ErrImageChanged  = errors.New("CONTAINER_IMAGE_CHANGED")
	ErrManaged       = errors.New("CONTAINER_MANAGED_BY_TRASSA")
	ErrFileForbidden = errors.New("COMPOSE_FILE_FORBIDDEN")
	ErrNotEditable   = errors.New("IMAGE_TAG_NOT_EDITABLE")
	ErrPinned        = errors.New("IMAGE_PINNED_BY_DIGEST")
	ErrConfig        = errors.New("COMPOSE_CONFIG_FAILED")
	ErrEditMismatch  = errors.New("COMPOSE_EDIT_MISMATCH")
	ErrPull          = errors.New("IMAGE_PULL_FAILED")
	ErrNotHealthy    = errors.New("CONTAINER_NOT_HEALTHY")
	ErrDocker        = errors.New("DOCKER_UNAVAILABLE")
)

// Codes — все коды пакета для отчёта помощника.
var Codes = []error{ErrNotFound, ErrNotCompose, ErrImageChanged, ErrManaged, ErrFileForbidden, ErrNotEditable,
	ErrPinned, ErrConfig, ErrEditMismatch, ErrPull, ErrNotHealthy, ErrDocker}

func notEditable(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrNotEditable, fmt.Sprintf(format, a...))
}

// Span — значение `image:` в тексте файла: байты [Start, End) без кавычек, Quote — '"', '\” или 0.
type Span struct {
	Start, End int
	Quote      byte
	Value      string
}

var (
	reServicesKey = regexp.MustCompile(`^services:[ ]*(?:#.*)?$`)
	reTopKey      = regexp.MustCompile(`^[^\s#-][^:]*:`)
	reKeyLine     = regexp.MustCompile(`^( +)("[^"]*"|'[^']*'|[^\s"'#:][^:#]*?)[ ]*:(?:[ ]+(.*?))?[ ]*$`)
)

func indentOf(line string) int { return len(line) - len(strings.TrimLeft(line, " ")) }

func unquoteKey(k string) string {
	if len(k) >= 2 && (k[0] == '"' || k[0] == '\'') && k[len(k)-1] == k[0] {
		return k[1 : len(k)-1]
	}
	return k
}

// stripComment — значение без хвостового « #…»: у значения в кавычках — после закрывающей кавычки.
func stripComment(v string) string {
	if v != "" && (v[0] == '"' || v[0] == '\'') {
		j := strings.IndexByte(v[1:], v[0])
		if j < 0 {
			return v
		}
		rest := strings.TrimLeft(v[j+2:], " ")
		if rest == "" || strings.HasPrefix(rest, "#") {
			return v[:j+2]
		}
		return v
	}
	if i := strings.Index(v, " #"); i >= 0 {
		return strings.TrimRight(v[:i], " ")
	}
	return v
}

// FindImage — значение `image:` сервиса service в compose-файле. Сервиса или ключа image в файле нет — (nil, nil):
// образ может быть задан в другом файле проекта. Неоднозначный текст — ErrNotEditable.
func FindImage(content []byte, service string) (*Span, error) {
	if bytes.ContainsRune(content, '\t') {
		return nil, notEditable("в файле есть табуляция")
	}
	if bytes.ContainsRune(content, '\r') {
		return nil, notEditable("переводы строк CRLF")
	}
	lines := strings.Split(string(content), "\n")
	offsets := make([]int, len(lines))
	for i, pos := 0, 0; i < len(lines); i++ {
		offsets[i], pos = pos, pos+len(lines[i])+1
	}
	blank := func(l string) bool { t := strings.TrimSpace(l); return t == "" || strings.HasPrefix(t, "#") }
	docs, inServices, svcIndent, inSvc, keyIndent := 0, false, -1, false, -1
	var found *Span
	for i, line := range lines {
		if strings.HasPrefix(line, "---") || strings.HasPrefix(line, "...") {
			if docs++; docs > 1 || i > 0 && !allBlank(lines[:i], blank) {
				return nil, notEditable("в файле несколько документов YAML")
			}
			continue
		}
		if blank(line) {
			continue
		}
		ind := indentOf(line)
		if ind == 0 {
			inSvc = false
			inServices = reServicesKey.MatchString(line)
			if !inServices && strings.HasPrefix(line, "services") {
				return nil, notEditable("ключ services записан не блоком")
			}
			if !inServices && !reTopKey.MatchString(line) {
				return nil, notEditable("строка верхнего уровня не ключ: %d", i+1)
			}
			continue
		}
		if !inServices {
			continue
		}
		if svcIndent < 0 {
			svcIndent = ind
		}
		if ind < svcIndent {
			return nil, notEditable("неровный отступ в services: строка %d", i+1)
		}
		m := reKeyLine.FindStringSubmatch(line)
		if ind == svcIndent {
			inSvc, keyIndent = false, -1
			if m == nil {
				return nil, notEditable("строка %d в services — не имя сервиса", i+1)
			}
			if unquoteKey(m[2]) == service {
				if found != nil || m[3] != "" && !strings.HasPrefix(m[3], "#") {
					return nil, notEditable("сервис %s описан не блоком или дважды", service)
				}
				inSvc = true
			}
			continue
		}
		if !inSvc {
			continue
		}
		if keyIndent < 0 {
			keyIndent = ind
		}
		if ind != keyIndent {
			continue // вложенные ключи (environment, ports…)
		}
		// Элементы списка на отступе ключей (ports:\n- "80:80") — значение предыдущего ключа.
		if t := line[ind:]; t == "-" || strings.HasPrefix(t, "- ") {
			continue
		}
		if m == nil {
			return nil, notEditable("строка %d сервиса %s — не ключ", i+1, service)
		}
		key := unquoteKey(m[2])
		if key == "<<" || key == "extends" {
			return nil, notEditable("сервис %s наследует настройки (%s)", service, key)
		}
		if key != "image" {
			continue
		}
		if found != nil {
			return nil, notEditable("ключ image у %s дважды", service)
		}
		raw := stripComment(m[3])
		if raw == "" {
			return nil, notEditable("image у %s без значения в строке", service)
		}
		valStart := offsets[i] + strings.Index(line, raw)
		s := &Span{Start: valStart, End: valStart + len(raw)}
		switch raw[0] {
		case '"', '\'':
			if len(raw) < 2 || raw[len(raw)-1] != raw[0] || strings.ContainsAny(raw[1:len(raw)-1], `"'\`) {
				return nil, notEditable("кавычки image у %s", service)
			}
			s.Quote, s.Start, s.End = raw[0], s.Start+1, s.End-1
		case '&', '*', '!', '|', '>', '{', '[', '@', '`', '%':
			return nil, notEditable("image у %s — не простое значение", service)
		}
		s.Value = string(content[s.Start:s.End])
		found = s
	}
	return found, nil
}

func allBlank(ls []string, blank func(string) bool) bool {
	for _, l := range ls {
		if !blank(l) {
			return false
		}
	}
	return true
}

// Replace — content с заменённым значением span.
func Replace(content []byte, s *Span, value string) []byte {
	out := make([]byte, 0, len(content)+len(value))
	out = append(out, content[:s.Start]...)
	out = append(out, value...)
	return append(out, content[s.End:]...)
}

// Кусок значения image с переменной: ${VAR}, ${VAR:-по умолчанию}, $VAR.
var (
	reVarWhole = regexp.MustCompile(`^\$(?:\{([A-Za-z_][A-Za-z0-9_]{0,127})(?::?[-?][^}$]*)?\}|([A-Za-z_][A-Za-z0-9_]{0,127}))$`)
	reVarTag   = regexp.MustCompile(`^([^$]+):\$(?:\{([A-Za-z_][A-Za-z0-9_]{0,127})(?::?[-?][^}$]*)?\}|([A-Za-z_][A-Za-z0-9_]{0,127}))$`)
)

// VarRef — значение image берётся из переменной: Whole — вся ссылка (${IMAGE}), иначе только тег (repo:${TAG}).
type VarRef struct {
	Name  string
	Whole bool
	// Repo — часть до «:» у тега из переменной.
	Repo string
}

// ParseVar — переменная в значении image; без «$» — (nil, nil); «$» в другой форме — ErrNotEditable.
func ParseVar(value string) (*VarRef, error) {
	if !strings.Contains(value, "$") {
		return nil, nil
	}
	if m := reVarWhole.FindStringSubmatch(value); m != nil {
		return &VarRef{Name: m[1] + m[2], Whole: true}, nil
	}
	if m := reVarTag.FindStringSubmatch(value); m != nil {
		return &VarRef{Name: m[2] + m[3], Repo: m[1]}, nil
	}
	return nil, notEditable("образ собран из переменных так, что тег не вычислить: %s", value)
}

var reEnvLine = regexp.MustCompile(`^(?:export[ ]+)?([A-Za-z_][A-Za-z0-9_]*)[ ]*=[ ]*(.*?)[ ]*$`)

// FindEnv — значение переменной name в файле .env (одна строка `NAME=значение`, можно в кавычках). Нет или
// несколько — ErrNotEditable: тогда тег задан не там, где его можно поменять предсказуемо.
func FindEnv(content []byte, name string) (*Span, error) {
	if bytes.ContainsRune(content, '\r') {
		return nil, notEditable(".env с переводами строк CRLF")
	}
	var found *Span
	pos := 0
	for _, line := range strings.Split(string(content), "\n") {
		start := pos
		pos += len(line) + 1
		m := reEnvLine.FindStringSubmatchIndex(line)
		if m == nil || line[m[2]:m[3]] != name {
			continue
		}
		if found != nil {
			return nil, notEditable("переменная %s в .env дважды", name)
		}
		raw := line[m[4]:m[5]]
		s := &Span{Start: start + m[4], End: start + m[5]}
		if raw != "" && (raw[0] == '"' || raw[0] == '\'') {
			if len(raw) < 2 || raw[len(raw)-1] != raw[0] || strings.ContainsAny(raw[1:len(raw)-1], `"'\$`) {
				return nil, notEditable("кавычки переменной %s в .env", name)
			}
			s.Quote, s.Start, s.End = raw[0], s.Start+1, s.End-1
		} else if strings.ContainsAny(raw, ` #$"'\`) {
			return nil, notEditable("значение %s в .env — не простое", name)
		}
		s.Value = string(content[s.Start:s.End])
		found = s
	}
	if found == nil {
		return nil, notEditable("переменная %s не задана в .env проекта", name)
	}
	return found, nil
}
