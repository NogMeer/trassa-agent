// SPDX-License-Identifier: AGPL-3.0-only

package ops

import (
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"
	"unicode/utf8"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/config"
)

// Типы журналов (E08, раздел 6). Оба READ и только по подписанной операции: агент не отправляет журналы, пока
// панель не попросила подписью.
const (
	TypeLogsSubscribe = "logs.subscribe"
	TypeLogsRead      = "logs.read"
)

// Пределы журналов.
const (
	MaxLogSources = 20
	MaxReadLines  = 500
	MaxGrepRunes  = 200
	// LogDir — единственный каталог, файлы из которого можно читать.
	LogDir     = "/var/log/"
	maxLogPath = 4096
)

// Имена служб и контейнеров: без ведущего «-» (не похоже на ключ journalctl), без пробелов и управляющих символов.
var (
	unitNameRe      = regexp.MustCompile(`^[A-Za-z0-9_.:@\\][A-Za-z0-9_.:@\\-]{0,199}$`)
	containerNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
)

// ValidLogPath — путь файла журнала по синтаксису: абсолютный, уже очищенный, внутри /var/log/, без «..».
// Ссылки проверяет помощник при открытии (без следования по ним).
func ValidLogPath(p string) error {
	if len(p) > maxLogPath || strings.ContainsRune(p, 0) || !utf8.ValidString(p) {
		return errors.New("путь: недопустимые символы или длина")
	}
	if !strings.HasPrefix(p, LogDir) || path.Clean(p) != p || p == strings.TrimSuffix(LogDir, "/") {
		return errors.New("путь вне /var/log/")
	}
	for _, c := range strings.Split(strings.TrimPrefix(p, LogDir), "/") {
		if c == "" || c == "." || c == ".." {
			return errors.New("путь: пустой компонент или «..»")
		}
	}
	return nil
}

// ValidLogSource проверяет источник по схеме.
func ValidLogSource(s *agentv1.LogSource) error {
	n := s.GetName()
	switch s.GetKind() {
	case agentv1.LogSourceKind_LOG_SOURCE_KIND_SYSTEM, agentv1.LogSourceKind_LOG_SOURCE_KIND_SSH:
		if n != "" {
			return errors.New("у SYSTEM и SSH нет имени")
		}
	case agentv1.LogSourceKind_LOG_SOURCE_KIND_UNIT:
		if !unitNameRe.MatchString(n) {
			return fmt.Errorf("имя службы %q", n)
		}
	case agentv1.LogSourceKind_LOG_SOURCE_KIND_DOCKER:
		if !containerNameRe.MatchString(n) {
			return fmt.Errorf("имя контейнера %q", n)
		}
	case agentv1.LogSourceKind_LOG_SOURCE_KIND_FILE:
		return ValidLogPath(n)
	case agentv1.LogSourceKind_LOG_SOURCE_KIND_APP:
		// app_id в нижнем регистре, как его пишет деплой в метку trassa.app_id.
		if !config.IsUUID(n) || strings.ToLower(n) != n {
			return fmt.Errorf("app_id %q", n)
		}
	default:
		return fmt.Errorf("вид источника %v", s.GetKind())
	}
	return nil
}

func validLevel(l agentv1.LogLevel) bool {
	return l >= agentv1.LogLevel_LOG_LEVEL_UNSPECIFIED && l <= agentv1.LogLevel_LOG_LEVEL_DEBUG
}

func validateLogsSubscribe(b *agentv1.OperationBody) error {
	p := b.GetParams().GetLogsSubscribe()
	if len(p.GetSources()) > MaxLogSources {
		return fmt.Errorf("источников больше %d", MaxLogSources)
	}
	if !validLevel(p.GetMinLevel()) {
		return errors.New("min_level")
	}
	for _, s := range p.GetSources() {
		if err := ValidLogSource(s); err != nil {
			return err
		}
	}
	return nil
}

func validateLogsRead(b *agentv1.OperationBody) error {
	p := b.GetParams().GetLogsRead()
	if p.GetSource() == nil {
		return errors.New("source обязателен")
	}
	if err := ValidLogSource(p.GetSource()); err != nil {
		return err
	}
	if p.GetLines() < 1 || p.GetLines() > MaxReadLines {
		return fmt.Errorf("lines: от 1 до %d", MaxReadLines)
	}
	if !utf8.ValidString(p.GetGrep()) || utf8.RuneCountInString(p.GetGrep()) > MaxGrepRunes {
		return fmt.Errorf("grep: до %d символов", MaxGrepRunes)
	}
	return nil
}

func logsSpecs() []Spec {
	return []Spec{
		{
			Type: TypeLogsSubscribe, Class: Read, Rollback: agentv1.RollbackKind_ROLLBACK_KIND_NONE,
			match:    func(p *agentv1.OperationParams) bool { return p.GetLogsSubscribe() != nil },
			Validate: validateLogsSubscribe,
		},
		{
			Type: TypeLogsRead, Class: Read, Rollback: agentv1.RollbackKind_ROLLBACK_KIND_NONE,
			match:    func(p *agentv1.OperationParams) bool { return p.GetLogsRead() != nil },
			Validate: validateLogsRead,
		},
	}
}
