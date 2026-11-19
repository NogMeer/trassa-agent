// SPDX-License-Identifier: AGPL-3.0-only

// Package redact вычищает секреты из вывода операций до отправки в панель (E05-T20, R20).
//
// Это первый слой: такой же фильтр стоит на приёме в apps/api (operations.inbound). Образцы — известные форматы
// ключей и токенов плюс пары «имя=значение» с говорящими именами. Ложное срабатывание дешевле утечки.
package redact

import (
	"regexp"
	"strings"
)

// Mask — чем заменяется секрет.
const Mask = "[REDACTED]"

type rule struct {
	re *regexp.Regexp
	// repl — шаблон замены; группы ${1}… сохраняют неопасную часть (имя ключа, схему адреса).
	repl string
}

var rules = []rule{
	// Закрытые ключи PEM целиком (однострочный вид; многострочный режет Writer).
	{regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----`), Mask},
	// Токены Trassa: trs_enr_…, trs_pat_… и другие с префиксом trs_.
	{regexp.MustCompile(`\btrs_[a-z]{2,8}_[A-Za-z0-9_-]{16,}`), Mask},
	// GitHub.
	{regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,})`), Mask},
	// GitLab.
	{regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{20,}`), Mask},
	// Slack.
	{regexp.MustCompile(`\bxox[abposr]-[A-Za-z0-9-]{10,}`), Mask},
	// AWS: ключ доступа.
	{regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`), Mask},
	// Google API.
	{regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}`), Mask},
	// Stripe.
	{regexp.MustCompile(`\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}`), Mask},
	// Anthropic, OpenAI.
	{regexp.MustCompile(`\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}`), Mask},
	// JWT.
	{regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`), Mask},
	// Telegram-бот.
	{regexp.MustCompile(`\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b`), Mask},
	// Заголовок Authorization.
	{regexp.MustCompile(`(?i)(authorization\s*[:=]\s*(?:bearer|basic|token)\s+)[^\s"']+`), "${1}" + Mask},
	// Учётные данные в адресе: scheme://user:pass@host.
	{regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://[^\s:/@]+:)[^\s@/]+@`), "${1}" + Mask + "@"},
	// Пары имя=значение, имя: значение, "имя": "значение" с говорящим именем.
	{regexp.MustCompile(`(?i)((?:"|')?[a-z0-9_.-]*(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret|credentials?)(?:"|')?\s*[:=]\s*)("[^"]*"|'[^']*'|[^\s,;}]+)`), "${1}" + Mask},
}

// String вычищает секреты из строки.
func String(s string) string {
	for _, r := range rules {
		s = r.re.ReplaceAllString(s, r.repl)
	}
	return s
}

var (
	pemBegin = regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----`)
	pemEnd   = regexp.MustCompile(`-----END [A-Z0-9 ]*PRIVATE KEY-----`)
)

// Lines вычищает секреты построчно с учётом многострочных блоков PEM: всё между BEGIN и END заменяется одной
// меткой. Состояние «внутри блока» переходит между вызовами через inPEM — вывод приходит кусками.
type Lines struct{ inPEM bool }

// Line обрабатывает одну строку (без перевода строки). Пустой результат и false — строку нужно выбросить.
func (l *Lines) Line(s string) (string, bool) {
	if l.inPEM {
		if loc := pemEnd.FindStringIndex(s); loc != nil {
			l.inPEM = false
			rest := strings.TrimSpace(s[loc[1]:])
			if rest == "" {
				return "", false
			}
			return String(rest), true
		}
		return "", false
	}
	if loc := pemBegin.FindStringIndex(s); loc != nil && !pemEnd.MatchString(s[loc[1]:]) {
		l.inPEM = true
		return String(s[:loc[0]]) + Mask, true
	}
	return String(s), true
}

// Text вычищает многострочный текст целиком.
func Text(s string) string {
	var l Lines
	parts := strings.Split(s, "\n")
	out := parts[:0]
	for _, p := range parts {
		if v, ok := l.Line(p); ok {
			out = append(out, v)
		}
	}
	return strings.Join(out, "\n")
}
