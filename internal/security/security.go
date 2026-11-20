// SPDX-License-Identifier: AGPL-3.0-only

// Package security — проверки центра безопасности (E10, раздел 6) в помощнике: только чтение, без оболочки.
// Список проверок зашит здесь (R7): код, которого нет в списке, панель запросить не может — операция
// отклоняется как PARAMS_INVALID. Скан не дольше 60 с, каждая проверка — со своим сроком; не уложившаяся
// получает ERROR TIMEOUT. evidence проходит фильтр секретов и не содержит ключей и хэшей паролей.
package security

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"
	"unicode/utf8"

	"google.golang.org/protobuf/proto"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/redact"
)

// Пределы скана.
const (
	ScanTimeout = 60 * time.Second
	MaxResult   = 1 << 20
	MaxEvidence = 2 << 10
	MaxChecks   = 100
	// MaxSubjects — сколько объектов одной проверки уходит в результат (порты, файлы, пользователи).
	MaxSubjects = 100
)

// checkTimeout — срок одной проверки (переменная: тесты сокращают его).
var checkTimeout = 20 * time.Second

// Коды ошибок проверки (CheckResult.error).
const (
	ErrTimeout     = "TIMEOUT"
	ErrUnsupported = "UNSUPPORTED"
	ErrReadFailed  = "READ_FAILED"
)

// Finding — итог проверки по одному объекту.
type Finding struct {
	Subject  string
	State    agentv1.CheckState
	Evidence string
	Error    string
}

func pass(subject, ev string) Finding {
	return Finding{Subject: subject, State: agentv1.CheckState_CHECK_STATE_PASS, Evidence: ev}
}
func fail(subject, ev string) Finding {
	return Finding{Subject: subject, State: agentv1.CheckState_CHECK_STATE_FAIL, Evidence: ev}
}
func na(ev string) Finding { return Finding{State: agentv1.CheckState_CHECK_STATE_NA, Evidence: ev} }
func failed(code string, err error) Finding {
	return Finding{State: agentv1.CheckState_CHECK_STATE_ERROR, Error: code, Evidence: err.Error()}
}

// Check — одна проверка каталога.
type Check struct {
	Code string
	Run  func(ctx context.Context, s *Scan) []Finding
}

// registry — зашитый список. Заполняется в init файлов проверок.
var registry = map[string]Check{}

func register(c Check) {
	if _, dup := registry[c.Code]; dup {
		panic("security: проверка " + c.Code + " дважды")
	}
	registry[c.Code] = c
}

// Codes — коды, которые умеет этот помощник (отсортированы).
func Codes() []string {
	out := make([]string, 0, len(registry))
	for c := range registry {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// Known — код есть в списке.
func Known(code string) bool { _, ok := registry[code]; return ok }

// ValidateParams — схема security.scan: непустой список известных кодов без повторов (R1, R7).
func ValidateParams(p *agentv1.SecurityScanParams) error {
	if len(p.GetChecks()) == 0 {
		return errors.New("checks: пустой список")
	}
	if len(p.GetChecks()) > MaxChecks {
		return fmt.Errorf("checks: больше %d", MaxChecks)
	}
	seen := map[string]bool{}
	for _, c := range p.GetChecks() {
		if !Known(c) {
			return fmt.Errorf("checks: неизвестный код %q", c)
		}
		if seen[c] {
			return fmt.Errorf("checks: повтор %q", c)
		}
		seen[c] = true
	}
	if len(p.GetBaselineDigest()) > 128 {
		return errors.New("baseline_digest: длина")
	}
	return nil
}

// Run выполняет проверки по порядку запроса и собирает снимок. Проверки идут по одной: общий срок ScanTimeout,
// у каждой — не больше checkTimeout и не больше остатка общего срока.
func Run(ctx context.Context, sys *System, p *agentv1.SecurityScanParams) *agentv1.SecurityScanResult {
	ctx, cancel := context.WithTimeout(ctx, ScanTimeout)
	defer cancel()
	s := newScan(sys)
	res := &agentv1.SecurityScanResult{}
	for _, code := range p.GetChecks() {
		c := registry[code]
		for _, f := range runOne(ctx, s, c) {
			res.Checks = append(res.Checks, &agentv1.CheckResult{
				Code: code, Subject: clip(redact.String(f.Subject), 200), State: f.State,
				Evidence: clip(redact.String(f.Evidence), MaxEvidence), Error: f.Error,
			})
		}
	}
	s.snapshot(ctx, res)
	shrink(res)
	return res
}

func runOne(ctx context.Context, s *Scan, c Check) []Finding {
	cctx, cancel := context.WithTimeout(ctx, checkTimeout)
	defer cancel()
	done := make(chan []Finding, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- []Finding{failed(ErrReadFailed, fmt.Errorf("сбой проверки: %v", r))}
			}
		}()
		done <- c.Run(cctx, s)
	}()
	select {
	case out := <-done:
		if len(out) == 0 {
			return []Finding{pass("", "")}
		}
		if len(out) > MaxSubjects {
			out = append(out[:MaxSubjects], Finding{State: agentv1.CheckState_CHECK_STATE_FAIL,
				Evidence: fmt.Sprintf("и ещё %d объектов", len(out)-MaxSubjects)})
		}
		return out
	case <-cctx.Done():
		return []Finding{{State: agentv1.CheckState_CHECK_STATE_ERROR, Error: ErrTimeout, Evidence: "проверка не уложилась в срок"}}
	}
}

// shrink урезает результат до MaxResult: сначала снимок сокетов, затем evidence.
func shrink(res *agentv1.SecurityScanResult) {
	for proto.Size(res) > MaxResult && len(res.Listeners) > 0 {
		res.Listeners = res.Listeners[:len(res.Listeners)/2]
	}
	for proto.Size(res) > MaxResult {
		cut := false
		for _, c := range res.Checks {
			if len(c.Evidence) > 64 {
				c.Evidence = clip(c.Evidence, 64)
				cut = true
			}
		}
		if !cut {
			res.Checks = res.Checks[:len(res.Checks)/2]
		}
	}
}

func clip(s string, n int) string {
	s = string([]rune(s)) // неверный UTF-8 → U+FFFD
	if len(s) <= n {
		return s
	}
	s = s[:n]
	for !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}
