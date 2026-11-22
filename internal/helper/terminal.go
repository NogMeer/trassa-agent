// SPDX-License-Identifier: AGPL-3.0-only

package helper

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/access"
	"github.com/NogMeer/trassa-agent/internal/helperrpc"
	"github.com/NogMeer/trassa-agent/internal/nonce"
	"github.com/NogMeer/trassa-agent/internal/opcheck"
	"github.com/NogMeer/trassa-agent/internal/terminal"
	"github.com/NogMeer/trassa-agent/internal/verify"
)

// Пределы терминала (decisions E16, 9.4 и 9.6).
const (
	MaxTerminals    = 20
	RenewWindow     = 10 * time.Minute
	terminalPoll    = 2 * time.Second
	CodeSessionMax  = "ACCESS_SESSION_LIMIT"
	CodeRenewBad    = "TERMINAL_RENEW_INVALID"
	ContextRenew    = "trassa-terminal-renew-v1"
	terminalTermEnv = "xterm-256color"
)

// TerminalUnits — службы терминалов (systemd через D-Bus; в тестах — подмена).
type TerminalUnits interface {
	Start(ctx context.Context, s terminal.Shell, slave *os.File) error
	Active(ctx context.Context, sessionID string) (bool, error)
	Stop(ctx context.Context, sessionID string) error
	StopAll(ctx context.Context) error
	// Session — сеанс logind оболочки; TerminateSession — закрыть его со всеми процессами.
	Session(ctx context.Context, sessionID string) (string, error)
	TerminateSession(ctx context.Context, id string) error
}

// Terminals — открытые терминалы помощника.
type Terminals struct {
	Units   TerminalUnits
	OpenPTY func() (master, slave *os.File, n int, err error)
	// Locales — сгенерированные локали (locale -a); nil — только C.
	Locales func(ctx context.Context) []string
	// SetSize — размер окна PTY (nil — terminal.SetSize); Poll — как часто сверять службу и сроки (0 — 2 с).
	SetSize func(f *os.File, cols, rows uint32) error
	Poll    time.Duration

	mu       sync.Mutex
	sessions map[string]*termSession
}

type termSession struct {
	// login — сеанс logind оболочки: закрывается вместе со службой (фоновые процессы терминала не остаются).
	login      string
	opID       string
	user       string
	renewUntil time.Time
	hardUntil  time.Time
	closeCh    chan agentv1.TerminalEndReason
}

func (t *Terminals) count() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.sessions)
}

// pickLang — локаль из белого списка, если сгенерирована; иначе C.UTF-8, иначе C.
func (t *Terminals) pickLang(ctx context.Context, want string) string {
	var have []string
	if t.Locales != nil {
		have = t.Locales(ctx)
	}
	norm := func(s string) string {
		return strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(s, "-", ""), "_", ""))
	}
	for _, cand := range []string{want, "C.UTF-8"} {
		for _, h := range have {
			if cand != "" && norm(h) == norm(cand) {
				return cand
			}
		}
	}
	return "C"
}

func (e *Executor) terminalEnv(r *run) (*Terminals, *access.Env, *agentv1.OperationResult) {
	if e.Terminals == nil || e.Access == nil {
		return nil, nil, r.failed(CodeAccessUnavailable, "терминал на этом сервере недоступен")
	}
	return e.Terminals, e.Access, nil
}

// applyTerminalOpen — terminal.open: только пользователю доступа (или trassa-rescue с действующей выдачей),
// не больше MaxTerminals. Операция живёт, пока открыт терминал; итог — TerminalSessionResult.
func (e *Executor) applyTerminalOpen(ctx context.Context, r *run) *agentv1.OperationResult {
	t, acc, fail := e.terminalEnv(r)
	if fail != nil {
		return fail
	}
	p := r.body.GetParams().GetTerminalOpen()
	shell, err := acc.ShellOf(p.GetUnixUser(), e.now())
	if err != nil {
		return r.failed(accessCode(err), err.Error())
	}
	if t.count() >= MaxTerminals {
		return r.failed(CodeSessionMax, fmt.Sprintf("открыто терминалов: %d", MaxTerminals))
	}
	sid := strings.ToLower(p.GetSessionId())
	lang := t.pickLang(ctx, p.GetEnvLang())
	master, slave, n, err := t.OpenPTY()
	if err != nil {
		return r.failed(CodeApplyFailed, "PTY: "+err.Error())
	}
	defer master.Close()
	setSize := t.SetSize
	if setSize == nil {
		setSize = terminal.SetSize
	}
	if err := setSize(master, p.GetCols(), p.GetRows()); err != nil {
		slave.Close()
		return r.failed(CodeApplyFailed, err.Error())
	}
	maxRun := time.Duration(p.GetMaxDurationSec()) * time.Second
	started := e.now()
	err = t.Units.Start(ctx, terminal.Shell{SessionID: sid, User: p.GetUnixUser(), Shell: shell, Lang: lang, Term: terminalTermEnv,
		PTSNumber: n, MaxRun: maxRun}, slave)
	slave.Close()
	if err != nil {
		return r.failed(CodeApplyFailed, err.Error())
	}
	s := &termSession{opID: strings.ToLower(r.body.GetOperationId()), user: p.GetUnixUser(), renewUntil: started.Add(RenewWindow),
		hardUntil: started.Add(maxRun), closeCh: make(chan agentv1.TerminalEndReason, 1)}
	if s.renewUntil.After(s.hardUntil) {
		s.renewUntil = s.hardUntil
	}
	t.mu.Lock()
	if t.sessions == nil {
		t.sessions = map[string]*termSession{}
	}
	if _, dup := t.sessions[sid]; dup || len(t.sessions) >= MaxTerminals {
		t.mu.Unlock()
		_ = t.Units.Stop(context.WithoutCancel(ctx), sid)
		return r.failed(CodeSessionMax, "сеанс уже открыт или предел сеансов")
	}
	t.sessions[sid] = s
	t.mu.Unlock()
	defer func() {
		t.mu.Lock()
		delete(t.sessions, sid)
		t.mu.Unlock()
	}()
	// Сеанс logind появляется, когда PAM перенёс оболочку в session-N.scope: ждём до 3 с.
	for i := 0; i < 30 && s.login == ""; i++ {
		if id, err := t.Units.Session(ctx, sid); err == nil && id != "" {
			s.login = id
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if s.login == "" {
		e.log().Warn("helper: сеанс logind терминала не найден: закрытие остановит только службу", "session", sid)
	}
	r.system("Терминал %s открыт: %s, %s", sid, p.GetUnixUser(), lang)
	if err := r.send(helperrpc.Response{Kind: helperrpc.KindTerminal, FD: master, Terminal: &helperrpc.TerminalInfo{
		SessionID: sid, UnixUser: p.GetUnixUser(), Lang: lang, IdleTimeoutSec: p.GetIdleTimeoutSec()}}); err != nil {
		_ = t.Units.Stop(context.WithoutCancel(ctx), sid)
		return r.failed(CodeApplyFailed, "PTY агенту не передан: "+err.Error())
	}
	reason := e.waitTerminal(ctx, t, sid, s)
	res := r.succeeded("Терминал закрыт: " + reason.String())
	res.Data = &agentv1.OperationResult_TerminalOpen{TerminalOpen: &agentv1.TerminalSessionResult{
		Reason: reason, Lang: lang, StartedAtMs: started.UnixMilli()}}
	return res
}

// waitTerminal — до конца сеанса: оболочка вышла, закрыт агентом или клиентом, срок продления или предельный
// срок вышел, агент закрыл соединение. Служба останавливается во всех случаях, кроме выхода оболочки.
func (e *Executor) waitTerminal(ctx context.Context, t *Terminals, sid string, s *termSession) agentv1.TerminalEndReason {
	poll := t.Poll
	if poll <= 0 {
		poll = terminalPoll
	}
	tick := time.NewTicker(poll)
	defer tick.Stop()
	gone := helperrpc.Disconnected(ctx)
	// stop — служба и сеанс logind со всеми процессами (в том числе запущенными в фоне из терминала).
	stop := func(reason agentv1.TerminalEndReason) agentv1.TerminalEndReason {
		sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		if err := t.Units.Stop(sctx, sid); err != nil {
			e.log().Error("helper: служба терминала не остановлена", "session", sid, "err", err)
		}
		if err := t.Units.TerminateSession(sctx, s.login); err != nil {
			e.log().Error("helper: сеанс logind терминала не закрыт", "session", sid, "login", s.login, "err", err)
		}
		return reason
	}
	for {
		select {
		case reason := <-s.closeCh:
			return stop(reason)
		case <-gone:
			return stop(agentv1.TerminalEndReason_TERMINAL_END_REASON_AGENT_RESTART)
		case <-ctx.Done():
			return stop(agentv1.TerminalEndReason_TERMINAL_END_REASON_ERROR)
		case <-tick.C:
		}
		now := e.now()
		t.mu.Lock()
		renew, hard := s.renewUntil, s.hardUntil
		t.mu.Unlock()
		switch {
		case !now.Before(hard):
			return stop(agentv1.TerminalEndReason_TERMINAL_END_REASON_MAX_DURATION)
		case !now.Before(renew):
			return stop(agentv1.TerminalEndReason_TERMINAL_END_REASON_NOT_RENEWED)
		}
		if active, err := t.Units.Active(ctx, sid); err == nil && !active {
			// Оболочка вышла, но её фоновые процессы могли остаться в сеансе — закрываем и его.
			return stop(agentv1.TerminalEndReason_TERMINAL_END_REASON_SHELL_EXIT)
		}
	}
}

// TerminalClose — закрыть сеанс (агент: простой, клиент закрыл; доступ — отзыв). Сужение: подпись не нужна.
func (e *Executor) TerminalClose(sid string, reason agentv1.TerminalEndReason) bool {
	if e.Terminals == nil {
		return false
	}
	t := e.Terminals
	t.mu.Lock()
	s, ok := t.sessions[strings.ToLower(sid)]
	t.mu.Unlock()
	if !ok {
		return false
	}
	if reason == agentv1.TerminalEndReason_TERMINAL_END_REASON_UNSPECIFIED {
		reason = agentv1.TerminalEndReason_TERMINAL_END_REASON_CLIENT
	}
	select {
	case s.closeCh <- reason:
	default:
	}
	return true
}

// ErrRenew — продление отклонено.
var ErrRenew = errors.New(CodeRenewBad)

// TerminalRenew — SignedTerminalRenew от worker: подпись панели, сервер, сроки, одноразовый nonce, сеанс открыт
// этой операцией. Срок продления — min(now + RenewWindow, предельный срок).
func (e *Executor) TerminalRenew(raw []byte) error {
	if e.Terminals == nil || e.Checker == nil {
		return ErrRenew
	}
	var sr agentv1.SignedTerminalRenew
	if err := proto.Unmarshal(raw, &sr); err != nil {
		return fmt.Errorf("%w: разбор", ErrRenew)
	}
	if err := verify.Signature(e.Checker.PanelKeys(), sr.GetKeyId(), ContextRenew, sr.GetBody(), sr.GetSignature()); err != nil {
		return fmt.Errorf("%w: подпись", ErrRenew)
	}
	var b agentv1.TerminalRenewBody
	if err := proto.Unmarshal(sr.GetBody(), &b); err != nil {
		return fmt.Errorf("%w: тело", ErrRenew)
	}
	now := e.now()
	notAfter, issued := time.UnixMilli(b.GetNotAfterMs()), time.UnixMilli(b.GetIssuedAtMs())
	switch {
	case b.GetServerId() != e.Checker.ServerID:
		return fmt.Errorf("%w: чужой сервер", ErrRenew)
	case !notAfter.After(now) || notAfter.Sub(now) > opcheck.MaxNotAfter+opcheck.ClockTolerance:
		return fmt.Errorf("%w: срок", ErrRenew)
	case issued.After(now.Add(opcheck.ClockTolerance)) || len(b.GetNonce()) != opcheck.NonceSize:
		return fmt.Errorf("%w: выдача или nonce", ErrRenew)
	}
	t := e.Terminals
	sid := strings.ToLower(b.GetSessionId())
	t.mu.Lock()
	s, ok := t.sessions[sid]
	t.mu.Unlock()
	if !ok || s.opID != strings.ToLower(b.GetOperationId()) {
		return fmt.Errorf("%w: сеанса нет", ErrRenew)
	}
	// Каждое продление — один раз: Record допускает повтор того же номера за тем же ключом, поэтому сначала Check.
	if e.Checker.Nonces.Check(b.GetNonce(), "renew:"+sid) != nonce.Fresh {
		return fmt.Errorf("%w: повтор", ErrRenew)
	}
	if err := e.Checker.Nonces.Record(b.GetNonce(), "renew:"+sid, notAfter); err != nil {
		return fmt.Errorf("%w: повтор", ErrRenew)
	}
	t.mu.Lock()
	until := now.Add(RenewWindow)
	if until.After(s.hardUntil) {
		until = s.hardUntil
	}
	if until.After(s.renewUntil) {
		s.renewUntil = until
	}
	t.mu.Unlock()
	return nil
}

// StopOrphanTerminals — старт помощника: службы терминалов без таймеров продления останавливаются.
func (e *Executor) StopOrphanTerminals(ctx context.Context) {
	if e.Terminals == nil {
		return
	}
	if err := e.Terminals.Units.StopAll(ctx); err != nil {
		e.log().Warn("helper: службы терминалов при старте", "err", err)
	}
}
