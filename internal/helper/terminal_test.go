// SPDX-License-Identifier: AGPL-3.0-only

package helper

import (
	"context"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/helperrpc"
	"github.com/NogMeer/trassa-agent/internal/ops"
	"github.com/NogMeer/trassa-agent/internal/terminal"
)

type fakeUnits struct {
	mu         sync.Mutex
	started    []terminal.Shell
	stopped    []string
	exited     map[string]bool
	terminated []string
}

func (u *fakeUnits) Session(_ context.Context, sid string) (string, error) {
	return "s-" + sid[len(sid)-2:], nil
}

func (u *fakeUnits) TerminateSession(_ context.Context, id string) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.terminated = append(u.terminated, id)
	return nil
}

func (u *fakeUnits) Start(_ context.Context, s terminal.Shell, slave *os.File) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if slave == nil {
		return os.ErrInvalid
	}
	u.started = append(u.started, s)
	return nil
}

func (u *fakeUnits) Active(_ context.Context, sid string) (bool, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return !u.exited[sid], nil
}

func (u *fakeUnits) Stop(_ context.Context, sid string) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.stopped = append(u.stopped, sid)
	return nil
}

func (u *fakeUnits) StopAll(context.Context) error { return nil }

func (f *fixture) enableTerminals(t *testing.T) *fakeUnits {
	t.Helper()
	f.enableAccess(t)
	units := &fakeUnits{exited: map[string]bool{}}
	f.e.Terminals = &Terminals{Units: units, Poll: 5 * time.Millisecond,
		OpenPTY: func() (*os.File, *os.File, int, error) {
			r, w, err := os.Pipe()
			return r, w, 3, err
		},
		SetSize: func(*os.File, uint32, uint32) error { return nil },
		Locales: func(context.Context) []string { return []string{"C.utf8", "en_US.utf8"} },
	}
	return units
}

func (f *fixture) terminalBody(user, sid string) *agentv1.OperationBody {
	b := f.body(ops.TypeTerminalOpen, &agentv1.OperationParams{Params: &agentv1.OperationParams_TerminalOpen{TerminalOpen: &agentv1.TerminalOpenParams{
		SessionId: sid, UnixUser: user, Cols: 80, Rows: 24, IdleTimeoutSec: 600, MaxDurationSec: 3600, EnvLang: "ru_RU.UTF-8"}}})
	b.NotAfterMs = b.GetIssuedAtMs() + 60_000
	return b
}

// execAsync — Execute в фоне: кадр terminal с дескриптором приходит до итога.
func (f *fixture) execAsync(raw []byte) (<-chan helperrpc.Response, <-chan *agentv1.OperationResult) {
	term := make(chan helperrpc.Response, 1)
	done := make(chan *agentv1.OperationResult, 1)
	go func() {
		var res *agentv1.OperationResult
		f.e.Execute(context.Background(), raw, func(r helperrpc.Response) error {
			switch r.Kind {
			case helperrpc.KindTerminal:
				term <- r
			case helperrpc.KindResult:
				res = &agentv1.OperationResult{}
				_ = proto.Unmarshal(r.Result, res)
			}
			return nil
		})
		done <- res
	}()
	return term, done
}

func TestTerminalOpenRenewExpire(t *testing.T) {
	f := newFixture(t)
	units := f.enableTerminals(t)
	// Не пользователь доступа — отказ (root отклоняется ещё проверкой 6).
	o := f.exec(sealed(f.terminalBody("ops", "01a1f4b6-f2f2-7e66-85b4-0000000000e1")))
	if o.result.GetErrorCode() != "ACCESS_USER_NOT_MANAGED" {
		t.Fatalf("без доступа: %+v", o.result)
	}
	expectReject(t, f, sealed(f.terminalBody("root", "01a1f4b6-f2f2-7e66-85b4-0000000000e2")), "ACCESS_UNIX_USER_FORBIDDEN")
	long := f.terminalBody("ops", "01a1f4b6-f2f2-7e66-85b4-0000000000e3")
	long.NotAfterMs = long.GetIssuedAtMs() + 5*60_000
	expectReject(t, f, sealed(long), ops.CodeParamsInvalid)
	// Пользователь доступа.
	_ = os.MkdirAll(f.e.Access.Root+"/etc/trassa/access", 0o700)
	_ = os.WriteFile(f.e.Access.Root+"/etc/trassa/access/state.json", []byte(`{"users":{"ops":{"shell":"/bin/bash"}}}`), 0o600)
	sid := "01a1f4b6-f2f2-7e66-85b4-0000000000e4"
	b := f.terminalBody("ops", sid)
	term, done := f.execAsync(sealed(b))
	var fr helperrpc.Response
	select {
	case fr = <-term:
	case <-time.After(5 * time.Second):
		t.Fatal("нет кадра terminal")
	}
	if fr.FD == nil || fr.Terminal.SessionID != sid || fr.Terminal.Lang != "en_US.UTF-8" && fr.Terminal.Lang != "C.UTF-8" {
		t.Fatalf("%+v", fr.Terminal)
	}
	if s := units.started[0]; s.User != "ops" || s.Shell != "/bin/bash" || s.Term != "xterm-256color" || s.MaxRun != time.Hour {
		t.Fatalf("%+v", s)
	}
	// Продление: верная подпись — да; повтор того же nonce, чужой сеанс, контекст операции — нет.
	renew := func(sid, op string, nonce []byte, ctx string) []byte {
		body, _ := proto.Marshal(&agentv1.TerminalRenewBody{OperationId: op, ServerId: serverID, SessionId: sid, Nonce: nonce,
			IssuedAtMs: f.clock.Now().UnixMilli(), NotAfterMs: f.clock.Now().Add(time.Minute).UnixMilli()})
		sig, k := signWith(panelPriv, keyID, ctx, body)
		raw, _ := proto.Marshal(&agentv1.SignedTerminalRenew{Body: body, Signature: sig, KeyId: k})
		return raw
	}
	n := newNonce()
	if err := f.e.TerminalRenew(renew(sid, b.GetOperationId(), n, ContextRenew)); err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string][]byte{
		"повтор nonce":      renew(sid, b.GetOperationId(), n, ContextRenew),
		"чужая операция":    renew(sid, "01a1f4b6-f2f2-7e66-85b4-000000000999", newNonce(), ContextRenew),
		"контекст операции": renew(sid, b.GetOperationId(), newNonce(), "trassa-operation-v1"),
		"нет такого сеанса": renew("01a1f4b6-f2f2-7e66-85b4-0000000000ff", b.GetOperationId(), newNonce(), ContextRenew),
	} {
		if err := f.e.TerminalRenew(raw); err == nil {
			t.Errorf("%s: продление принято", name)
		}
	}
	// Срок продления вышел — служба остановлена, итог NOT_RENEWED.
	f.clock.Add(RenewWindow + time.Second)
	select {
	case res := <-done:
		if res.GetTerminalOpen().GetReason() != agentv1.TerminalEndReason_TERMINAL_END_REASON_NOT_RENEWED {
			t.Fatalf("%+v", res)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("терминал не закрылся по сроку продления")
	}
	if strings.Join(units.stopped, ",") != sid || strings.Join(units.terminated, ",") != "s-e4" {
		t.Fatalf("остановлены: %v, сеансы logind: %v", units.stopped, units.terminated)
	}
	// Закрытие агентом (простой) и выход оболочки.
	sid2 := "01a1f4b6-f2f2-7e66-85b4-0000000000e5"
	term, done = f.execAsync(sealed(f.terminalBody("ops", sid2)))
	<-term
	if !f.e.TerminalClose(sid2, agentv1.TerminalEndReason_TERMINAL_END_REASON_IDLE) {
		t.Fatal("сеанс не найден")
	}
	if res := <-done; res.GetTerminalOpen().GetReason() != agentv1.TerminalEndReason_TERMINAL_END_REASON_IDLE {
		t.Fatalf("%+v", res)
	}
	sid3 := "01a1f4b6-f2f2-7e66-85b4-0000000000e6"
	term, done = f.execAsync(sealed(f.terminalBody("ops", sid3)))
	<-term
	units.mu.Lock()
	units.exited[sid3] = true
	units.mu.Unlock()
	if res := <-done; res.GetTerminalOpen().GetReason() != agentv1.TerminalEndReason_TERMINAL_END_REASON_SHELL_EXIT {
		t.Fatalf("%+v", res)
	}
	// Выход оболочки тоже закрывает сеанс logind: фоновые процессы терминала не остаются.
	units.mu.Lock()
	defer units.mu.Unlock()
	if strings.Join(units.terminated, ",") != "s-e4,s-e5,s-e6" {
		t.Fatalf("сеансы logind: %v", units.terminated)
	}
	// Отзыв доступа (signed access.sessions.terminate) закрывает открытый терминал.
}

func TestTerminateClosesHelperTerminal(t *testing.T) {
	f := newFixture(t)
	f.enableTerminals(t)
	_ = os.MkdirAll(f.e.Access.Root+"/etc/trassa/access", 0o700)
	_ = os.WriteFile(f.e.Access.Root+"/etc/trassa/access/state.json", []byte(`{"users":{"ops":{}}}`), 0o600)
	sid := "01a1f4b6-f2f2-7e66-85b4-0000000000e7"
	term, done := f.execAsync(sealed(f.terminalBody("ops", sid)))
	<-term
	tb := f.body(ops.TypeAccessSessionsTerminate, &agentv1.OperationParams{Params: &agentv1.OperationParams_AccessSessionsTerminate{
		AccessSessionsTerminate: &agentv1.AccessSessionsTerminateParams{SessionIds: []string{sid, "01a1f4b6-f2f2-7e66-85b4-0000000000ee"}}}})
	o := f.exec(sealed(tb))
	if r := o.result.GetAccessSessionsTerminate(); strings.Join(r.GetTerminated(), ",") != sid || len(r.GetNotFound()) != 1 {
		t.Fatalf("%+v", o.result)
	}
	if res := <-done; res.GetTerminalOpen().GetReason() != agentv1.TerminalEndReason_TERMINAL_END_REASON_REVOKED {
		t.Fatalf("%+v", res)
	}
}
