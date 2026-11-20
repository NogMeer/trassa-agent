// SPDX-License-Identifier: AGPL-3.0-only

package channel

import (
	"context"
	"os"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/helperrpc"
	"github.com/NogMeer/trassa-agent/internal/terminal"
)

// Терминал через помощник (E16, decisions 9.4): агент качает байты PTY, считает простой и держит квитанции;
// сроки продления и предельный срок — у помощника.
const (
	termChunk      = 32 << 10  // байтов вывода в кадре (кадр — до 64 КиБ данных)
	termWindow     = 256 << 10 // неподтверждённого вывода не больше: дальше чтение PTY ждёт квитанции
	termIdleCheck  = 10 * time.Second
	termMaxInFrame = 64 << 10
)

// TerminalHelper — помощник с терминалами (helperrpc.Client).
type TerminalHelper interface {
	ExecuteTerminal(ctx context.Context, signed []byte, onAck func(bool, string), onProgress func([]byte),
		onTerminal func(helperrpc.TerminalInfo, *os.File)) ([]byte, error)
	TerminalRenew(ctx context.Context, signed []byte) error
	TerminalClose(ctx context.Context, sessionID string, reason int32) error
}

// termBridge — один терминал: вывод PTY → кадры шлюзу (с буфером до квитанции), ввод шлюза → PTY.
type termBridge struct {
	a      *Agent
	h      TerminalHelper
	sid    string
	master *os.File
	idle   time.Duration

	mu       sync.Mutex
	cond     *sync.Cond
	outBuf   []byte // вывод, ещё не подтверждённый шлюзом
	outStart uint64 // смещение outBuf[0] в потоке
	inNext   uint64 // принято ввода от начала потока
	last     time.Time
	done     bool
}

func (a *Agent) terminalHelper() (TerminalHelper, bool) {
	h, ok := a.cfg.Helper.(TerminalHelper)
	return h, ok
}

func (a *Agent) currentConn() *conn {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.cur
}

// setConn — соединение сеанса шлюза для кадров терминала; новое соединение получает неподтверждённый вывод
// заново (шлюз склеит по смещению).
func (a *Agent) setConn(c *conn) {
	a.mu.Lock()
	a.cur = c
	bridges := make([]*termBridge, 0, len(a.terms))
	for _, b := range a.terms {
		bridges = append(bridges, b)
	}
	a.mu.Unlock()
	if c == nil {
		return
	}
	for _, b := range bridges {
		b.resend(c)
	}
}

func (b *termBridge) send(c *conn, f *agentv1.TerminalServerFrame) {
	if c == nil {
		return
	}
	f.SessionId = b.sid
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, _ = c.send(ctx, &agentv1.AgentMessage{Payload: &agentv1.AgentMessage_Terminal{Terminal: f}})
}

func (b *termBridge) resend(c *conn) {
	b.mu.Lock()
	data, off := append([]byte(nil), b.outBuf...), b.outStart
	b.mu.Unlock()
	for len(data) > 0 {
		n := min(len(data), termChunk)
		b.send(c, &agentv1.TerminalServerFrame{Frame: &agentv1.TerminalServerFrame_Output{Output: &agentv1.TerminalData{Offset: off, Data: data[:n]}}})
		data, off = data[n:], off+uint64(n)
	}
}

// readLoop — вывод PTY шлюзу; конец чтения (оболочка вышла, EIO) — кадр exit.
func (b *termBridge) readLoop() {
	buf := make([]byte, termChunk)
	for {
		b.mu.Lock()
		for len(b.outBuf) >= termWindow && !b.done {
			b.cond.Wait()
		}
		done := b.done
		b.mu.Unlock()
		if done {
			return
		}
		n, err := b.master.Read(buf)
		if n > 0 {
			b.mu.Lock()
			off := b.outStart + uint64(len(b.outBuf))
			b.outBuf = append(b.outBuf, buf[:n]...)
			b.last = b.a.cfg.Now()
			b.mu.Unlock()
			b.send(b.a.currentConn(), &agentv1.TerminalServerFrame{Frame: &agentv1.TerminalServerFrame_Output{Output: &agentv1.TerminalData{
				Offset: off, Data: append([]byte(nil), buf[:n]...)}}})
		}
		if err != nil {
			b.send(b.a.currentConn(), &agentv1.TerminalServerFrame{Frame: &agentv1.TerminalServerFrame_Exit{Exit: &agentv1.TerminalExit{
				Reason: agentv1.TerminalEndReason_TERMINAL_END_REASON_SHELL_EXIT}}})
			return
		}
	}
}

// idleLoop — простой дольше idle_timeout: помощник закрывает терминал.
func (b *termBridge) idleLoop(ctx context.Context) {
	t := time.NewTicker(termIdleCheck)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		b.mu.Lock()
		idle, done := b.a.cfg.Now().Sub(b.last) > b.idle, b.done
		b.mu.Unlock()
		if done {
			return
		}
		if idle {
			_ = b.h.TerminalClose(ctx, b.sid, int32(agentv1.TerminalEndReason_TERMINAL_END_REASON_IDLE))
			return
		}
	}
}

// frame — кадр шлюза для этого терминала.
func (b *termBridge) frame(ctx context.Context, f *agentv1.TerminalClientFrame) {
	switch x := f.GetFrame().(type) {
	case *agentv1.TerminalClientFrame_Input:
		d := x.Input
		if len(d.GetData()) > termMaxInFrame {
			return
		}
		b.mu.Lock()
		off, next := d.GetOffset(), b.inNext
		data := d.GetData()
		// Повтор после обрыва: уже принятое пропускается; разрыв (шлюз потерял кусок) — ждём повтора.
		if off > next || off+uint64(len(data)) <= next {
			b.mu.Unlock()
			b.send(b.a.currentConn(), &agentv1.TerminalServerFrame{Frame: &agentv1.TerminalServerFrame_Ack{Ack: &agentv1.TerminalAck{Received: next}}})
			return
		}
		data = data[next-off:]
		b.mu.Unlock()
		w, err := b.master.Write(data)
		b.mu.Lock()
		b.inNext += uint64(w)
		b.last = b.a.cfg.Now()
		recv := b.inNext
		b.mu.Unlock()
		b.send(b.a.currentConn(), &agentv1.TerminalServerFrame{Frame: &agentv1.TerminalServerFrame_Ack{Ack: &agentv1.TerminalAck{Received: recv}}})
		if err != nil {
			b.a.cfg.Log.Warn("терминал: запись в PTY", "session", b.sid, "err", err)
		}
	case *agentv1.TerminalClientFrame_Resize:
		if err := terminal.SetSize(b.master, x.Resize.GetCols(), x.Resize.GetRows()); err != nil {
			b.a.cfg.Log.Debug("терминал: размер", "err", err)
		}
	case *agentv1.TerminalClientFrame_Ack:
		b.mu.Lock()
		if r := x.Ack.GetReceived(); r > b.outStart && r <= b.outStart+uint64(len(b.outBuf)) {
			b.outBuf = append([]byte(nil), b.outBuf[r-b.outStart:]...)
			b.outStart = r
			b.cond.Broadcast()
		}
		b.mu.Unlock()
	case *agentv1.TerminalClientFrame_Close:
		reason := x.Close.GetReason()
		if reason == agentv1.TerminalEndReason_TERMINAL_END_REASON_UNSPECIFIED {
			reason = agentv1.TerminalEndReason_TERMINAL_END_REASON_CLIENT
		}
		_ = b.h.TerminalClose(ctx, b.sid, int32(reason))
	}
}

// terminalFrame — кадр терминала от шлюза: в свой мост; чужой или закрытый сеанс — пропуск.
func (a *Agent) terminalFrame(ctx context.Context, f *agentv1.TerminalClientFrame) {
	a.mu.Lock()
	b := a.terms[f.GetSessionId()]
	a.mu.Unlock()
	if b != nil {
		b.frame(ctx, f)
	}
}

// terminalRenew — подписанное продление уходит помощнику: проверяет и сдвигает срок он.
func (a *Agent) terminalRenew(ctx context.Context, r *agentv1.SignedTerminalRenew) {
	h, ok := a.terminalHelper()
	if !ok {
		return
	}
	raw, err := proto.Marshal(r)
	if err != nil {
		return
	}
	if err := h.TerminalRenew(ctx, raw); err != nil {
		a.cfg.Log.Warn("терминал: продление отклонено помощником", "err", err)
	}
}

// openTerminal — помощник открыл терминал: мост, кадр ready, чтение PTY и учёт простоя.
func (a *Agent) openTerminal(ctx context.Context, h TerminalHelper, info helperrpc.TerminalInfo, master *os.File) *termBridge {
	b := &termBridge{a: a, h: h, sid: info.SessionID, master: master, idle: time.Duration(info.IdleTimeoutSec) * time.Second, last: a.cfg.Now()}
	b.cond = sync.NewCond(&b.mu)
	a.mu.Lock()
	if a.terms == nil {
		a.terms = map[string]*termBridge{}
	}
	a.terms[b.sid] = b
	a.mu.Unlock()
	b.send(a.currentConn(), &agentv1.TerminalServerFrame{Frame: &agentv1.TerminalServerFrame_Ready{Ready: &agentv1.TerminalReady{
		UnixUser: info.UnixUser, Lang: info.Lang}}})
	go b.readLoop()
	go b.idleLoop(ctx)
	return b
}

// close — терминал закрыт помощником: мост снимается, PTY закрывается; возвращает байтов вывода всего.
func (b *termBridge) close() uint64 {
	b.a.mu.Lock()
	delete(b.a.terms, b.sid)
	b.a.mu.Unlock()
	b.mu.Lock()
	b.done = true
	total := b.outStart + uint64(len(b.outBuf))
	b.cond.Broadcast()
	b.mu.Unlock()
	b.master.Close()
	return total
}

// runTerminal — terminal.open: соединение с помощником живёт весь сеанс (его закрытие — конец терминала); итог
// дополняется числом байтов вывода, которое видит только агент.
func (a *Agent) runTerminal(ctx context.Context, h TerminalHelper, raw []byte, ack func(bool, string), progress func([]byte)) ([]byte, error) {
	var b *termBridge
	res, err := h.ExecuteTerminal(ctx, raw, ack, progress, func(info helperrpc.TerminalInfo, master *os.File) {
		if b != nil { // второй дескриптор в одной операции — ошибка помощника
			master.Close()
			return
		}
		b = a.openTerminal(ctx, h, info, master)
	})
	if b == nil {
		return res, err
	}
	total := b.close()
	if res == nil {
		return res, err
	}
	var r agentv1.OperationResult
	if proto.Unmarshal(res, &r) == nil && r.GetTerminalOpen() != nil {
		r.GetTerminalOpen().BytesOut = total
		if out, merr := proto.Marshal(&r); merr == nil {
			res = out
		}
	}
	return res, err
}
