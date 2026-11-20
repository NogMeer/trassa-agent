// SPDX-License-Identifier: AGPL-3.0-only

package channel

import (
	"context"
	"io"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/helperrpc"
)

type termHelper struct {
	mu     sync.Mutex
	closed []int32
}

func (h *termHelper) ExecuteTerminal(context.Context, []byte, func(bool, string), func([]byte), func(helperrpc.TerminalInfo, *os.File)) ([]byte, error) {
	return nil, nil
}
func (h *termHelper) TerminalRenew(context.Context, []byte) error { return nil }
func (h *termHelper) TerminalClose(_ context.Context, _ string, reason int32) error {
	h.mu.Lock()
	h.closed = append(h.closed, reason)
	h.mu.Unlock()
	return nil
}

// pair — двусторонний «PTY»: master у моста, peer — сторона оболочки.
func pair(t *testing.T) (*os.File, *os.File) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	return os.NewFile(uintptr(fds[0]), "master"), os.NewFile(uintptr(fds[1]), "peer")
}

func TestTerminalBridge(t *testing.T) {
	a := &Agent{cfg: Config{Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: time.Now}}
	h := &termHelper{}
	master, peer := pair(t)
	defer peer.Close()
	b := a.openTerminal(context.Background(), h, helperrpc.TerminalInfo{SessionID: "s1", IdleTimeoutSec: 600}, master)
	in := func(off uint64, s string) {
		a.terminalFrame(context.Background(), &agentv1.TerminalClientFrame{SessionId: "s1",
			Frame: &agentv1.TerminalClientFrame_Input{Input: &agentv1.TerminalData{Offset: off, Data: []byte(s)}}})
	}
	in(0, "ls")
	in(0, "ls")    // повтор после обрыва — пропуск
	in(1, "s -l")  // частичный повтор — только новое
	in(10, "late") // разрыв — ждём повтора
	_ = peer.SetReadDeadline(time.Now().Add(2 * time.Second))
	got := make([]byte, 16)
	n, _ := peer.Read(got)
	if string(got[:n]) != "ls -l" || b.inNext != 5 {
		t.Fatalf("ввод %q, принято %d", got[:n], b.inNext)
	}
	// Вывод: окно 256 КиБ без квитанции, дальше чтение ждёт.
	go func() { _, _ = peer.Write(make([]byte, 400<<10)) }()
	deadline := time.Now().Add(3 * time.Second)
	for {
		b.mu.Lock()
		l := len(b.outBuf)
		b.mu.Unlock()
		if l >= termWindow || time.Now().After(deadline) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	b.mu.Lock()
	if l := len(b.outBuf); l < termWindow || l > termWindow+termChunk {
		b.mu.Unlock()
		t.Fatalf("неподтверждённого вывода %d", l)
	}
	b.mu.Unlock()
	a.terminalFrame(context.Background(), &agentv1.TerminalClientFrame{SessionId: "s1",
		Frame: &agentv1.TerminalClientFrame_Ack{Ack: &agentv1.TerminalAck{Received: 200 << 10}}})
	b.mu.Lock()
	start := b.outStart
	b.mu.Unlock()
	if start != 200<<10 {
		t.Fatalf("квитанция: начало буфера %d", start)
	}
	// Квитанция вне буфера не двигает его.
	a.terminalFrame(context.Background(), &agentv1.TerminalClientFrame{SessionId: "s1",
		Frame: &agentv1.TerminalClientFrame_Ack{Ack: &agentv1.TerminalAck{Received: 10 << 20}}})
	b.mu.Lock()
	if b.outStart != 200<<10 {
		t.Fatalf("квитанция дальше вывода принята: %d", b.outStart)
	}
	b.mu.Unlock()
	a.terminalFrame(context.Background(), &agentv1.TerminalClientFrame{SessionId: "s1",
		Frame: &agentv1.TerminalClientFrame_Close{Close: &agentv1.TerminalClose{}}})
	h.mu.Lock()
	if len(h.closed) != 1 || h.closed[0] != int32(agentv1.TerminalEndReason_TERMINAL_END_REASON_CLIENT) {
		t.Fatalf("закрытие: %v", h.closed)
	}
	h.mu.Unlock()
	if total := b.close(); total < 200<<10 {
		t.Fatalf("байтов вывода %d", total)
	}
	a.mu.Lock()
	if len(a.terms) != 0 {
		t.Fatal("мост не снят")
	}
	a.mu.Unlock()
}
