// SPDX-License-Identifier: AGPL-3.0-only

package helperrpc

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type echo struct{}

func (echo) Serve(_ context.Context, req Request, send func(Response) error) {
	_ = send(Response{Kind: KindHello, HelperVersion: "1.0.0", Capabilities: []string{"system.info"}})
}

// Короткий путь: у Unix-сокета предел длины пути ~104 байта, а t.TempDir() на macOS длинный.
func sockPath(t *testing.T) string {
	dir, err := os.MkdirTemp("/tmp", "trh")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, "h.sock")
}

func startServer(t *testing.T, allowed int) string {
	t.Helper()
	p := sockPath(t)
	l, err := Listen(p, -1)
	if err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(p)
	if st.Mode().Perm() != 0o660 {
		t.Fatalf("права сокета %v", st.Mode().Perm())
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = (&Server{AllowedUID: allowed, Handler: echo{}}).Serve(ctx, l)
		close(done)
	}()
	t.Cleanup(func() { cancel(); <-done })
	return p
}

// Проверка 7: свой uid проходит по SO_PEERCRED/LOCAL_PEERCRED.
func TestPeerAllowed(t *testing.T) {
	p := startServer(t, os.Getuid())
	v, caps, err := (&Client{Path: p, Timeout: 5 * time.Second}).Hello(context.Background())
	if err != nil || v != "1.0.0" || len(caps) != 1 {
		t.Fatalf("hello: %v %v %v", v, caps, err)
	}
}

// Проверка 7: процесс с другим uid получает PEER_FORBIDDEN до чтения запроса.
func TestPeerForbidden(t *testing.T) {
	p := startServer(t, os.Getuid()+1)
	_, _, err := (&Client{Path: p, Timeout: 5 * time.Second}).Hello(context.Background())
	var re *RemoteError
	if !errors.As(err, &re) || re.Code != CodePeerForbidden {
		t.Fatalf("ждали PEER_FORBIDDEN, получили %v", err)
	}
}

func TestListenRefusesNonSocket(t *testing.T) {
	p := sockPath(t)
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(p, -1); err == nil {
		t.Fatal("обычный файл на месте сокета удалён")
	}
}

func TestFrameLimit(t *testing.T) {
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], MaxFrame+1)
	var v Request
	if err := ReadFrame(bytes.NewReader(hdr[:]), &v); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("кадр больше предела: %v", err)
	}
	var buf bytes.Buffer
	if err := WriteFrame(&buf, Request{Method: MethodHello}); err != nil {
		t.Fatal(err)
	}
	if err := ReadFrame(&buf, &v); err != nil || v.Method != MethodHello {
		t.Fatalf("круг: %v %v", v, err)
	}
}

// termServer — Execute отвечает кадром terminal с дескриптором (концом канала) и ждёт закрытия соединения
// агентом (Disconnected), затем отдаёт итог.
type termServer struct{ disconnected chan struct{} }

func (s *termServer) Serve(ctx context.Context, req Request, send func(Response) error) {
	r, w, _ := os.Pipe()
	defer r.Close()
	defer w.Close()
	_, _ = w.Write([]byte("hello from pty"))
	_ = send(Response{Kind: KindAck, Accepted: true})
	_ = send(Response{Kind: KindTerminal, FD: r, Terminal: &TerminalInfo{SessionID: "s1", UnixUser: "ops", Lang: "C.UTF-8"}})
	select {
	case <-Disconnected(ctx):
		close(s.disconnected)
	case <-time.After(200 * time.Millisecond):
		_ = send(Response{Kind: KindResult, Result: []byte("done")})
	}
}

func TestTerminalFDPassing(t *testing.T) {
	p := sockPath(t)
	l, err := Listen(p, -1)
	if err != nil {
		t.Fatal(err)
	}
	srv := &termServer{disconnected: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = (&Server{AllowedUID: os.Getuid(), Handler: srv}).Serve(ctx, l) }()
	t.Cleanup(cancel)
	var got string
	res, err := (&Client{Path: p}).ExecuteTerminal(context.Background(), []byte("op"), func(bool, string) {}, nil,
		func(info TerminalInfo, f *os.File) {
			defer f.Close()
			b := make([]byte, 64)
			n, _ := f.Read(b)
			got = info.SessionID + ":" + string(b[:n])
		})
	if err != nil || string(res) != "done" || got != "s1:hello from pty" {
		t.Fatalf("%q %v %q", res, err, got)
	}
	// Агент закрыл соединение посреди сеанса — обработчик это видит.
	cctx, ccancel := context.WithCancel(context.Background())
	go func() {
		_, _ = (&Client{Path: p}).ExecuteTerminal(cctx, []byte("op"), func(bool, string) {}, nil, func(_ TerminalInfo, f *os.File) {
			f.Close()
			ccancel()
		})
	}()
	select {
	case <-srv.disconnected:
	case <-time.After(5 * time.Second):
		t.Fatal("обработчик не увидел закрытия соединения")
	}
}
