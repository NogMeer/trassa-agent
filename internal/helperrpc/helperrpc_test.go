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
