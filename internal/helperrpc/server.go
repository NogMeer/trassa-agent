// SPDX-License-Identifier: AGPL-3.0-only

package helperrpc

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// Handler обрабатывает запрос; send пишет кадр ответа.
type Handler interface {
	Serve(ctx context.Context, req Request, send func(Response) error)
}

// Server — сокет помощника.
type Server struct {
	// AllowedUID — uid пользователя trassa. Запросы от любого другого uid (в том числе root) отклоняются.
	AllowedUID int
	Handler    Handler
	Log        *slog.Logger
	// RequestTimeout — время на чтение запроса.
	RequestTimeout time.Duration

	wg sync.WaitGroup
}

// Listen создаёт сокет с правами 0660 и группой gid. Старый файл сокета удаляется, но только если это сокет.
func Listen(path string, gid int) (*net.UnixListener, error) {
	if st, err := os.Lstat(path); err == nil {
		if st.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("%s существует и это не сокет", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	}
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	l.SetUnlinkOnClose(true)
	// Права ставятся сразу после bind; родительский каталог /run/trassa — 0750 root:trassa, поэтому окна, когда
	// сокет доступен посторонним, нет.
	if err := os.Chmod(path, 0o660); err != nil {
		l.Close()
		return nil, err
	}
	if gid >= 0 {
		if err := os.Chown(path, 0, gid); err != nil && os.Geteuid() == 0 {
			l.Close()
			return nil, err
		}
	}
	return l, nil
}

// Serve принимает соединения до отмены ctx.
func (s *Server) Serve(ctx context.Context, l *net.UnixListener) error {
	if s.AllowedUID < 0 {
		return errors.New("helperrpc: uid агента не задан")
	}
	go func() {
		<-ctx.Done()
		l.Close()
	}()
	for {
		c, err := l.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				s.wg.Wait()
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handle(ctx, c)
		}()
	}
}

func (s *Server) logger() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

// CheckPeer — проверка 7: uid вызывающего равен uid пользователя trassa. Ошибка getsockopt — отказ.
func CheckPeer(c *net.UnixConn, allowed int) error {
	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}
	uid := -1
	var credErr error
	if err := raw.Control(func(fd uintptr) { uid, credErr = peerUID(fd) }); err != nil {
		return err
	}
	if credErr != nil {
		return credErr
	}
	if uid != allowed {
		return fmt.Errorf("uid %d не равен %d", uid, allowed)
	}
	return nil
}

func (s *Server) handle(ctx context.Context, c *net.UnixConn) {
	defer c.Close()
	if err := CheckPeer(c, s.AllowedUID); err != nil {
		s.logger().Warn("helper: чужой процесс на сокете", "err", err)
		_ = WriteFrame(c, Response{Kind: KindError, Code: CodePeerForbidden})
		return
	}
	timeout := s.RequestTimeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	_ = c.SetReadDeadline(time.Now().Add(timeout))
	var req Request
	if err := ReadFrame(c, &req); err != nil {
		_ = WriteFrame(c, Response{Kind: KindError, Code: "BAD_REQUEST"})
		return
	}
	_ = c.SetReadDeadline(time.Time{})
	// Агент после запроса ничего не пишет: чтение вернётся, только когда он закроет соединение. Обработчики,
	// которым это важно (терминал), видят это через Disconnected(ctx).
	gone := make(chan struct{})
	go func() {
		var b [1]byte
		_, _ = c.Read(b[:])
		close(gone)
	}()
	ctx = context.WithValue(ctx, goneKey{}, (<-chan struct{})(gone))
	var mu sync.Mutex
	s.Handler.Serve(ctx, req, func(r Response) error {
		mu.Lock()
		defer mu.Unlock()
		_ = c.SetWriteDeadline(time.Now().Add(30 * time.Second))
		if r.FD == nil {
			return WriteFrame(c, r)
		}
		b, err := EncodeFrame(r)
		if err != nil {
			return err
		}
		// Дескриптор привязан к первому байту кадра (SCM_RIGHTS).
		n, _, err := c.WriteMsgUnix(b, unix.UnixRights(int(r.FD.Fd())), nil)
		if err == nil && n != len(b) {
			err = errors.New("helperrpc: кадр с дескриптором записан не целиком")
		}
		return err
	})
}

type goneKey struct{}

// Disconnected — канал закрывается, когда агент закрыл соединение этого запроса (nil — вне сервера).
func Disconnected(ctx context.Context) <-chan struct{} {
	ch, _ := ctx.Value(goneKey{}).(<-chan struct{})
	return ch
}
