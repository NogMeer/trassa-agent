// SPDX-License-Identifier: AGPL-3.0-only

package helperrpc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// Client — сторона агента.
type Client struct {
	Path string
	// Timeout — предел на весь запрос, кроме Execute (там — ctx).
	Timeout time.Duration

	mu     sync.Mutex
	encPub []byte
	encID  string
}

// RemoteError — помощник ответил кадром error.
type RemoteError struct{ Code string }

func (e *RemoteError) Error() string { return "helper: " + e.Code }

// ErrNoResult — помощник закрыл соединение без итога.
var ErrNoResult = errors.New("helper: соединение закрыто без итога")

func (c *Client) dial(ctx context.Context) (*net.UnixConn, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", c.Path)
	if err != nil {
		return nil, err
	}
	uc := conn.(*net.UnixConn)
	if dl, ok := ctx.Deadline(); ok {
		_ = uc.SetDeadline(dl)
	}
	go func() {
		<-ctx.Done()
		_ = uc.SetDeadline(time.Now())
	}()
	return uc, nil
}

func (c *Client) call(ctx context.Context, req Request, want string) (Response, error) {
	if c.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.Timeout)
		defer cancel()
	}
	conn, err := c.dial(ctx)
	if err != nil {
		return Response{}, err
	}
	defer conn.Close()
	if err := writeRequest(conn, req); err != nil {
		return Response{}, err
	}
	var r Response
	if err := ReadFrame(conn, &r); err != nil {
		return Response{}, err
	}
	if r.Kind == KindError {
		return r, &RemoteError{Code: r.Code}
	}
	if r.Kind != want {
		return r, fmt.Errorf("helper: ждали %s, пришло %s", want, r.Kind)
	}
	return r, nil
}

// Hello — версия помощника и зашитый список типов. Ключ шифрования запоминается для EncryptionKey.
func (c *Client) Hello(ctx context.Context) (version string, capabilities []string, err error) {
	r, err := c.call(ctx, Request{Method: MethodHello}, KindHello)
	if err == nil {
		c.mu.Lock()
		c.encPub, c.encID = r.EncryptionPublicKey, r.EncryptionKeyID
		c.mu.Unlock()
	}
	return r.HelperVersion, r.Capabilities, err
}

// EncryptionKey — ключ X25519 помощника из последнего Hello (для Hello агента шлюзу).
func (c *Client) EncryptionKey() ([]byte, string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.encPub, c.encID
}

// Confirm передаёт SignedConfirm; в ответ — итог операции, который нужно отправить шлюзу.
func (c *Client) Confirm(ctx context.Context, signed []byte) ([]byte, error) {
	r, err := c.call(ctx, Request{Method: MethodConfirm, Signed: signed}, KindResult)
	return r.Result, err
}

// Reports — итоги, которые шлюз ещё не подтвердил (в том числе автооткаты без связи).
func (c *Client) Reports(ctx context.Context) ([][]byte, error) {
	r, err := c.call(ctx, Request{Method: MethodReports}, KindReports)
	return r.Results, err
}

// Reported — шлюз подтвердил приём итога.
func (c *Client) Reported(ctx context.Context, operationID string, outcome int32) error {
	_, err := c.call(ctx, Request{Method: MethodReported, OperationID: operationID, Outcome: outcome}, KindOK)
	return err
}

// Running — операции в работе (для Heartbeat).
func (c *Client) Running(ctx context.Context) ([]string, error) {
	r, err := c.call(ctx, Request{Method: MethodRunning}, KindRunning)
	return r.Running, err
}

// Execute передаёт SignedOperation. onAck вызывается один раз (принята или код отказа), onProgress — на каждый
// кусок вывода. Возвращает итог (OperationResult) или nil, если операция отклонена.
func (c *Client) Execute(ctx context.Context, signed []byte, onAck func(accepted bool, code string), onProgress func([]byte)) ([]byte, error) {
	return c.ExecuteTerminal(ctx, signed, onAck, onProgress, nil)
}

// ExecuteTerminal — Execute с кадром terminal: onTerminal получает сведения и ведущую сторону PTY (закрывает
// получатель). Без onTerminal пришедший дескриптор закрывается.
func (c *Client) ExecuteTerminal(ctx context.Context, signed []byte, onAck func(accepted bool, code string), onProgress func([]byte),
	onTerminal func(TerminalInfo, *os.File)) ([]byte, error) {
	conn, err := c.dial(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err := writeRequest(conn, Request{Method: MethodExecute, Signed: signed}); err != nil {
		return nil, err
	}
	fr := &fdReader{c: conn}
	defer fr.closeAll()
	acked := false
	for {
		var r Response
		if err := ReadFrame(fr, &r); err != nil {
			if acked {
				return nil, fmt.Errorf("%w: %v", ErrNoResult, err)
			}
			return nil, err
		}
		switch r.Kind {
		case KindError:
			return nil, &RemoteError{Code: r.Code}
		case KindAck:
			acked = true
			onAck(r.Accepted, r.Code)
			if !r.Accepted {
				return nil, nil
			}
		case KindProgress:
			if onProgress != nil {
				onProgress(r.Progress)
			}
		case KindResult:
			return r.Result, nil
		case KindTerminal:
			f := fr.take()
			if f == nil || r.Terminal == nil {
				return nil, errors.New("helper: кадр terminal без дескриптора")
			}
			if onTerminal == nil {
				f.Close()
				continue
			}
			onTerminal(*r.Terminal, f)
		default:
			return nil, fmt.Errorf("helper: неожиданный кадр %s", r.Kind)
		}
	}
}

// LogsPoll — новые записи журналов по действующей подписке с позиций agent (E08-T15). Возвращает подписку,
// записи (LogRecord, protobuf), новые позиции и есть ли ещё.
func (c *Client) LogsPoll(ctx context.Context, subscription string, positions map[string]string) (string, [][]byte, map[string]string, bool, error) {
	r, err := c.call(ctx, Request{Method: MethodLogsPoll, Subscription: subscription, Positions: positions}, KindLogs)
	return r.Subscription, r.Records, r.Positions, r.More, err
}

// writeRequest пишет запрос. Помощник отказывает чужому uid (PEER_FORBIDDEN) до чтения запроса и закрывает
// соединение, поэтому запись может упасть с EPIPE, хотя ответ с кодом уже лежит в сокете: тогда возвращается
// этот код, а не «broken pipe».
func writeRequest(conn net.Conn, req Request) error {
	werr := WriteFrame(conn, req)
	if werr == nil {
		return nil
	}
	var r Response
	if ReadFrame(conn, &r) == nil && r.Kind == KindError {
		return &RemoteError{Code: r.Code}
	}
	return werr
}

// EventsPoll — события детектора (Event, protobuf), накопленные помощником с прошлого опроса.
func (c *Client) EventsPoll(ctx context.Context) ([][]byte, error) {
	r, err := c.call(ctx, Request{Method: MethodEventsPoll}, KindEvents)
	return r.Events, err
}

// WgStats — метрики пиров WireGuard (MetricsBatch, protobuf): устройство читает помощник (нужен CAP_NET_ADMIN).
func (c *Client) WgStats(ctx context.Context) ([]byte, error) {
	r, err := c.call(ctx, Request{Method: MethodWgStats}, KindWgStats)
	return r.Result, err
}

// TerminalRenew — передать подписанное продление терминала.
func (c *Client) TerminalRenew(ctx context.Context, signed []byte) error {
	_, err := c.call(ctx, Request{Method: MethodTerminalRenew, Signed: signed}, KindOK)
	return err
}

// Cancel — передать подписанную отмену релиза, сборки или операции в ожидании подтверждения (E10-T14). Для
// последней — итог отката (OperationResult, protobuf); для релиза и сборки — пусто (итог придёт с операцией).
// Отказ — код помощника (CANCEL_TOO_LATE и др.).
func (c *Client) Cancel(ctx context.Context, signed []byte) ([]byte, error) {
	r, err := c.call(ctx, Request{Method: MethodCancel, Signed: signed}, KindResult)
	return r.Result, err
}

// TerminalClose — закрыть терминал (простой, клиент закрыл): сужение доступа, подпись не нужна.
func (c *Client) TerminalClose(ctx context.Context, sessionID string, reason int32) error {
	_, err := c.call(ctx, Request{Method: MethodTerminalClose, SessionID: sessionID, Reason: reason}, KindOK)
	return err
}

// fdReader — чтение с приёмом дескрипторов SCM_RIGHTS: пришедшие дескрипторы копятся до take.
type fdReader struct {
	c   *net.UnixConn
	fds []*os.File
}

func (r *fdReader) Read(p []byte) (int, error) {
	oob := make([]byte, unix.CmsgSpace(4*4))
	n, oobn, _, _, err := r.c.ReadMsgUnix(p, oob)
	if oobn > 0 {
		if msgs, perr := unix.ParseSocketControlMessage(oob[:oobn]); perr == nil {
			for _, m := range msgs {
				if fds, ferr := unix.ParseUnixRights(&m); ferr == nil {
					for _, fd := range fds {
						r.fds = append(r.fds, os.NewFile(uintptr(fd), "pty"))
					}
				}
			}
		}
	}
	return n, err
}

func (r *fdReader) take() *os.File {
	if len(r.fds) == 0 {
		return nil
	}
	f := r.fds[0]
	r.fds = r.fds[1:]
	return f
}

func (r *fdReader) closeAll() {
	for _, f := range r.fds {
		f.Close()
	}
}
