// SPDX-License-Identifier: AGPL-3.0-only

package helperrpc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"
)

// Client — сторона агента.
type Client struct {
	Path string
	// Timeout — предел на весь запрос, кроме Execute (там — ctx).
	Timeout time.Duration
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
	if err := WriteFrame(conn, req); err != nil {
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

// Hello — версия помощника и зашитый список типов.
func (c *Client) Hello(ctx context.Context) (version string, capabilities []string, err error) {
	r, err := c.call(ctx, Request{Method: MethodHello}, KindHello)
	return r.HelperVersion, r.Capabilities, err
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
	conn, err := c.dial(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err := WriteFrame(conn, Request{Method: MethodExecute, Signed: signed}); err != nil {
		return nil, err
	}
	acked := false
	for {
		var r Response
		if err := ReadFrame(conn, &r); err != nil {
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

