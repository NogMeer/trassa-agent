// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/coder/websocket"
)

// Протокол окна терминала (apps/api access/terminal/client-socket.ts): первый кадр — {ticket, resumeFrom},
// дальше двоичные кадры: от клиента — ввод, клиенту — 8 байт смещения вывода и вывод. Управление — текстом.
const (
	terminalPath = "/v1/ws/terminal"
	// frameMax — TERMINAL_FRAME_BYTES панели.
	frameMax     = 64 << 10
	pingEvery    = 25 * time.Second
	reconnectFor = 60 * time.Second
	// Коды закрытия окна (CLOSE в client-socket.ts).
	closeTicketInvalid = 4401
	closeRevoked       = 4403
	closeIdle          = 4408
	closeUnavailable   = 4503
)

// renewEvery — продление пропуска (пропуск живёт 10 минут); переменная — для тестов.
var renewEvery = 4 * time.Minute

type sessionOpened struct {
	SessionID            string    `json:"sessionId"`
	Ticket               string    `json:"ticket"`
	Recording            bool      `json:"recording"`
	RecordingUnavailable bool      `json:"recordingUnavailable"`
	PassExpiresAt        time.Time `json:"passExpiresAt"`
	UnixUser             string    `json:"unixUser"`
	Sudo                 bool      `json:"sudo"`
	Server               struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"server"`
}

type ctrl struct {
	Type   string `json:"type"`
	Reason string `json:"reason,omitempty"`
	Code   *int   `json:"code,omitempty"`
}

// Terminal — терминал человека: размер и сырой режим (на Windows — ещё вывод VT).
type Terminal interface {
	Size() (cols, rows int)
	// Raw — сырой режим; restore возвращает прежний.
	Raw() (restore func(), err error)
	// Resized — сигнал смены размера.
	Resized(ctx context.Context) <-chan struct{}
}

// relay — одна сессия через Trassa: подключение, возврат после обрыва, продление пропуска.
type relay struct {
	a       *App
	c       *client
	ws      string
	sess    sessionOpened
	term    Terminal
	in      <-chan []byte
	out     io.Writer
	nextOff uint64
}

// endErr — сессия закончилась: код выхода оболочки или причина.
type endErr struct {
	code int
	msg  string
}

func (e *endErr) Error() string { return e.msg }

// Relay — trassa ssh без --direct: сессия через Trassa тем же WebSocket, что у окна браузера.
func (a *App) Relay(ctx context.Context, c *client, ws string, srv myServer, unixUser string, term Terminal) (int, error) {
	cols, rows := term.Size()
	body := map[string]any{
		"serverId": srv.ServerID, "unixUser": unixUser,
		"cols": clampInt(cols, 1, 1000, 80), "rows": clampInt(rows, 1, 500, 24),
		"clientType": "CLI", "lang": a.Lang.locale(),
	}
	var s sessionOpened
	if err := c.do(ctx, http.MethodPost, wsPath(ws, "sessions"), body, &s); err != nil {
		return 1, err
	}
	if s.SessionID == "" || s.Ticket == "" {
		return 1, fmt.Errorf("%w: сессия", errBadResponse)
	}
	who := clean(s.UnixUser)
	if s.Sudo {
		who += " (" + a.t("ssh.sudo") + ")"
	}
	fmt.Fprint(a.Stderr, a.t("ssh.relay", clean(srv.Name), who))
	switch {
	case s.Recording:
		fmt.Fprint(a.Stderr, a.t("ssh.recording"))
	case s.RecordingUnavailable:
		fmt.Fprint(a.Stderr, a.t("ssh.rec_off"))
	}
	restore, err := term.Raw()
	if err != nil {
		return 1, err
	}
	defer restore()

	rctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	r := &relay{a: a, c: c, ws: ws, sess: s, term: term, in: readInput(rctx, a.Stdin), out: a.Stdout}
	renewed := make(chan struct{})
	go func() {
		defer close(renewed)
		r.renew(rctx, cancel)
	}()
	code, err := r.run(rctx)
	// Продление не переживает сессию: после конца пропуск больше не продлевается.
	cause := context.Cause(rctx)
	cancel(nil)
	<-renewed
	if err != nil && cause != nil && !errors.Is(cause, context.Canceled) {
		err = cause
	}
	var ee *endErr
	if errors.As(err, &ee) {
		if ee.msg != "" {
			fmt.Fprint(a.Stderr, "\r\n"+ee.msg+"\r\n")
		}
		return ee.code, nil
	}
	if ctx.Err() != nil {
		// Остановка сигналом: сессия закрывается, а не висит до простоя.
		_ = c.do(context.WithoutCancel(ctx), http.MethodPost, wsPath(ws, "sessions/"+url.PathEscape(s.SessionID)+"/terminate"), nil, nil)
		return 130, nil
	}
	return code, err
}

func clampInt(v, lo, hi, def int) int {
	if v < lo || v > hi {
		return def
	}
	return v
}

// readInput — ввод человека кадрами до frameMax; EOF не из терминала — Ctrl-D (на удалённом pty это конец ввода).
func readInput(ctx context.Context, f io.Reader) <-chan []byte {
	ch := make(chan []byte, 16)
	if f == nil {
		return ch
	}
	go func() {
		buf := make([]byte, 32<<10)
		for {
			n, err := f.Read(buf)
			if n > 0 {
				b := append([]byte(nil), buf[:n]...)
				select {
				case ch <- b:
				case <-ctx.Done():
					return
				}
			}
			if err != nil {
				select {
				case ch <- []byte{0x04}:
				case <-ctx.Done():
				}
				return
			}
		}
	}()
	return ch
}

// renew — продление пропуска каждые 4 минуты (пропуск живёт 10). Отказ — конец сессии с причиной.
func (r *relay) renew(ctx context.Context, cancel context.CancelCauseFunc) {
	t := time.NewTicker(renewEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		var out struct {
			PassExpiresAt time.Time `json:"passExpiresAt"`
		}
		err := r.c.do(ctx, http.MethodPost, wsPath(r.ws, "sessions/"+url.PathEscape(r.sess.SessionID)+"/renew"), nil, &out)
		var ne *netError
		switch {
		case err == nil, errors.As(err, &ne), apiStatus(err) >= 500, apiStatus(err) == http.StatusTooManyRequests:
			// Сеть или панель — временно: следующая попытка через тот же интервал, пропуск ещё действует.
		case apiCode(err) == "ACCESS_SESSION_CLOSED":
			cancel(&endErr{code: 1, msg: r.a.t("err.session_closed", "CLOSED")})
			return
		default:
			cancel(&endErr{code: 1, msg: r.a.Explain(err)})
			return
		}
	}
}

// run — подключения, пока сессия жива: после обрыва — новый билет и возврат с resumeFrom.
func (r *relay) run(ctx context.Context) (int, error) {
	ticket := r.sess.Ticket
	var lostAt time.Time
	for {
		err := r.attach(ctx, ticket, &lostAt)
		var ee *endErr
		if errors.As(err, &ee) || ctx.Err() != nil {
			return 0, err
		}
		if lostAt.IsZero() {
			lostAt = r.a.now()
			fmt.Fprint(r.a.Stderr, r.a.t("ssh.lost"))
		}
		if r.a.now().Sub(lostAt) > reconnectFor {
			return 0, &endErr{code: 1, msg: r.a.t("err.lost_for_good")}
		}
		if err := r.a.sleep(ctx, 2*time.Second); err != nil {
			return 0, err
		}
		var t struct {
			Ticket string `json:"ticket"`
		}
		terr := r.c.do(ctx, http.MethodPost, wsPath(r.ws, "sessions/"+url.PathEscape(r.sess.SessionID)+"/ticket"), nil, &t)
		var ne *netError
		switch {
		case terr == nil && t.Ticket != "":
			ticket = t.Ticket
		case terr == nil:
			return 0, fmt.Errorf("%w: билет", errBadResponse)
		case errors.As(terr, &ne), apiStatus(terr) >= 500:
			ticket = ""
		default:
			return 0, &endErr{code: 1, msg: r.a.Explain(terr)}
		}
	}
}

// attach — одно подключение окна. nil и сетевые ошибки — повтор; *endErr — конец.
func (r *relay) attach(ctx context.Context, ticket string, lostAt *time.Time) error {
	if ticket == "" {
		return errors.New("no ticket")
	}
	u := *r.c.base
	u.Scheme = map[string]string{"https": "wss", "http": "ws"}[u.Scheme]
	u.Path = terminalPath
	hdr := http.Header{"User-Agent": {r.c.ua}}
	// Без Origin: так панель отличает CLI от браузера; токен в окно не уходит — его держит билет.
	conn, _, err := websocket.Dial(ctx, u.String(), &websocket.DialOptions{HTTPClient: r.a.HTTP, HTTPHeader: hdr})
	if err != nil {
		return err
	}
	defer conn.CloseNow()
	conn.SetReadLimit(frameMax + 4096)
	hello, _ := json.Marshal(map[string]any{"ticket": ticket, "resumeFrom": r.nextOff})
	if err := conn.Write(ctx, websocket.MessageText, hello); err != nil {
		return err
	}
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go r.pump(cctx, conn)
	for {
		typ, data, err := conn.Read(ctx)
		if err != nil {
			return r.closed(err)
		}
		if typ == websocket.MessageBinary {
			if !lostAt.IsZero() {
				*lostAt = time.Time{}
				fmt.Fprint(r.a.Stderr, r.a.t("ssh.back"))
			}
			if err := r.output(data); err != nil {
				return err
			}
			continue
		}
		var m ctrl
		if json.Unmarshal(data, &m) != nil {
			continue
		}
		switch m.Type {
		case "ready":
			if !lostAt.IsZero() {
				*lostAt = time.Time{}
				fmt.Fprint(r.a.Stderr, r.a.t("ssh.back"))
			}
		case "lost":
			if lostAt.IsZero() {
				*lostAt = r.a.now()
				fmt.Fprint(r.a.Stderr, r.a.t("ssh.lost"))
			} else if r.a.now().Sub(*lostAt) > reconnectFor {
				return &endErr{code: 1, msg: r.a.t("err.lost_for_good")}
			}
		case "exit":
			code := 0
			if m.Code != nil {
				code = *m.Code
			}
			if m.Reason == "IDLE" {
				return &endErr{code: 1, msg: r.a.t("err.idle")}
			}
			return &endErr{code: code}
		case "close":
			return r.reason(m.Reason)
		}
	}
}

// output — вывод по смещению: повтор после возврата не печатается дважды.
func (r *relay) output(data []byte) error {
	if len(data) < 8 {
		return nil
	}
	off := binary.BigEndian.Uint64(data[:8])
	b := data[8:]
	end := off + uint64(len(b))
	if end <= r.nextOff {
		return nil
	}
	if off < r.nextOff {
		b = b[r.nextOff-off:]
	}
	r.nextOff = end
	_, err := r.out.Write(b)
	return err
}

func (r *relay) reason(reason string) error {
	switch reason {
	case "REVOKED":
		return &endErr{code: 1, msg: r.a.t("err.revoked")}
	case "IDLE":
		return &endErr{code: 1, msg: r.a.t("err.idle")}
	case "REPLACED":
		return &endErr{code: 1, msg: r.a.t("err.replaced")}
	case "EXPIRED", "MAX_DURATION":
		return &endErr{code: 1, msg: r.a.t("err.pass_expired")}
	case "CLIENT":
		return &endErr{code: 0}
	}
	return &endErr{code: 1, msg: r.a.t("err.session_closed", clean(reason))}
}

// closed — закрытие окна панелью: коды 4xxx с причиной; прочее — обрыв, повтор.
func (r *relay) closed(err error) error {
	var ce websocket.CloseError
	if !errors.As(err, &ce) {
		return err
	}
	switch ce.Code {
	case websocket.StatusNormalClosure:
		return r.reason(ce.Reason)
	case closeRevoked:
		return &endErr{code: 1, msg: r.a.t("err.revoked")}
	case closeIdle:
		return &endErr{code: 1, msg: r.a.t("err.idle")}
	case closeTicketInvalid, closeUnavailable:
		return err
	case 4000:
		return r.reason(ce.Reason)
	}
	return err
}

// pump — ввод, смена размера и ping в окно.
func (r *relay) pump(ctx context.Context, conn *websocket.Conn) {
	ping := time.NewTicker(pingEvery)
	defer ping.Stop()
	resized := r.term.Resized(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case b := <-r.in:
			if err := conn.Write(ctx, websocket.MessageBinary, b); err != nil {
				return
			}
		case <-resized:
			cols, rows := r.term.Size()
			m, _ := json.Marshal(map[string]any{"type": "resize", "cols": clampInt(cols, 1, 1000, 80), "rows": clampInt(rows, 1, 500, 24)})
			if err := conn.Write(ctx, websocket.MessageText, m); err != nil {
				return
			}
		case <-ping.C:
			if err := conn.Write(ctx, websocket.MessageText, []byte(`{"type":"ping"}`)); err != nil {
				return
			}
		}
	}
}
