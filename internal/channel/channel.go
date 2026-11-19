// SPDX-License-Identifier: AGPL-3.0-only

// Package channel — канал агента со шлюзом (E05-T11): WSS, рукопожатие, пульс, доставка итогов с квитанциями,
// переподключение с разбросом.
//
// Агент — посредник без прав: операции и подтверждения он передаёт помощнику как есть (помощник проверяет всё
// сам), подпись проверяет заранее лишь затем, чтобы не будить помощника мусором. Итоги лежат у помощника на диске,
// пока шлюз не пришлёт InboundAck, поэтому обрыв связи или перезапуск агента итог не теряет.
package channel

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/coder/websocket"
	"google.golang.org/protobuf/proto"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/identity"
	"github.com/NogMeer/trassa-agent/internal/ops"
	"github.com/NogMeer/trassa-agent/internal/verify"
)

// Пределы канала (04, раздел 5 E05).
const (
	MaxMessage       = 1 << 20
	HandshakeTimeout = 10 * time.Second
	DefaultHeartbeat = 20 * time.Second
	writeTimeout     = 10 * time.Second
	// stableAfter — сессия дольше этого сбрасывает счётчик задержек.
	stableAfter = 60 * time.Second
)

// Helper — помощник глазами агента (helperrpc.Client).
type Helper interface {
	Hello(ctx context.Context) (string, []string, error)
	Execute(ctx context.Context, signed []byte, onAck func(bool, string), onProgress func([]byte)) ([]byte, error)
	Confirm(ctx context.Context, signed []byte) ([]byte, error)
	Reports(ctx context.Context) ([][]byte, error)
	Reported(ctx context.Context, operationID string, outcome int32) error
	Running(ctx context.Context) ([]string, error)
}

// Config — настройки агента.
type Config struct {
	GatewayURL string
	ServerID   string
	Identity   *identity.Identity
	PanelKeys  []verify.PanelKey
	Helper     Helper
	Version    string
	OS         string
	OSVersion  string
	Arch       string
	HTTPClient *http.Client
	Log        *slog.Logger
	Backoff    Backoff
	Now        func() time.Time
}

var (
	// ErrRevoked — шлюз сообщил, что ключ отозван: агент больше не подключается.
	ErrRevoked = errors.New("agent revoked")
	errClosed  = errors.New("шлюз закрыл соединение")
)

// Agent — канал.
type Agent struct {
	cfg Config
	ob  *outbox
	// Sessions — число успешных рукопожатий (для тестов и журнала).
	mu       sync.Mutex
	sessions int
	opWG     sync.WaitGroup
}

// New создаёт агента.
func New(cfg Config) *Agent {
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Backoff.Base == 0 {
		cfg.Backoff = DefaultBackoff()
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{}
	}
	return &Agent{cfg: cfg, ob: newOutbox()}
}

// Sessions — сколько раз рукопожатие прошло.
func (a *Agent) Sessions() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.sessions
}

// Run держит канал до отмены ctx или отзыва ключа.
func (a *Agent) Run(ctx context.Context) error {
	defer a.opWG.Wait()
	attempt := 0
	for {
		start := a.cfg.Now()
		err := a.session(ctx)
		if errors.Is(err, ErrRevoked) {
			a.cfg.Log.Error("агент отозван панелью: подключений больше не будет")
			return err
		}
		if ctx.Err() != nil {
			return nil
		}
		if a.cfg.Now().Sub(start) >= stableAfter {
			attempt = 0
		}
		d := a.cfg.Backoff.Delay(attempt)
		attempt++
		a.cfg.Log.Warn("канал оборван, переподключение", "err", err, "delay", d.Round(time.Millisecond))
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(d):
		}
	}
}

// conn — одно соединение.
type conn struct {
	a    *Agent
	ws   *websocket.Conn
	mu   sync.Mutex
	seq  uint64
	sent map[uint64]string // seq кадра итога → operation_id
}

func (c *conn) send(ctx context.Context, m *agentv1.AgentMessage) (uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.seq++
	m.Seq = c.seq
	raw, err := proto.Marshal(m)
	if err != nil {
		return 0, err
	}
	if len(raw) > MaxMessage {
		return 0, fmt.Errorf("кадр %d байт больше предела", len(raw))
	}
	wctx, cancel := context.WithTimeout(ctx, writeTimeout)
	defer cancel()
	if err := c.ws.Write(wctx, websocket.MessageBinary, raw); err != nil {
		return 0, err
	}
	if r := m.GetOperationResult(); r != nil {
		c.sent[c.seq] = r.GetOperationId()
	}
	return c.seq, nil
}

func (c *conn) read(ctx context.Context) (*agentv1.GatewayMessage, error) {
	typ, raw, err := c.ws.Read(ctx)
	if err != nil {
		return nil, err
	}
	if typ != websocket.MessageBinary {
		return nil, errors.New("текстовый кадр")
	}
	var m agentv1.GatewayMessage
	if err := proto.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("кадр не разобран: %w", err)
	}
	return &m, nil
}

func closeErr(cl *agentv1.Close) error {
	switch cl.GetReason() {
	case agentv1.CloseReason_CLOSE_REASON_REVOKED:
		return ErrRevoked
	case agentv1.CloseReason_CLOSE_REASON_DUPLICATE:
		return fmt.Errorf("%w: похоже, сервер скопирован вместе с ключом агента: переустановите агент на копии", errClosed)
	default:
		return fmt.Errorf("%w: %v %s", errClosed, cl.GetReason(), cl.GetMessage())
	}
}

func (a *Agent) session(ctx context.Context) error {
	dctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	ws, resp, err := websocket.Dial(dctx, a.cfg.GatewayURL, &websocket.DialOptions{
		HTTPClient: a.cfg.HTTPClient,
		HTTPHeader: http.Header{"User-Agent": {"trassa-agent/" + a.cfg.Version}},
	})
	cancel()
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusForbidden {
			// 403 AGENT_REVOKED при подключении (раздел 5).
			return fmt.Errorf("%w (HTTP 403)", ErrRevoked)
		}
		return err
	}
	defer ws.CloseNow()
	ws.SetReadLimit(MaxMessage)
	c := &conn{a: a, ws: ws, sent: map[uint64]string{}}
	sctx, scancel := context.WithCancel(ctx)
	defer scancel()

	hb, err := a.handshake(sctx, c)
	if err != nil {
		return err
	}
	a.mu.Lock()
	a.sessions++
	a.mu.Unlock()
	a.cfg.Log.Info("канал установлен", "heartbeat", hb)

	// Итоги, которые шлюз ещё не подтвердил: из прошлых сессий и автооткаты без связи.
	if reps, err := a.cfg.Helper.Reports(sctx); err != nil {
		a.cfg.Log.Warn("помощник: итоги не получены", "err", err)
	} else {
		for _, raw := range reps {
			a.ob.add(raw)
		}
	}
	for _, r := range a.ob.pending() {
		if _, err := c.send(sctx, &agentv1.AgentMessage{Payload: &agentv1.AgentMessage_OperationResult{OperationResult: r}}); err != nil {
			return err
		}
	}

	errc := make(chan error, 2)
	go func() { errc <- a.heartbeat(sctx, c, hb) }()
	go func() { errc <- a.readLoop(sctx, c) }()
	err = <-errc
	scancel()
	if err == nil {
		err = errClosed
	}
	return err
}

func (a *Agent) handshake(ctx context.Context, c *conn) (time.Duration, error) {
	hctx, cancel := context.WithTimeout(ctx, HandshakeTimeout)
	defer cancel()
	m, err := c.read(hctx)
	if err != nil {
		return 0, fmt.Errorf("ждали Challenge: %w", err)
	}
	if cl := m.GetClose(); cl != nil {
		return 0, closeErr(cl)
	}
	ch := m.GetChallenge()
	if ch == nil {
		return 0, errors.New("первый кадр шлюза не Challenge")
	}
	supported := false
	for _, v := range ch.GetProtocolVersions() {
		if v == agentv1.ProtocolVersion_PROTOCOL_VERSION_1 {
			supported = true
		}
	}
	if !supported {
		return 0, errors.New("шлюз не поддерживает протокол 1")
	}
	sig, err := a.cfg.Identity.SignChallenge(ch.GetNonce(), a.cfg.ServerID)
	if err != nil {
		return 0, err
	}
	helperVersion, caps, herr := a.cfg.Helper.Hello(hctx)
	if herr != nil {
		// Без помощника агент всё равно выходит на связь: панель увидит пустой список типов и пустую версию.
		a.cfg.Log.Warn("помощник недоступен", "err", herr)
	}
	if _, err := c.send(hctx, &agentv1.AgentMessage{Payload: &agentv1.AgentMessage_Hello{Hello: &agentv1.Hello{
		ServerId: a.cfg.ServerID, Signature: sig, ProtocolVersion: agentv1.ProtocolVersion_PROTOCOL_VERSION_1,
		AgentVersion: a.cfg.Version, HelperVersion: helperVersion, Capabilities: caps,
		Os: a.cfg.OS, OsVersion: a.cfg.OSVersion, Arch: a.cfg.Arch, AgentTimeMs: a.cfg.Now().UnixMilli(),
	}}}); err != nil {
		return 0, err
	}
	m, err = c.read(hctx)
	if err != nil {
		return 0, fmt.Errorf("ждали Welcome: %w", err)
	}
	if cl := m.GetClose(); cl != nil {
		return 0, closeErr(cl)
	}
	w := m.GetWelcome()
	if w == nil || w.GetProtocolVersion() != agentv1.ProtocolVersion_PROTOCOL_VERSION_1 {
		return 0, errors.New("ждали Welcome с протоколом 1")
	}
	hb := time.Duration(w.GetHeartbeatSec()) * time.Second
	if hb <= 0 || hb > 5*time.Minute {
		hb = DefaultHeartbeat
	}
	return hb, nil
}

func (a *Agent) heartbeat(ctx context.Context, c *conn, every time.Duration) error {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
		running, err := a.cfg.Helper.Running(ctx)
		if err != nil {
			running = nil
		}
		if _, err := c.send(ctx, &agentv1.AgentMessage{Payload: &agentv1.AgentMessage_Heartbeat{Heartbeat: &agentv1.Heartbeat{
			AgentTimeMs: a.cfg.Now().UnixMilli(), RunningOperationIds: running,
		}}}); err != nil {
			return err
		}
	}
}

func (a *Agent) readLoop(ctx context.Context, c *conn) error {
	for {
		m, err := c.read(ctx)
		if err != nil {
			return err
		}
		switch p := m.GetPayload().(type) {
		case *agentv1.GatewayMessage_Operation:
			raw, err := proto.Marshal(p.Operation)
			if err != nil {
				continue
			}
			a.opWG.Add(1)
			go func() {
				defer a.opWG.Done()
				a.operation(ctx, c, p.Operation, raw)
			}()
		case *agentv1.GatewayMessage_Confirm:
			raw, err := proto.Marshal(p.Confirm)
			if err != nil {
				continue
			}
			a.opWG.Add(1)
			go func() {
				defer a.opWG.Done()
				a.confirm(ctx, c, raw)
			}()
		case *agentv1.GatewayMessage_InboundAck:
			a.inboundAck(ctx, c, p.InboundAck.GetSeq())
		case *agentv1.GatewayMessage_Close:
			return closeErr(p.Close)
		case *agentv1.GatewayMessage_Subscribe, *agentv1.GatewayMessage_Unsubscribe:
			// Потоки журналов — E08.
			a.cfg.Log.Debug("подписка пока не поддерживается")
		default:
			return fmt.Errorf("неожиданный кадр шлюза %T", p)
		}
	}
}

// operation передаёт операцию помощнику. Выполнение не привязано к соединению: обрыв связи не прерывает
// операцию, итог уйдёт в следующей сессии.
func (a *Agent) operation(sctx context.Context, c *conn, so *agentv1.SignedOperation, raw []byte) {
	var body agentv1.OperationBody
	_ = proto.Unmarshal(so.GetBody(), &body) // только ради operation_id в ответе; решает помощник
	opID := body.GetOperationId()
	ack := func(accepted bool, code string) {
		_, _ = c.send(sctx, &agentv1.AgentMessage{Payload: &agentv1.AgentMessage_OperationAck{OperationAck: &agentv1.OperationAck{
			OperationId: opID, Accepted: accepted, RejectCode: code,
		}}})
	}
	if err := verify.Signature(a.cfg.PanelKeys, so.GetKeyId(), verify.ContextOperation, so.GetBody(), so.GetSignature()); err != nil {
		a.cfg.Log.Warn("операция с неверной подписью", "op", opID)
		ack(false, ops.CodeSignatureInvalid)
		return
	}
	// Операция живёт дольше соединения: контекст агента, а не сессии.
	res, err := a.cfg.Helper.Execute(context.WithoutCancel(sctx), raw, ack, func(p []byte) {
		var pr agentv1.OperationProgress
		if proto.Unmarshal(p, &pr) == nil {
			_, _ = c.send(sctx, &agentv1.AgentMessage{Payload: &agentv1.AgentMessage_OperationProgress{OperationProgress: &pr}})
		}
	})
	if err != nil {
		a.cfg.Log.Error("помощник: операция", "op", opID, "err", err)
		return
	}
	if res == nil {
		return // отклонена, ack уже отправлен
	}
	a.deliver(sctx, c, res)
}

func (a *Agent) confirm(sctx context.Context, c *conn, raw []byte) {
	res, err := a.cfg.Helper.Confirm(context.WithoutCancel(sctx), raw)
	if err != nil {
		a.cfg.Log.Warn("помощник: подтверждение не принято", "err", err)
		return
	}
	a.deliver(sctx, c, res)
}

func (a *Agent) deliver(sctx context.Context, c *conn, raw []byte) {
	r := a.ob.add(raw)
	if r == nil {
		a.cfg.Log.Error("помощник вернул неразборчивый итог")
		return
	}
	if sctx.Err() != nil {
		return // уйдёт в следующей сессии
	}
	_, _ = c.send(sctx, &agentv1.AgentMessage{Payload: &agentv1.AgentMessage_OperationResult{OperationResult: r}})
}

func (a *Agent) inboundAck(ctx context.Context, c *conn, seq uint64) {
	c.mu.Lock()
	op, ok := c.sent[seq]
	delete(c.sent, seq)
	c.mu.Unlock()
	if !ok {
		return
	}
	r := a.ob.get(op)
	if r == nil {
		return
	}
	if err := a.cfg.Helper.Reported(ctx, op, int32(r.GetOutcome())); err != nil {
		a.cfg.Log.Warn("помощник: отметка доставки", "op", op, "err", err)
		return
	}
	a.ob.remove(op, r.GetOutcome())
}

// outbox — итоги, ждущие InboundAck. Ключ — operation_id: новый итог той же операции (подтверждение, автооткат)
// заменяет прежний.
type outbox struct {
	mu sync.Mutex
	m  map[string]*agentv1.OperationResult
}

func newOutbox() *outbox { return &outbox{m: map[string]*agentv1.OperationResult{}} }

func (o *outbox) add(raw []byte) *agentv1.OperationResult {
	var r agentv1.OperationResult
	if err := proto.Unmarshal(raw, &r); err != nil || r.GetOperationId() == "" {
		return nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if cur, ok := o.m[r.GetOperationId()]; ok && cur.GetFinishedAtMs() > r.GetFinishedAtMs() {
		return cur
	}
	o.m[r.GetOperationId()] = &r
	return &r
}

func (o *outbox) get(op string) *agentv1.OperationResult {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.m[op]
}

func (o *outbox) remove(op string, outcome agentv1.OperationOutcome) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if cur, ok := o.m[op]; ok && cur.GetOutcome() == outcome {
		delete(o.m, op)
	}
}

func (o *outbox) pending() []*agentv1.OperationResult {
	o.mu.Lock()
	defer o.mu.Unlock()
	out := make([]*agentv1.OperationResult, 0, len(o.m))
	for _, r := range o.m {
		out = append(out, r)
	}
	return out
}
