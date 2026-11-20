// SPDX-License-Identifier: AGPL-3.0-only

package helper

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/access"
	"github.com/NogMeer/trassa-agent/internal/autorollback"
	"github.com/NogMeer/trassa-agent/internal/backup"
	"github.com/NogMeer/trassa-agent/internal/config"
	"github.com/NogMeer/trassa-agent/internal/helperrpc"
	"github.com/NogMeer/trassa-agent/internal/logsrc"
	"github.com/NogMeer/trassa-agent/internal/nonce"
	"github.com/NogMeer/trassa-agent/internal/ops"
	"github.com/NogMeer/trassa-agent/internal/redact"
	"github.com/NogMeer/trassa-agent/internal/rollback"
	secretkey "github.com/NogMeer/trassa-agent/internal/sealed"
	"github.com/NogMeer/trassa-agent/internal/security"
	"github.com/NogMeer/trassa-agent/internal/wireguard"
)

// Коды итога, которые ставит исполнитель (в дополнение к кодам проверок и update).
const (
	CodeVerifyFailed         = "VERIFY_FAILED"
	CodeApplyFailed          = "APPLY_FAILED"
	CodeRollbackUnavailable  = "ROLLBACK_UNAVAILABLE"
	CodeRollbackFailed       = "ROLLBACK_FAILED"
	CodeRollbackNotAvailable = "ROLLBACK_NOT_AVAILABLE"
	CodeAutoRollback         = "AUTO_ROLLBACK_NO_CONFIRM"
	CodeInterrupted          = "INTERRUPTED"
	CodeInternal             = "INTERNAL"
	CodeConfirmUnknown       = "CONFIRM_UNKNOWN"
)

const (
	// MaxParallelReads — READ-операций одновременно (раздел 8).
	MaxParallelReads = 4
	// MaxChunk — предел куска вывода.
	MaxChunk = 16 << 10
	// StateRetention — сколько хранить доставленные итоги.
	StateRetention = 30 * 24 * time.Hour
	// UpdateWatchdog — сколько новая версия может не выходить на связь.
	UpdateWatchdog = 120 * time.Second
)

// System — сведения о системе.
type System interface {
	Info(ctx context.Context) (*agentv1.SystemInfoResult, []string)
	Inventory(ctx context.Context, kinds []agentv1.InventoryKind) (*agentv1.SystemInventoryResult, []string)
}

// Services — systemd: перезапуск и отложенный запуск команды во временном юните (вне cgroup помощника, чтобы
// пережить остановку самого помощника).
type Services interface {
	Restart(ctx context.Context, units ...string) error
	Schedule(ctx context.Context, unit string, after time.Duration, argv ...string) error
}

// Executor — исполнитель операций помощника.
type Executor struct {
	Checker  *Checker
	States   States
	Nonces   *nonce.Store
	Rollback *rollback.Store
	Auto     autorollback.Store
	Timer    autorollback.Timer
	Lock     FileLock
	BootID   func() (string, error)
	Now      func() time.Time
	Log      *slog.Logger
	Version  string
	System   System
	Services Services
	Updater  *Updater
	Paths    config.Paths
	// Logs читает журналы (E08-T15); nil — logs.subscribe и logs.read завершаются LOGS_UNAVAILABLE.
	Logs *logsrc.Reader
	// Security — система для security.scan (E10); nil — SECURITY_UNAVAILABLE.
	Security *security.System
	// WireGuard — приватная сеть (E14); nil — WG_UNAVAILABLE.
	WireGuard *wireguard.Env
	// Secrets — ключ X25519 помощника для секретов операций (E13, HPKE); nil — секретов не принимает.
	Secrets *secretkey.Key
	// Backup — бэкапы restic (E13); BackupTarget — цель SERVER; nil — BACKUP_UNAVAILABLE.
	Backup       *backup.Env
	BackupTarget *backup.Target
	// Access — доступ (E16); nil — ACCESS_UNAVAILABLE. Terminals — терминалы через помощник (E16).
	Access    *access.Env
	Terminals *Terminals

	once     sync.Once
	handlers map[string]handler
	mutating chan struct{}
	long     chan struct{}
	reads    chan struct{}
	mu       sync.Mutex
	running  map[string]chan struct{}
}

type handler struct {
	preview func(ctx context.Context, r *run) (*agentv1.Preview, *agentv1.OperationResult)
	apply   func(ctx context.Context, r *run) *agentv1.OperationResult
}

// run — одна операция в работе.
type run struct {
	e       *Executor
	body    *agentv1.OperationBody
	spec    ops.Spec
	started time.Time
	send    func(helperrpc.Response) error
	seq     uint32
	phase   agentv1.OperationPhase
	lines   redact.Lines
}

func (e *Executor) init() {
	e.once.Do(func() {
		e.handlers = e.builtinHandlers()
		e.mutating = make(chan struct{}, 1)
		e.long = make(chan struct{}, 1)
		e.reads = make(chan struct{}, MaxParallelReads)
		e.running = map[string]chan struct{}{}
	})
}

func (e *Executor) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

func (e *Executor) log() *slog.Logger {
	if e.Log != nil {
		return e.Log
	}
	return slog.Default()
}

// CheckHandlers — у каждого типа каталога есть обработчик, и наоборот.
func (e *Executor) CheckHandlers() error {
	e.init()
	types := e.Checker.Catalog.Types()
	if len(types) == 0 {
		return ops.ErrEmptyCatalog
	}
	for _, t := range types {
		if _, ok := e.handlers[t]; !ok {
			return fmt.Errorf("нет обработчика для %s", t)
		}
	}
	if len(e.handlers) != len(types) {
		return errors.New("обработчик без типа в каталоге")
	}
	return nil
}

// Serve — helperrpc.Handler.
func (e *Executor) Serve(ctx context.Context, req helperrpc.Request, send func(helperrpc.Response) error) {
	e.init()
	switch req.Method {
	case helperrpc.MethodHello:
		r := helperrpc.Response{Kind: helperrpc.KindHello, HelperVersion: e.Version, Capabilities: e.Checker.Catalog.Types()}
		if e.Secrets != nil {
			r.EncryptionPublicKey, r.EncryptionKeyID = e.Secrets.Public(), e.Secrets.ID
		}
		_ = send(r)
	case helperrpc.MethodExecute:
		e.Execute(ctx, req.Signed, send)
	case helperrpc.MethodConfirm:
		res, code := e.Confirm(ctx, req.Signed)
		if code != "" {
			_ = send(helperrpc.Response{Kind: helperrpc.KindError, Code: code})
			return
		}
		_ = send(helperrpc.Response{Kind: helperrpc.KindResult, Result: res})
	case helperrpc.MethodReports:
		res, err := e.Reports()
		if err != nil {
			e.log().Error("helper: reports", "err", err)
			_ = send(helperrpc.Response{Kind: helperrpc.KindError, Code: CodeInternal})
			return
		}
		_ = send(helperrpc.Response{Kind: helperrpc.KindReports, Results: res})
	case helperrpc.MethodReported:
		if err := e.Reported(req.OperationID, req.Outcome); err != nil {
			_ = send(helperrpc.Response{Kind: helperrpc.KindError, Code: CodeInternal})
			return
		}
		_ = send(helperrpc.Response{Kind: helperrpc.KindOK})
	case helperrpc.MethodLogsPoll:
		e.pollLogs(ctx, req, send)
	case helperrpc.MethodWgStats:
		b := &agentv1.MetricsBatch{CollectedAtMs: e.now().UnixMilli()}
		if e.WireGuard != nil {
			ms, err := e.WireGuard.Stats(e.now())
			if err != nil {
				e.log().Debug("helper: wg.stats", "err", err)
			}
			b.Metrics = ms
		}
		raw, _ := proto.Marshal(b)
		_ = send(helperrpc.Response{Kind: helperrpc.KindWgStats, Result: raw})
	case helperrpc.MethodEventsPoll:
		var raw [][]byte
		if e.Security != nil && e.Security.Detector != nil {
			for _, ev := range e.Security.Detector.Drain() {
				if b, err := proto.Marshal(ev); err == nil {
					raw = append(raw, b)
				}
			}
		}
		_ = send(helperrpc.Response{Kind: helperrpc.KindEvents, Events: raw})
	case helperrpc.MethodTerminalRenew:
		if err := e.TerminalRenew(req.Signed); err != nil {
			e.log().Warn("helper: продление терминала отклонено", "err", err)
			_ = send(helperrpc.Response{Kind: helperrpc.KindError, Code: CodeRenewBad})
			return
		}
		_ = send(helperrpc.Response{Kind: helperrpc.KindOK})
	case helperrpc.MethodTerminalClose:
		if !e.TerminalClose(req.SessionID, agentv1.TerminalEndReason(req.Reason)) {
			_ = send(helperrpc.Response{Kind: helperrpc.KindError, Code: "TERMINAL_NOT_FOUND"})
			return
		}
		_ = send(helperrpc.Response{Kind: helperrpc.KindOK})
	case helperrpc.MethodRunning:
		_ = send(helperrpc.Response{Kind: helperrpc.KindRunning, Running: e.Running()})
	default:
		_ = send(helperrpc.Response{Kind: helperrpc.KindError, Code: "BAD_REQUEST"})
	}
}

func rejectFrame(code string) helperrpc.Response {
	return helperrpc.Response{Kind: helperrpc.KindAck, Accepted: false, Code: code}
}

// Execute проверяет и выполняет операцию.
func (e *Executor) Execute(ctx context.Context, raw []byte, send func(helperrpc.Response) error) {
	e.init()
	checked, rej := e.Checker.Operation(raw)
	if rej != nil {
		e.log().Warn("helper: операция отклонена", "code", rej.Code, "detail", rej.Detail)
		_ = send(rejectFrame(rej.Code))
		return
	}
	b := checked.Body
	op := strings.ToLower(b.GetOperationId())
	nonceHex := hex.EncodeToString(b.GetNonce())

	// 4. nonce. Повтор той же операции с тем же nonce — не ошибка: отвечаем состоянием или готовым итогом.
	st, err := e.States.Get(op)
	if err != nil {
		e.log().Error("helper: состояние", "op", op, "err", err)
		_ = send(helperrpc.Response{Kind: helperrpc.KindError, Code: CodeInternal})
		return
	}
	if st != nil {
		if st.Nonce != nonceHex {
			_ = send(rejectFrame(ops.CodeReplay))
			return
		}
		e.redeliver(ctx, st, send)
		return
	}
	if e.Nonces.Check(b.GetNonce(), op) == nonce.Replay {
		_ = send(rejectFrame(ops.CodeReplay))
		return
	}
	// Номер записывается до выполнения: без записи повтор после перезапуска не отклонить.
	if err := e.Nonces.Record(b.GetNonce(), op, time.UnixMilli(b.GetNotAfterMs())); err != nil {
		if errors.Is(err, nonce.ErrReplay) {
			_ = send(rejectFrame(ops.CodeReplay))
			return
		}
		e.log().Error("helper: окно nonce", "err", err)
		_ = send(helperrpc.Response{Kind: helperrpc.KindError, Code: CodeInternal})
		return
	}

	mutating := checked.Spec.Class.Mutating() && !b.GetDryRun()
	var release func()
	if checked.Spec.Session && !b.GetDryRun() {
		release, err = func() {}, nil
	} else if mutating && checked.Spec.Long {
		release, err = e.acquireLong(ctx)
	} else {
		release, err = e.acquire(ctx, mutating)
	}
	if err != nil {
		_ = send(helperrpc.Response{Kind: helperrpc.KindError, Code: CodeInternal})
		return
	}
	defer release()

	st = &OpState{OperationID: op, Type: b.GetType(), Nonce: nonceHex, Mutating: mutating, Status: StatusRunning, UpdatedAtMs: e.now().UnixMilli()}
	if err := e.States.Put(st); err != nil {
		e.log().Error("helper: запись состояния", "op", op, "err", err)
		_ = send(helperrpc.Response{Kind: helperrpc.KindError, Code: CodeInternal})
		return
	}
	done := e.markRunning(op)
	defer e.unmarkRunning(op, done)
	_ = send(helperrpc.Response{Kind: helperrpc.KindAck, Accepted: true})

	r := &run{e: e, body: b, spec: checked.Spec, started: e.now(), send: send}
	res := r.perform(ctx)
	if err := e.saveResult(st, res); err != nil {
		e.log().Error("helper: запись итога", "op", op, "err", err)
	}
	out, err := proto.Marshal(res)
	if err != nil {
		e.log().Error("helper: итог не сериализуется", "op", op, "err", err)
		_ = send(helperrpc.Response{Kind: helperrpc.KindError, Code: CodeInternal})
		return
	}
	_ = send(helperrpc.Response{Kind: helperrpc.KindResult, Result: out})
}

func (e *Executor) acquire(ctx context.Context, mutating bool) (func(), error) {
	if !mutating {
		select {
		case e.reads <- struct{}{}:
			return func() { <-e.reads }, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	select {
	case e.mutating <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	// Межпроцессная блокировка: «trassa-helper rollback» из таймера не трогает файлы посреди операции.
	unlock, err := e.Lock.Lock(ctx)
	if err != nil {
		<-e.mutating
		return nil, err
	}
	return func() { unlock(); <-e.mutating }, nil
}

// acquireLong — очередь долгих операций (бэкапы, Spec.Long): по одной, без общей блокировки изменений системы —
// автооткат SSH или firewall не ждёт конца многочасового бэкапа.
func (e *Executor) acquireLong(ctx context.Context) (func(), error) {
	select {
	case e.long <- struct{}{}:
		return func() { <-e.long }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (e *Executor) markRunning(op string) chan struct{} {
	e.mu.Lock()
	defer e.mu.Unlock()
	ch := make(chan struct{})
	e.running[op] = ch
	return ch
}

func (e *Executor) unmarkRunning(op string, ch chan struct{}) {
	e.mu.Lock()
	delete(e.running, op)
	e.mu.Unlock()
	close(ch)
}

// Running — операции в работе.
func (e *Executor) Running() []string {
	e.init()
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]string, 0, len(e.running))
	for op := range e.running {
		out = append(out, op)
	}
	return out
}

func (e *Executor) redeliver(ctx context.Context, st *OpState, send func(helperrpc.Response) error) {
	e.mu.Lock()
	ch := e.running[st.OperationID]
	e.mu.Unlock()
	_ = send(helperrpc.Response{Kind: helperrpc.KindAck, Accepted: true})
	if ch != nil {
		select {
		case <-ch:
		case <-ctx.Done():
			return
		}
		fresh, err := e.States.Get(st.OperationID)
		if err != nil || fresh == nil {
			_ = send(helperrpc.Response{Kind: helperrpc.KindError, Code: CodeInternal})
			return
		}
		st = fresh
	}
	if len(st.Result) == 0 {
		_ = send(helperrpc.Response{Kind: helperrpc.KindError, Code: CodeInternal})
		return
	}
	_ = send(helperrpc.Response{Kind: helperrpc.KindResult, Result: st.Result})
}

func (e *Executor) saveResult(st *OpState, res *agentv1.OperationResult) error {
	raw, err := proto.Marshal(res)
	if err != nil {
		return err
	}
	st.Result = raw
	st.Outcome = int32(res.GetOutcome())
	st.Reported = false
	st.Status = StatusDone
	if res.GetOutcome() == agentv1.OperationOutcome_OPERATION_OUTCOME_AWAITING_CONFIRM {
		st.Status = StatusAwaitingConfirm
	}
	st.UpdatedAtMs = e.now().UnixMilli()
	return e.States.Put(st)
}

// Reports — итоги, которые шлюз ещё не подтвердил.
func (e *Executor) Reports() ([][]byte, error) {
	all, err := e.States.List()
	if err != nil {
		return nil, err
	}
	var out [][]byte
	for _, st := range all {
		if st.Status != StatusRunning && !st.Reported && len(st.Result) > 0 {
			out = append(out, st.Result)
		}
	}
	return out, nil
}

// Reported отмечает итог доставленным, если он не сменился с тех пор.
func (e *Executor) Reported(op string, outcome int32) error {
	unlock, err := e.Lock.Lock(context.Background())
	if err != nil {
		return err
	}
	defer unlock()
	st, err := e.States.Get(op)
	if err != nil || st == nil {
		return err
	}
	if st.Outcome != outcome || st.Reported {
		return nil
	}
	st.Reported = true
	return e.States.Put(st)
}

// ---------- Итоги и вывод ----------

func (r *run) result(outcome agentv1.OperationOutcome, code, msg string) *agentv1.OperationResult {
	return &agentv1.OperationResult{
		OperationId:  r.body.GetOperationId(),
		Outcome:      outcome,
		ErrorCode:    code,
		Message:      redact.Text(msg),
		StartedAtMs:  r.started.UnixMilli(),
		FinishedAtMs: r.e.now().UnixMilli(),
	}
}

func (r *run) succeeded(msg string) *agentv1.OperationResult {
	return r.result(agentv1.OperationOutcome_OPERATION_OUTCOME_SUCCEEDED, "", msg)
}

func (r *run) failed(code, msg string) *agentv1.OperationResult {
	return r.result(agentv1.OperationOutcome_OPERATION_OUTCOME_FAILED, code, msg)
}

func (r *run) rolledBack(code, msg string) *agentv1.OperationResult {
	return r.result(agentv1.OperationOutcome_OPERATION_OUTCOME_ROLLED_BACK, code, msg)
}

// log пишет кусок вывода: секреты вычищены, кусок не больше 16 КиБ.
func (r *run) log(stream agentv1.LogStream, text string) {
	var lines []string
	for _, l := range strings.Split(strings.TrimRight(text, "\n"), "\n") {
		if v, ok := r.lines.Line(l); ok {
			lines = append(lines, v)
		}
	}
	out := strings.Join(lines, "\n")
	for len(out) > 0 {
		chunk := out
		if len(chunk) > MaxChunk {
			cut := MaxChunk
			for cut > 0 && !utf8RuneStart(chunk[cut]) {
				cut--
			}
			chunk = chunk[:cut]
		}
		out = out[len(chunk):]
		r.seq++
		raw, _ := proto.Marshal(&agentv1.OperationProgress{
			OperationId: r.body.GetOperationId(), Seq: r.seq, Phase: r.phase, Stream: stream, Chunk: chunk,
		})
		_ = r.send(helperrpc.Response{Kind: helperrpc.KindProgress, Progress: raw})
	}
}

func utf8RuneStart(b byte) bool { return b&0xC0 != 0x80 }

func (r *run) system(format string, a ...any) {
	r.log(agentv1.LogStream_LOG_STREAM_SYSTEM, fmt.Sprintf(format, a...))
}

func (r *run) perform(ctx context.Context) *agentv1.OperationResult {
	h, ok := r.e.handlers[r.spec.Type]
	if !ok {
		return r.failed(ops.CodeTypeUnknown, "нет обработчика")
	}
	if r.body.GetDryRun() {
		r.phase = agentv1.OperationPhase_OPERATION_PHASE_PREVIEW
		if h.preview == nil {
			res := r.succeeded("")
			res.Preview = &agentv1.Preview{Summary: "Только чтение: ничего не изменится"}
			return res
		}
		p, fail := h.preview(ctx, r)
		if fail != nil {
			return fail
		}
		res := r.succeeded("")
		res.Preview = redactPreview(p)
		return res
	}
	r.phase = agentv1.OperationPhase_OPERATION_PHASE_APPLY
	return h.apply(ctx, r)
}

// ---------- Подтверждение и автооткат ----------

// Confirm снимает автооткат по подписанному подтверждению и возвращает итог операции.
func (e *Executor) Confirm(ctx context.Context, raw []byte) ([]byte, string) {
	e.init()
	cb, rej := e.Checker.Confirm(raw)
	if rej != nil {
		e.log().Warn("helper: подтверждение отклонено", "code", rej.Code, "detail", rej.Detail)
		return nil, rej.Code
	}
	op := strings.ToLower(cb.GetOperationId())
	key := "confirm:" + op
	if err := e.Nonces.Record(cb.GetNonce(), key, time.UnixMilli(cb.GetNotAfterMs())); err != nil {
		if errors.Is(err, nonce.ErrReplay) {
			return nil, ops.CodeReplay
		}
		return nil, CodeInternal
	}
	unlock, err := e.Lock.Lock(ctx)
	if err != nil {
		return nil, CodeInternal
	}
	defer unlock()
	st, err := e.States.Get(op)
	if err != nil {
		return nil, CodeInternal
	}
	rec, err := e.Auto.Get(op)
	if err != nil {
		return nil, CodeInternal
	}
	if rec == nil {
		// Подтверждение пришло повторно или после автооткатa: отвечаем итогом как есть.
		if st != nil && st.Status == StatusDone && len(st.Result) > 0 {
			return st.Result, ""
		}
		return nil, CodeConfirmUnknown
	}
	if st == nil || st.Status != StatusAwaitingConfirm {
		return nil, CodeConfirmUnknown
	}
	// Порядок: сначала таймер, потом запись (decisions п. 6). Сбой остановки таймера не страшен: без записи
	// сработавший таймер ничего не делает.
	if err := e.Timer.Disarm(ctx, op); err != nil {
		e.log().Warn("helper: таймер не снят", "op", op, "err", err)
	}
	if err := e.Auto.Delete(op); err != nil {
		return nil, CodeInternal
	}
	var res agentv1.OperationResult
	if err := proto.Unmarshal(st.Result, &res); err != nil {
		return nil, CodeInternal
	}
	res.Outcome = agentv1.OperationOutcome_OPERATION_OUTCOME_SUCCEEDED
	res.FinishedAtMs = e.now().UnixMilli()
	if err := e.saveResult(st, &res); err != nil {
		return nil, CodeInternal
	}
	// Набор межсетевого экрана Trassa подтверждён (firewall.apply или возврат его точки): при загрузке системы
	// служба берёт только подтверждённый набор, неподтверждённый до старта помощника не действует.
	if e.Security != nil {
		if m, _ := e.Rollback.Load(op); m != nil && m.State.NftFile != "" {
			if err := security.ConfirmFirewall(e.Security); err != nil {
				e.log().Error("helper: подтверждённый набор межсетевого экрана не записан", "err", err)
			}
		}
	}
	// Ключи WireGuard, отправленные в отставку ротацией или удалением, — только после подтверждения: до него
	// откат должен их найти.
	if e.WireGuard != nil && (st.Type == ops.TypeWireguardApply || st.Type == ops.TypeWireguardRemove) {
		if err := e.WireGuard.Store.AfterConfirm(); err != nil {
			e.log().Warn("helper: ключи WireGuard после подтверждения", "err", err)
		}
	}
	return st.Result, ""
}

// AutoRollback выполняет автооткат op, если запись о нём ещё есть. Идемпотентен: без записи ничего не делает.
// Вызывается таймером («trassa-helper rollback <op>») и при старте помощника для просроченных записей.
func (e *Executor) AutoRollback(ctx context.Context, op string) error {
	e.init()
	op = strings.ToLower(op)
	unlock, err := e.Lock.Lock(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	return e.autoRollbackLocked(ctx, op)
}

func (e *Executor) autoRollbackLocked(ctx context.Context, op string) error {
	rec, err := e.Auto.Get(op)
	if err != nil || rec == nil {
		return err
	}
	st, err := e.States.Get(op)
	if err != nil {
		return err
	}
	if st == nil {
		st = &OpState{OperationID: op, Mutating: true}
	}
	var res agentv1.OperationResult
	if len(st.Result) > 0 {
		_ = proto.Unmarshal(st.Result, &res)
	}
	res.OperationId = op
	res.FinishedAtMs = e.now().UnixMilli()
	switch rec.Kind {
	case autorollback.KindConfig:
		if _, rerr := e.Rollback.Restore(op); rerr != nil {
			e.log().Error("helper: автооткат не удался", "op", op, "err", rerr)
			res.Outcome, res.ErrorCode, res.Message = agentv1.OperationOutcome_OPERATION_OUTCOME_FAILED, CodeRollbackFailed, redact.Text(rerr.Error())
		} else {
			res.Outcome, res.ErrorCode, res.Message = agentv1.OperationOutcome_OPERATION_OUTCOME_ROLLED_BACK, CodeAutoRollback, "Нет подтверждения связи после изменения: прежнее состояние возвращено"
			if m, _ := e.Rollback.Load(op); m != nil && len(m.Services) > 0 {
				if err := e.Services.Restart(ctx, m.Services...); err != nil {
					res.Message += "; перезапуск служб: " + redact.Text(err.Error())
				}
			}
		}
	case autorollback.KindUpdate:
		if rerr := e.restorePrevBinaries(ctx); rerr != nil {
			res.Outcome, res.ErrorCode, res.Message = agentv1.OperationOutcome_OPERATION_OUTCOME_FAILED, CodeRollbackFailed, redact.Text(rerr.Error())
		} else {
			res.Outcome, res.ErrorCode, res.Message = agentv1.OperationOutcome_OPERATION_OUTCOME_ROLLED_BACK, "UPDATE_ROLLED_BACK", "Новая версия агента не вышла на связь: возвращена прежняя"
		}
	default:
		return fmt.Errorf("вид автооткатa %q", rec.Kind)
	}
	if err := e.saveResult(st, &res); err != nil {
		return err
	}
	if err := e.Timer.Disarm(ctx, op); err != nil {
		e.log().Warn("helper: таймер не снят", "op", op, "err", err)
	}
	return e.Auto.Delete(op)
}

// Recover — при старте помощника: прерванные операции, автооткаты после перезагрузки, уборка.
func (e *Executor) Recover(ctx context.Context) error {
	e.init()
	unlock, err := e.Lock.Lock(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	states, err := e.States.List()
	if err != nil {
		return err
	}
	// Операция, оборванная падением помощника: если точка отката есть — возвращаем.
	for _, st := range states {
		if st.Status != StatusRunning {
			continue
		}
		if rec, _ := e.Auto.Get(st.OperationID); rec != nil {
			if err := e.autoRollbackLocked(ctx, st.OperationID); err != nil {
				e.log().Error("helper: откат прерванной", "op", st.OperationID, "err", err)
			}
			continue
		}
		res := &agentv1.OperationResult{OperationId: st.OperationID, FinishedAtMs: e.now().UnixMilli(), ErrorCode: CodeInterrupted}
		res.Outcome, res.Message = agentv1.OperationOutcome_OPERATION_OUTCOME_FAILED, "Помощник перезапустился во время операции"
		if st.Mutating && st.Type == ops.TypeBackupRestore && e.Backup != nil {
			if had, rerr := e.Backup.RecoverLocalCopy(ctx, st.OperationID); rerr != nil {
				res.ErrorCode, res.Message = CodeRollbackFailed, "Локальная копия не вернулась: "+redact.Text(rerr.Error())
			} else if had {
				res.Outcome, res.Message = agentv1.OperationOutcome_OPERATION_OUTCOME_ROLLED_BACK, "Помощник перезапустился во время восстановления: локальная копия возвращена"
			}
		}
		if st.Mutating {
			if _, lerr := e.Rollback.Load(st.OperationID); lerr == nil {
				if _, rerr := e.Rollback.Restore(st.OperationID); rerr != nil {
					res.ErrorCode, res.Message = CodeRollbackFailed, redact.Text(rerr.Error())
				} else {
					res.Outcome, res.Message = agentv1.OperationOutcome_OPERATION_OUTCOME_ROLLED_BACK, "Помощник перезапустился во время операции: прежнее состояние возвращено"
				}
			}
		}
		if err := e.saveResult(st, res); err != nil {
			return err
		}
	}
	recs, err := e.Auto.List()
	if err != nil {
		return err
	}
	boot, berr := e.bootID()
	keep := map[string]bool{}
	for _, rec := range recs {
		left := time.UnixMilli(rec.DeadlineMs).Sub(e.now())
		if left <= 0 {
			if err := e.autoRollbackLocked(ctx, rec.OperationID); err != nil {
				e.log().Error("helper: просроченный автооткат", "op", rec.OperationID, "err", err)
			}
			continue
		}
		keep[rec.OperationID] = true
		if berr == nil && rec.BootID != boot {
			// Перезагрузка: временный таймер пропал вместе с /run — заводим на остаток срока.
			if err := e.Timer.Arm(ctx, rec.OperationID, left, e.timerHelper(rec.Kind)); err != nil {
				e.log().Error("helper: таймер после перезагрузки", "op", rec.OperationID, "err", err)
				continue
			}
			rec.BootID = boot
			if err := e.Auto.Put(rec); err != nil {
				return err
			}
		}
	}
	if err := e.States.Prune(e.now(), StateRetention); err != nil {
		e.log().Warn("helper: уборка состояний", "err", err)
	}
	if err := e.Rollback.Prune(keep); err != nil {
		e.log().Warn("helper: уборка точек отката", "err", err)
	}
	e.PruneBackupWork()
	return nil
}

// PruneBackupWork — локальные копии восстановлений старше 72 часов (E13). Помощник зовёт при старте и раз в час.
func (e *Executor) PruneBackupWork() {
	if e.Backup == nil {
		return
	}
	if err := e.Backup.PruneLocalCopies(); err != nil {
		e.log().Warn("helper: уборка локальных копий", "err", err)
	}
}

func (e *Executor) bootID() (string, error) {
	if e.BootID != nil {
		return e.BootID()
	}
	return autorollback.BootID("")
}

// timerHelper — чей бинарник запустит таймер. Сторож обновления — прежний из bin.prev: новый может не
// запуститься.
func (e *Executor) timerHelper(kind string) string {
	if kind == autorollback.KindUpdate {
		return filepath.Join(e.Paths.BinPrevDir, "trassa-helper")
	}
	return filepath.Join(e.Paths.BinDir, "trassa-helper")
}

// armAuto пишет запись о сроке и заводит таймер.
func (e *Executor) armAuto(ctx context.Context, op, kind string, after time.Duration) error {
	boot, err := e.bootID()
	if err != nil {
		return err
	}
	if err := e.Auto.Put(autorollback.Record{OperationID: op, Kind: kind, DeadlineMs: e.now().Add(after).UnixMilli(), BootID: boot}); err != nil {
		return err
	}
	if err := e.Timer.Arm(ctx, op, after, e.timerHelper(kind)); err != nil {
		_ = e.Auto.Delete(op)
		return err
	}
	return nil
}

func (e *Executor) disarmAuto(ctx context.Context, op string) {
	if err := e.Timer.Disarm(ctx, op); err != nil {
		e.log().Warn("helper: таймер не снят", "op", op, "err", err)
	}
	if err := e.Auto.Delete(op); err != nil {
		e.log().Error("helper: запись автооткатa не удалена", "op", op, "err", err)
	}
}

// maxPreviewDiff — предел разницы одного файла в предпросмотре (FileChange.diff).
const maxPreviewDiff = 64 << 10

// redactPreview — предпросмотр уходит в панель: разницы файлов, пути, сводка и заметки проходят redact (в
// конфигурации может оказаться пароль или ключ), разница обрезается до 64 КиБ по границе символа.
func redactPreview(p *agentv1.Preview) *agentv1.Preview {
	if p == nil {
		return nil
	}
	p.Summary = redact.String(p.GetSummary())
	for i, n := range p.GetNotes() {
		p.Notes[i] = redact.String(n)
	}
	for _, f := range p.GetFiles() {
		f.Path = redact.String(f.GetPath())
		d := redact.Text(f.GetDiff())
		if len(d) > maxPreviewDiff {
			d = strings.ToValidUTF8(d[:maxPreviewDiff], "") + "\n… (разница обрезана)"
		}
		f.Diff = d
	}
	return p
}
