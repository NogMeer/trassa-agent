// SPDX-License-Identifier: AGPL-3.0-only

package helper

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"google.golang.org/protobuf/proto"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/fsutil"
	"github.com/NogMeer/trassa-agent/internal/helperrpc"
	"github.com/NogMeer/trassa-agent/internal/logsrc"
)

// Коды итога журналов.
const (
	CodeLogsUnavailable = "LOGS_UNAVAILABLE"
	CodeLogsReadFailed  = "LOGS_READ_FAILED"
)

// subscriptionFile — действующая подписка журналов в каталоге помощника (root, 0600). Её меняет только
// подписанная logs.subscribe; агент лишь спрашивает новые записи по ней.
func (e *Executor) subscriptionFile() string { return filepath.Join(e.Paths.HelperDir, "logs.json") }

type subscriptionJSON struct {
	ID          string `json:"id"`
	CreatedAtMs int64  `json:"created_at_ms"`
	MinLevel    int32  `json:"min_level"`
	Sources     []struct {
		Kind int32  `json:"kind"`
		Name string `json:"name"`
	} `json:"sources"`
}

func (e *Executor) loadSubscription() (*logsrc.Subscription, error) {
	b, err := os.ReadFile(e.subscriptionFile())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var j subscriptionJSON
	if err := json.Unmarshal(b, &j); err != nil {
		return nil, err
	}
	s := &logsrc.Subscription{ID: j.ID, CreatedAtMs: j.CreatedAtMs, MinLevel: agentv1.LogLevel(j.MinLevel)}
	for _, x := range j.Sources {
		s.Sources = append(s.Sources, &agentv1.LogSource{Kind: agentv1.LogSourceKind(x.Kind), Name: x.Name})
	}
	return s, nil
}

func (e *Executor) saveSubscription(s *logsrc.Subscription) error {
	j := subscriptionJSON{ID: s.ID, CreatedAtMs: s.CreatedAtMs, MinLevel: int32(s.MinLevel)}
	for _, x := range s.Sources {
		j.Sources = append(j.Sources, struct {
			Kind int32  `json:"kind"`
			Name string `json:"name"`
		}{int32(x.GetKind()), x.GetName()})
	}
	b, err := json.Marshal(j)
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(e.subscriptionFile(), b, 0o600, fsutil.Keep)
}

// applyLogsSubscribe — новая подписка заменяет прежнюю; источники проверяются при открытии (файл — без ссылок и
// только внутри /var/log), в подписку попадают только открывшиеся. Пустой список выключает сбор.
func (e *Executor) applyLogsSubscribe(_ context.Context, r *run) *agentv1.OperationResult {
	if e.Logs == nil {
		return r.failed(CodeLogsUnavailable, "журналы на этой сборке не читаются")
	}
	p := r.body.GetParams().GetLogsSubscribe()
	st, ok := e.Logs.Open(p.GetSources())
	sub := &logsrc.Subscription{ID: strings.ToLower(r.body.GetOperationId()), CreatedAtMs: e.now().UnixMilli(), MinLevel: p.GetMinLevel(), Sources: ok}
	if err := e.saveSubscription(sub); err != nil {
		e.log().Error("helper: подписка журналов не сохранена", "err", err)
		return r.failed(CodeLogsUnavailable, "подписка не сохранена")
	}
	res := r.succeeded("")
	res.Data = &agentv1.OperationResult_LogsSubscribe{LogsSubscribe: &agentv1.LogsSubscribeResult{Sources: st}}
	return res
}

func (e *Executor) applyLogsRead(ctx context.Context, r *run) *agentv1.OperationResult {
	if e.Logs == nil {
		return r.failed(CodeLogsUnavailable, "журналы на этой сборке не читаются")
	}
	p := r.body.GetParams().GetLogsRead()
	if p.GetSource().GetKind() == agentv1.LogSourceKind_LOG_SOURCE_KIND_FILE {
		if f, reason, err := e.Logs.OpenFile(p.GetSource().GetName()); err != nil {
			return r.failed(reason, "файл не открыт")
		} else {
			f.Close()
		}
	}
	out, err := e.Logs.Read(ctx, p.GetSource(), int(p.GetLines()), p.GetGrep())
	if err != nil {
		e.log().Warn("helper: logs.read", "err", err)
		return r.failed(CodeLogsReadFailed, "журнал не прочитан")
	}
	res := r.succeeded("")
	res.Data = &agentv1.OperationResult_LogsRead{LogsRead: out}
	return res
}

// pollLogs — helperrpc logs.poll: новые записи действующей подписки с позиций агента. Позиции агент хранит
// вместе с уже принятыми записями: сбой между ними даёт повтор не больше одной пачки, а не потерю.
func (e *Executor) pollLogs(ctx context.Context, req helperrpc.Request, send func(helperrpc.Response) error) {
	if e.Logs == nil {
		_ = send(helperrpc.Response{Kind: helperrpc.KindLogs})
		return
	}
	sub, err := e.loadSubscription()
	if err != nil {
		e.log().Error("helper: подписка журналов не прочитана", "err", err)
		_ = send(helperrpc.Response{Kind: helperrpc.KindError, Code: CodeInternal})
		return
	}
	if sub == nil || len(sub.Sources) == 0 {
		id := ""
		if sub != nil {
			id = sub.ID
		}
		_ = send(helperrpc.Response{Kind: helperrpc.KindLogs, Subscription: id})
		return
	}
	// Позиции прежней подписки к новой не относятся: другие источники или те же с новой точки отсчёта.
	pos := req.Positions
	if req.Subscription != sub.ID {
		pos = nil
	}
	recs, next, more, errs := e.Logs.Poll(ctx, sub, pos)
	for _, err := range errs {
		e.log().Warn("helper: журнал не прочитан", "err", err)
	}
	raw := make([][]byte, 0, len(recs))
	for _, r := range recs {
		b, err := proto.Marshal(r)
		if err != nil {
			continue
		}
		raw = append(raw, b)
	}
	_ = send(helperrpc.Response{Kind: helperrpc.KindLogs, Subscription: sub.ID, Records: raw, Positions: next, More: more})
}
