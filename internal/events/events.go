// SPDX-License-Identifier: AGPL-3.0-only

// Package events — локальные пороги агента (E08-T12): служба упала, диск от 90%, память от 95% дольше минуты.
// Событие уходит шлюзу кадром Event при срабатывании и при снятии; шлюз публикует его как MonitorEvent
// (kind = AGENT_EVENT), инциденты из него делает E09.
//
// Схема Event: kind — код события (service.down, disk.full, mem.high), severity, message — короткая строка для
// журнала (текст для людей панель берёт по коду), at_ms, attributes: subject (на чём сработало), state
// (firing | resolved), value и threshold — числа в десятичной записи.
package events

import (
	"context"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/queue"
	"github.com/NogMeer/trassa-agent/internal/sysinfo"
)

// Коды событий (каталог E09).
const (
	CodeServiceDown = "service.down"
	CodeDiskFull    = "disk.full"
	CodeMemHigh     = "mem.high"
)

// Пороги E08 (раздел 6) и возврат: снятие на 2 п. п. ниже порога, чтобы значение у самой границы не давало пару
// событий каждые 15 секунд.
const (
	DiskPercent = 90.0
	MemPercent  = 95.0
	MemFor      = time.Minute
	hysteresis  = 2.0
	// MaxServices — сколько упавших служб отслеживается одновременно (лимит служб E08, раздел 4).
	MaxServices = 200
	// MaxQueue и MaxAge — сколько событий ждёт связи.
	MaxQueue = 500
	MaxAge   = time.Hour
)

// NewQueue — очередь событий до квитанции шлюза; now — часы агента (nil — time.Now).
func NewQueue(now func() time.Time) *queue.Queue[*agentv1.Event] {
	if now == nil {
		now = time.Now
	}
	return queue.New(MaxQueue, func(e *agentv1.Event) bool { return e.GetAtMs() >= now().Add(-MaxAge).UnixMilli() })
}

type key struct{ code, subject string }

// Detector помнит, что сейчас сработало. Состояние живёт в памяти: после перезапуска агента ещё действующее
// условие сработает снова (шлюз и E09 склеивают повтор по fingerprint).
type Detector struct {
	firing   map[key]bool
	memSince time.Time
}

// NewDetector — детектор без сработавших порогов.
func NewDetector() *Detector { return &Detector{firing: map[key]bool{}} }

// Observe сверяет пачку метрик и список служб с порогами. units == nil — список служб не получен: состояние
// служб не меняется (ни ложного «упала», ни ложного «поднялась»). Пропавший из пачки раздел тоже не снимается.
func (d *Detector) Observe(now time.Time, batch *agentv1.MetricsBatch, units []sysinfo.Unit) []*agentv1.Event {
	var out []*agentv1.Event
	at := now.UnixMilli()
	fire := func(code, subject string, sev agentv1.EventSeverity, value, threshold float64, msg string) {
		k := key{code, subject}
		if d.firing[k] {
			return
		}
		d.firing[k] = true
		out = append(out, event(code, subject, "firing", sev, at, value, threshold, msg))
	}
	resolve := func(code, subject string, sev agentv1.EventSeverity, value, threshold float64, msg string) {
		k := key{code, subject}
		if !d.firing[k] {
			return
		}
		delete(d.firing, k)
		out = append(out, event(code, subject, "resolved", sev, at, value, threshold, msg))
	}

	mem, haveMem := -1.0, false
	for _, m := range batch.GetMetrics() {
		switch m.GetName() {
		case "disk_used_percent":
			mount := m.GetLabels()["mount"]
			v := m.GetValue()
			if v >= DiskPercent {
				fire(CodeDiskFull, mount, agentv1.EventSeverity_EVENT_SEVERITY_WARN, v, DiskPercent, "disk "+mount+" is "+pct(v)+" full")
			} else if v < DiskPercent-hysteresis {
				resolve(CodeDiskFull, mount, agentv1.EventSeverity_EVENT_SEVERITY_INFO, v, DiskPercent, "disk "+mount+" is back to "+pct(v))
			}
		case "mem_used_percent":
			mem, haveMem = m.GetValue(), true
		}
	}
	if haveMem {
		switch {
		case mem >= MemPercent:
			if d.memSince.IsZero() {
				d.memSince = now
			}
			if now.Sub(d.memSince) >= MemFor {
				fire(CodeMemHigh, "", agentv1.EventSeverity_EVENT_SEVERITY_WARN, mem, MemPercent, "memory is "+pct(mem)+" used for over a minute")
			}
		case mem < MemPercent-hysteresis:
			d.memSince = time.Time{}
			resolve(CodeMemHigh, "", agentv1.EventSeverity_EVENT_SEVERITY_INFO, mem, MemPercent, "memory is back to "+pct(mem))
		default:
			// Между порогом и возвратом: таймер «дольше минуты» начинается заново, сработавшее не снимается.
			d.memSince = time.Time{}
		}
	}

	if units != nil {
		failed := map[string]bool{}
		for _, u := range units {
			// Только служба, которая должна работать (E06): oneshot, по таймеру или выключенная — не «упала». Сведения
			// не прочитались — считаем, что должна (лучше лишний инцидент, чем пропущенный).
			expected := !u.Described || sysinfo.ServiceExpected(u.UnitFileState, u.Type, u.TriggeredBy)
			if strings.HasSuffix(u.Name, ".service") && u.ActiveState == "failed" && expected && len(failed) < MaxServices {
				failed[u.Name] = true
			}
		}
		names := make([]string, 0, len(failed))
		for n := range failed {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			fire(CodeServiceDown, n, agentv1.EventSeverity_EVENT_SEVERITY_CRIT, 0, 0, "service "+n+" failed")
		}
		var up []string
		for k := range d.firing {
			if k.code == CodeServiceDown && !failed[k.subject] {
				up = append(up, k.subject)
			}
		}
		sort.Strings(up)
		for _, n := range up {
			resolve(CodeServiceDown, n, agentv1.EventSeverity_EVENT_SEVERITY_INFO, 1, 0, "service "+n+" is no longer failed")
		}
	}
	return out
}

func event(code, subject, state string, sev agentv1.EventSeverity, at int64, value, threshold float64, msg string) *agentv1.Event {
	attrs := map[string]string{"state": state}
	if subject != "" {
		attrs["subject"] = subject
	}
	if code != CodeServiceDown {
		attrs["value"] = strconv.FormatFloat(value, 'f', 1, 64)
		attrs["threshold"] = strconv.FormatFloat(threshold, 'f', 0, 64)
	}
	return &agentv1.Event{Kind: code, Severity: sev, Message: msg, AtMs: at, Attributes: attrs}
}

func pct(v float64) string { return strconv.FormatFloat(v, 'f', 1, 64) + "%" }

// HelperPoller — события детектора помощника (helperrpc.Client.EventsPoll).
type HelperPoller interface {
	EventsPoll(ctx context.Context) ([][]byte, error)
}

// PollHelper забирает события детектора (E10-T7) раз в every и кладёт в очередь отправки с квитанцией шлюза.
// Ошибка опроса пишется в журнал один раз, пока не пройдёт.
func PollHelper(ctx context.Context, h HelperPoller, q *queue.Queue[*agentv1.Event], every time.Duration, log *slog.Logger) {
	failing := ""
	for {
		raw, err := h.EventsPoll(ctx)
		switch {
		case err != nil && err.Error() != failing:
			log.Warn("события детектора: опрос помощника", "err", err)
			failing = err.Error()
		case err == nil:
			failing = ""
			for _, b := range raw {
				var e agentv1.Event
				if proto.Unmarshal(b, &e) == nil {
					q.Add(&e)
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		}
	}
}
