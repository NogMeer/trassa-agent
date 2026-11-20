// SPDX-License-Identifier: AGPL-3.0-only

// Package helperrpc — обмен агента с помощником по Unix-сокету /run/trassa/helper.sock (E05-T12).
//
// Одно соединение — один запрос. Кадр — 4 байта длины (big-endian) и JSON. Подписанные сообщения панели и итоги
// операций идут внутри как байты protobuf. Помощник не доверяет агенту: всё, что приходит в запросе, проверяется
// заново (раздел 6), а uid вызывающего сверяется по SO_PEERCRED до чтения запроса (проверка 7).
package helperrpc

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// MaxFrame — предел кадра. Подписанная операция не больше кадра WSS (1 МиБ); итог с запасом под base64.
const MaxFrame = 4 << 20

// Методы.
const (
	MethodHello      = "hello"       // версия и список типов помощника
	MethodExecute    = "execute"     // выполнить SignedOperation
	MethodConfirm    = "confirm"     // SignedConfirm: снять автооткат
	MethodReports    = "reports"     // итоги, ещё не подтверждённые шлюзом
	MethodReported   = "reported"    // шлюз подтвердил приём итога operation_id
	MethodRunning    = "running"     // операции, которые выполняются сейчас
	MethodLogsPoll   = "logs.poll"   // новые записи журналов по действующей подписке (E08-T15)
	MethodEventsPoll = "events.poll" // события детектора (E10-T7)
	MethodWgStats    = "wg.stats"    // метрики пиров WireGuard (E14-T14)
)

// Виды ответных кадров.
const (
	KindHello    = "hello"
	KindAck      = "ack"
	KindProgress = "progress"
	KindResult   = "result"
	KindReports  = "reports"
	KindRunning  = "running"
	KindLogs     = "logs"
	KindEvents   = "events"
	KindWgStats  = "wg.stats"
	KindOK       = "ok"
	KindError    = "error"
)

// CodePeerForbidden — вызывающий процесс не пользователь trassa.
const CodePeerForbidden = "PEER_FORBIDDEN"

// Request — запрос агента.
type Request struct {
	Method      string `json:"method"`
	Signed      []byte `json:"signed,omitempty"` // SignedOperation или SignedConfirm (protobuf)
	OperationID string `json:"operation_id,omitempty"`
	// Outcome — для reported: какой именно итог подтвердил шлюз. Итог мог смениться (автооткат), пока шёл ответ.
	Outcome int32 `json:"outcome,omitempty"`
	// Subscription и Positions — для logs.poll: какой подписке принадлежат позиции агента в источниках.
	Subscription string            `json:"subscription,omitempty"`
	Positions    map[string]string `json:"positions,omitempty"`
}

// Response — кадр ответа помощника. Execute отвечает кадрами ack, progress…, result.
type Response struct {
	Kind          string   `json:"kind"`
	Code          string   `json:"code,omitempty"` // код отказа или ошибки
	Accepted      bool     `json:"accepted,omitempty"`
	Progress      []byte   `json:"progress,omitempty"` // OperationProgress
	Result        []byte   `json:"result,omitempty"`   // OperationResult
	Results       [][]byte `json:"results,omitempty"`  // OperationResult…
	HelperVersion string   `json:"helper_version,omitempty"`
	Capabilities  []string `json:"capabilities,omitempty"`
	Running       []string `json:"running,omitempty"`
	// logs.poll: записи LogRecord (protobuf), новые позиции, есть ли ещё.
	Subscription string            `json:"subscription,omitempty"`
	Records      [][]byte          `json:"records,omitempty"`
	Positions    map[string]string `json:"positions,omitempty"`
	More         bool              `json:"more,omitempty"`
	// events.poll: события Event (protobuf).
	Events [][]byte `json:"events,omitempty"`
}

// ErrFrameTooLarge — кадр больше MaxFrame.
var ErrFrameTooLarge = errors.New("helperrpc: кадр больше предела")

// WriteFrame пишет кадр.
func WriteFrame(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(b) > MaxFrame {
		return ErrFrameTooLarge
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(b)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

// ReadFrame читает кадр; длина проверяется до выделения памяти.
func ReadFrame(r io.Reader, v any) error {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > MaxFrame {
		return ErrFrameTooLarge
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return fmt.Errorf("helperrpc: оборванный кадр: %w", err)
	}
	return json.Unmarshal(b, v)
}
