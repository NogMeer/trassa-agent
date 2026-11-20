// SPDX-License-Identifier: AGPL-3.0-only

// Package helper — исполнитель root-помощника trassa-helper (E05-T12…T19). Помощник не доверяет сетевому
// процессу: подпись, server_id, сроки, nonce, тип и параметры проверяются здесь заново (раздел 6), uid
// вызывающего — в helperrpc до чтения запроса.
package helper

import "github.com/NogMeer/trassa-agent/internal/opcheck"

// Проверки операций живут в internal/opcheck: ими пользуется и агент без прав (net.check).
type (
	Checker   = opcheck.Checker
	Rejection = opcheck.Rejection
	Checked   = opcheck.Checked
)

// Пределы проверок (см. opcheck).
const (
	MaxNotAfter    = opcheck.MaxNotAfter
	ClockTolerance = opcheck.ClockTolerance
	NonceSize      = opcheck.NonceSize
)
