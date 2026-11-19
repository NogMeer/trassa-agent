// SPDX-License-Identifier: AGPL-3.0-only

package channel

import (
	"math/rand/v2"
	"time"
)

// Backoff — задержка переподключения: экспоненциальная с разбросом, не больше Max (04: максимум 60 с).
// Разброс «равный»: половина окна гарантирована, половина случайна — тысячи агентов после падения шлюза не
// приходят одновременно, и ни один не долбит шлюз без паузы.
type Backoff struct {
	Base time.Duration
	Max  time.Duration
	// Rand возвращает число из [0, 1); подменяется в тестах.
	Rand func() float64
}

// DefaultBackoff — 1 с, 2 с, 4 с … до 60 с.
func DefaultBackoff() Backoff { return Backoff{Base: time.Second, Max: 60 * time.Second} }

// Delay — задержка перед попыткой attempt (с 0).
func (b Backoff) Delay(attempt int) time.Duration {
	window := b.Max
	if attempt < 30 {
		if w := b.Base << attempt; w > 0 && w < b.Max {
			window = w
		}
	}
	r := b.Rand
	if r == nil {
		r = rand.Float64
	}
	half := window / 2
	return half + time.Duration(r()*float64(window-half))
}
