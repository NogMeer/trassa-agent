// SPDX-License-Identifier: AGPL-3.0-only

//go:build windows

package cli

import (
	"context"
	"os"
	"time"

	"golang.org/x/sys/windows"
)

// Resized — на Windows сигнала смены размера нет: опрос раз в полсекунды.
func (t *osTerminal) Resized(ctx context.Context) <-chan struct{} {
	out := make(chan struct{}, 1)
	go func() {
		tk := time.NewTicker(500 * time.Millisecond)
		defer tk.Stop()
		c, r := t.Size()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tk.C:
				if nc, nr := t.Size(); nc != c || nr != r {
					c, r = nc, nr
					select {
					case out <- struct{}{}:
					default:
					}
				}
			}
		}
	}()
	return out
}

// enableVT — консоль Windows разбирает escape-последовательности вывода только с
// ENABLE_VIRTUAL_TERMINAL_PROCESSING.
func enableVT(f *os.File) func() {
	h := windows.Handle(f.Fd())
	var mode uint32
	if windows.GetConsoleMode(h, &mode) != nil {
		return func() {}
	}
	if windows.SetConsoleMode(h, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING) != nil {
		return func() {}
	}
	return func() { _ = windows.SetConsoleMode(h, mode) }
}
