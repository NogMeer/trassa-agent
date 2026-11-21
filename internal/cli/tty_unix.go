// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package cli

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

func (t *osTerminal) Resized(ctx context.Context) <-chan struct{} {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGWINCH)
	out := make(chan struct{}, 1)
	go func() {
		defer signal.Stop(sig)
		for {
			select {
			case <-ctx.Done():
				return
			case <-sig:
				select {
				case out <- struct{}{}:
				default:
				}
			}
		}
	}()
	return out
}

// enableVT — на Unix терминал и так понимает escape-последовательности.
func enableVT(*os.File) func() { return func() {} }
