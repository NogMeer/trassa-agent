// SPDX-License-Identifier: AGPL-3.0-only

//go:build !testops

package helper

func (e *Executor) extraHandlers() map[string]handler { return nil }
