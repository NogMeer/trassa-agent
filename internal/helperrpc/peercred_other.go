// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux && !darwin

package helperrpc

import "errors"

// peerUID: на других системах uid вызывающего не узнать — значит, отказ.
func peerUID(uintptr) (int, error) { return -1, errors.New("peer credentials unsupported") }
