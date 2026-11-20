// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux

package terminal

import (
	"errors"
	"os"
)

// ErrUnsupported — терминал есть только на Linux.
var ErrUnsupported = errors.New("терминал только на Linux")

// OpenPTY — только Linux.
func OpenPTY() (master, slave *os.File, n int, err error) { return nil, nil, 0, ErrUnsupported }

// SetSize — только Linux.
func SetSize(*os.File, uint32, uint32) error { return ErrUnsupported }
