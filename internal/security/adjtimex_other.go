// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux

package security

import "errors"

func adjtimex() (int64, error) { return 0, errors.New("adjtimex: только Linux") }
