// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux

package metrics

import "errors"

// Агент выпускается только для Linux; на других системах (сборка тестов разработчика) statfs не нужен.
func statfs(string) (FS, error) { return FS{}, errors.New("statfs: только Linux") }
