// SPDX-License-Identifier: AGPL-3.0-only

package backup

import (
	"fmt"
	"runtime"
)

// KnownTools — программы бэкапа, которые помощник согласен поставить: версия → архитектура → sha256 архива
// выпуска. Суммы — из подписанных SHA256SUMS выпусков (decisions E13, п. 1.1 и 1.10; подписи проверены).
// Подписанная операция панели не может поставить от root другой бинарник: сумма из тела обязана совпасть с
// этой таблицей. Новая версия — правка таблицы и decisions в одном выпуске агента.
var KnownTools = map[string]map[string]map[string]string{
	"restic": {
		"0.20.0": {
			"amd64": "0ccd9fa7885074a24603b051e01bf9bd8b5e45d6a1791e9d9887e9e9372107f7",
			"arm64": "1188daded239bccb5952a01d2ad33e77a0d3dc34f9d9fc1e7fdda618d44938ef",
		},
	},
	"rclone": {
		"1.75.2": {
			"amd64": "349ac8fba6ff65d6247043f1750cdcb518ec5d500ef91463a10d37c0ccdf3702",
			"arm64": "7e1e8d69654941b7b7df84ee74c5f7fb09cce7d5496947fb7bf16b55ff427d10",
		},
	},
}

// ErrToolUnknown — версия или сумма программы не из таблицы помощника (BACKUP_TOOL_UNKNOWN).
var ErrToolUnknown = fmt.Errorf("BACKUP_TOOL_UNKNOWN")

// CodeToolUnknown — код отказа проверки 6.
const CodeToolUnknown = "BACKUP_TOOL_UNKNOWN"

// CheckTool — версия и sha256 архива есть в KnownTools для архитектуры сервера.
func CheckTool(tool, version, sha string) error {
	return checkToolArch(tool, version, sha, runtime.GOARCH)
}

func checkToolArch(tool, version, sha, arch string) error {
	want, ok := KnownTools[tool][version][arch]
	if !ok {
		return fmt.Errorf("%w: %s %s для %s не поддерживается этой версией агента", ErrToolUnknown, tool, version, arch)
	}
	if sha != want {
		return fmt.Errorf("%w: sha256 %s %s не совпадает с таблицей агента", ErrToolUnknown, tool, version)
	}
	return nil
}
