// SPDX-License-Identifier: AGPL-3.0-only

package backup

import (
	"errors"
	"fmt"

	"github.com/NogMeer/trassa-agent/internal/tools"
)

// KnownTools — общая таблица программ помощника (internal/tools); restic и rclone — для бэкапов.
var KnownTools = tools.Known

// ErrToolUnknown — версия или сумма программы не из таблицы помощника (BACKUP_TOOL_UNKNOWN).
var ErrToolUnknown = errors.New("BACKUP_TOOL_UNKNOWN")

// CodeToolUnknown — код отказа проверки 6.
const CodeToolUnknown = "BACKUP_TOOL_UNKNOWN"

// CheckTool — версия и sha256 архива есть в таблице для архитектуры сервера.
func CheckTool(tool, version, sha string) error {
	if err := tools.Check(tool, version, sha); err != nil {
		return fmt.Errorf("%w: %v", ErrToolUnknown, err)
	}
	return nil
}
