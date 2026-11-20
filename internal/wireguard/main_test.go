// SPDX-License-Identifier: AGPL-3.0-only

package wireguard

import (
	"os"
	"path/filepath"
	"testing"
)

// TestMain — временный каталог по настоящему пути: на macOS /var — ссылка на /private/var, а запись помощника
// по ссылкам не идёт (fsutil.OpenNoFollow).
func TestMain(m *testing.M) {
	if real, err := filepath.EvalSymlinks(os.TempDir()); err == nil {
		_ = os.Setenv("TMPDIR", real)
	}
	os.Exit(m.Run())
}
