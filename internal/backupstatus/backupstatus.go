// SPDX-License-Identifier: AGPL-3.0-only

// Package backupstatus — время последнего успешного бэкапа по планам (E13, метрика backup_last_success_age_seconds).
// Пишет помощник (root) после backup.init, успешного backup.run и backup.unconfigure; читает агент без прав —
// в файле нет секретов, только id планов и время.
package backupstatus

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/NogMeer/trassa-agent/internal/fsutil"
)

// Path — файл состояния на сервере.
const Path = "/var/lib/trassa/backup/status.json"

// Plan — время настройки плана и последнего успешного запуска (мс Unix; 0 — успешных ещё не было).
type Plan struct {
	ConfiguredMs  int64 `json:"configured_ms"`
	LastSuccessMs int64 `json:"last_success_ms"`
}

// File — содержимое файла.
type File struct {
	Plans map[string]Plan `json:"plans"`
}

// Read читает файл; нет файла — пустое состояние без ошибки.
func Read(path string) (*File, error) {
	raw, err := fsutil.ReadLimited(path, 1<<20)
	if errors.Is(err, os.ErrNotExist) {
		return &File{Plans: map[string]Plan{}}, nil
	}
	if err != nil {
		return nil, err
	}
	var f File
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("состояние бэкапов повреждено: %w", err)
	}
	if f.Plans == nil {
		f.Plans = map[string]Plan{}
	}
	return &f, nil
}

// Update меняет файл под fn и записывает атомарно: каталог 0755, файл 0644 (его читает агент без прав).
// Пишущие операции помощника идут одной очередью — гонки записи нет.
func Update(path string, fn func(*File)) error {
	f, err := Read(path)
	if err != nil {
		// Повреждённый файл не должен навсегда остановить учёт: начинаем заново.
		f = &File{Plans: map[string]Plan{}}
	}
	fn(f)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if err := os.Chmod(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	raw, _ := json.Marshal(f)
	return fsutil.WriteFileAtomic(path, raw, 0o644, fsutil.Keep)
}

// Age — секунды с последнего успешного бэкапа у плана, который отстал больше всех (без успеха — с настройки).
// ok = false — планов нет, метрики нет.
func (f *File) Age(now time.Time) (float64, bool) {
	var oldest int64
	found := false
	for _, p := range f.Plans {
		ref := p.LastSuccessMs
		if ref == 0 {
			ref = p.ConfiguredMs
		}
		if ref <= 0 {
			continue
		}
		if !found || ref < oldest {
			oldest, found = ref, true
		}
	}
	if !found {
		return 0, false
	}
	age := now.Sub(time.UnixMilli(oldest)).Seconds()
	if age < 0 {
		age = 0
	}
	return age, true
}
