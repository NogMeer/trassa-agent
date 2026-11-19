// SPDX-License-Identifier: AGPL-3.0-only

// Package autorollback — автооткат по таймеру (E05-T19, R14, decisions п. 6).
//
// Два слоя. Запись о сроке в /var/lib/trassa/helper/autorollback/<operation_id>.json (deadline в UTC и boot_id)
// с fsync файла и каталога — до применения. Таймер на текущую загрузку — временный юнит systemd-run, который
// запускает «trassa-helper rollback <operation_id>». Временные юниты лежат в /run и перезагрузку не переживают,
// поэтому при старте помощник поднимает записи: срок вышел — откат сразу, не вышел и boot_id другой — новый таймер
// на остаток. Истина — запись: подтверждение удаляет её, и сработавший позже таймер ничего не делает.
package autorollback

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/NogMeer/trassa-agent/internal/config"
	"github.com/NogMeer/trassa-agent/internal/fsutil"
)

// Виды автооткатa.
const (
	KindConfig = "config" // точка отката CONFIG
	KindUpdate = "update" // сторож agent.update: вернуть bin.prev
)

// Record — запись о сроке.
type Record struct {
	OperationID string `json:"operation_id"`
	Kind        string `json:"kind"`
	DeadlineMs  int64  `json:"deadline_ms"`
	BootID      string `json:"boot_id"`
}

// Store — каталог записей.
type Store struct{ Dir string }

func (s Store) path(op string) (string, error) {
	if !config.IsUUID(op) {
		return "", fmt.Errorf("operation_id %q", op)
	}
	return filepath.Join(s.Dir, strings.ToLower(op)+".json"), nil
}

// Put записывает запись с fsync. Ошибка — операция не применяется (ROLLBACK_UNAVAILABLE).
func (s Store) Put(r Record) error {
	p, err := s.path(r.OperationID)
	if err != nil {
		return err
	}
	if r.Kind != KindConfig && r.Kind != KindUpdate {
		return fmt.Errorf("вид %q", r.Kind)
	}
	raw, _ := json.Marshal(r)
	return fsutil.WriteFileAtomic(p, raw, 0o600, fsutil.Keep)
}

// Get возвращает запись или nil.
func (s Store) Get(op string) (*Record, error) {
	p, err := s.path(op)
	if err != nil {
		return nil, err
	}
	raw, err := fsutil.ReadLimited(p, 64<<10)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var r Record
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Delete удаляет запись с fsync каталога.
func (s Store) Delete(op string) error {
	p, err := s.path(op)
	if err != nil {
		return err
	}
	return fsutil.RemoveSync(p)
}

// List — все записи.
func (s Store) List() ([]Record, error) {
	ents, err := os.ReadDir(s.Dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []Record
	for _, e := range ents {
		name := e.Name()
		if strings.HasPrefix(name, ".") || !strings.HasSuffix(name, ".json") {
			continue
		}
		r, err := s.Get(strings.TrimSuffix(name, ".json"))
		if err != nil {
			return nil, err
		}
		if r != nil {
			out = append(out, *r)
		}
	}
	return out, nil
}

// BootID — идентификатор текущей загрузки.
func BootID(path string) (string, error) {
	if path == "" {
		path = "/proc/sys/kernel/random/boot_id"
	}
	raw, err := fsutil.ReadLimited(path, 128)
	if err != nil {
		return "", err
	}
	id := strings.TrimSpace(string(raw))
	if id == "" {
		return "", errors.New("пустой boot_id")
	}
	return id, nil
}

// Timer заводит и снимает таймер текущей загрузки.
type Timer interface {
	// Arm заводит таймер, который запустит «helper rollback <operationID>».
	Arm(ctx context.Context, operationID string, after time.Duration, helper string) error
	Disarm(ctx context.Context, operationID string) error
}

// UnitName — имя временного юнита.
func UnitName(op string) string { return "trassa-rollback-" + strings.ToLower(op) }

// Systemd — таймер через systemd-run. Команды вызываются напрямую через exec, без оболочки.
type Systemd struct {
	SystemdRun string // /usr/bin/systemd-run
	Systemctl  string // /usr/bin/systemctl
}

// DefaultSystemd — пути на сервере.
func DefaultSystemd() Systemd {
	return Systemd{SystemdRun: "/usr/bin/systemd-run", Systemctl: "/usr/bin/systemctl"}
}

// ArmArgs — аргументы systemd-run (decisions п. 6): монотонный таймер, точность 1 с, выгрузка после
// срабатывания и после ошибки.
func (s Systemd) ArmArgs(op string, after time.Duration, helper string) []string {
	sec := int64((after + time.Second - 1) / time.Second)
	if sec < 1 {
		sec = 1
	}
	return []string{
		"--unit=" + UnitName(op),
		"--on-active=" + strconv.FormatInt(sec, 10) + "s",
		"--timer-property=AccuracySec=1s",
		"--timer-property=RemainAfterElapse=no",
		"--service-type=oneshot",
		"--collect",
		helper, "rollback", strings.ToLower(op),
	}
}

// Arm заводит таймер.
func (s Systemd) Arm(ctx context.Context, op string, after time.Duration, helper string) error {
	if !config.IsUUID(op) || !filepath.IsAbs(helper) {
		return fmt.Errorf("operation_id %q или путь %q", op, helper)
	}
	out, err := exec.CommandContext(ctx, s.SystemdRun, s.ArmArgs(op, after, helper)...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemd-run: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Disarm останавливает таймер. Не загруженный таймер — не ошибка (уже сработал или пережил перезагрузку только
// записью).
func (s Systemd) Disarm(ctx context.Context, op string) error {
	if !config.IsUUID(op) {
		return fmt.Errorf("operation_id %q", op)
	}
	out, err := exec.CommandContext(ctx, s.Systemctl, "stop", UnitName(op)+".timer").CombinedOutput()
	var ee *exec.ExitError
	if errors.As(err, &ee) && ee.ExitCode() == 5 { // юнит не загружен
		return nil
	}
	if err != nil {
		return fmt.Errorf("systemctl stop: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
