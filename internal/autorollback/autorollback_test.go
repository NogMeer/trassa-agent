// SPDX-License-Identifier: AGPL-3.0-only

package autorollback

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

const op = "01a1f4b6-f2f2-7e66-85b4-8ff564561ccb"

func TestStore(t *testing.T) {
	s := Store{Dir: t.TempDir()}
	if r, err := s.Get(op); err != nil || r != nil {
		t.Fatalf("пустой каталог: %v %v", r, err)
	}
	rec := Record{OperationID: op, Kind: KindConfig, DeadlineMs: 123, BootID: "b"}
	if err := s.Put(rec); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(Record{OperationID: op, Kind: "other"}); err == nil {
		t.Fatal("неизвестный вид принят")
	}
	if err := s.Put(Record{OperationID: "../x", Kind: KindConfig}); err == nil {
		t.Fatal("путь вместо operation_id принят")
	}
	got, err := s.Get(op)
	if err != nil || !reflect.DeepEqual(*got, rec) {
		t.Fatalf("%+v %v", got, err)
	}
	list, _ := s.List()
	if len(list) != 1 {
		t.Fatalf("записей %d", len(list))
	}
	if err := s.Delete(op); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(op); err != nil {
		t.Fatal("повторное удаление — ошибка")
	}
}

func TestArmArgs(t *testing.T) {
	got := DefaultSystemd().ArmArgs(op, 1500*time.Millisecond, "/usr/local/bin/trassa-helper")
	want := []string{
		"--unit=trassa-rollback-" + op, "--on-active=2s", "--timer-property=AccuracySec=1s",
		"--timer-property=RemainAfterElapse=no", "--service-type=oneshot", "--collect",
		"/usr/local/bin/trassa-helper", "rollback", op,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%v", got)
	}
}

func TestBootID(t *testing.T) {
	p := filepath.Join(t.TempDir(), "boot_id")
	_ = os.WriteFile(p, []byte("abc\n"), 0o600)
	if id, err := BootID(p); err != nil || id != "abc" {
		t.Fatalf("%q %v", id, err)
	}
	_ = os.WriteFile(p, []byte("\n"), 0o600)
	if _, err := BootID(p); err == nil {
		t.Fatal("пустой boot_id принят")
	}
}
