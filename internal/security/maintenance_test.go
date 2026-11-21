// SPDX-License-Identifier: AGPL-3.0-only

package security

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
)

func TestUpgradeSecurityOnly(t *testing.T) {
	sys := build(t, tree{})
	running := "cron.service loaded active running Cron\nnginx.service loaded active running nginx\n"
	rec := &recorder{out: map[string]string{
		"apt-get update": "", "apt-get -s": simUbuntu, "apt-get -y": "", "dpkg --audit": "",
	}}
	sys.Run = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name == "systemctl" && args[0] == "list-units" {
			return []byte(running), nil
		}
		return rec.run(ctx, name, args...)
	}
	before, err := RunningServices(context.Background(), sys)
	if err != nil || strings.Join(before, ",") != "cron.service,nginx.service" {
		t.Fatalf("%v %v", before, err)
	}
	n, err := Upgrade(context.Background(), sys, agentv1.UpgradeScope_UPGRADE_SCOPE_SECURITY)
	if err != nil || n != 1 {
		t.Fatalf("%d %v", n, err)
	}
	last := rec.calls[len(rec.calls)-1]
	if !strings.Contains(last, "install --only-upgrade -- libc6") || strings.Contains(last, "tzdata") || !strings.Contains(last, "--force-confold") {
		t.Fatalf("%s", last)
	}
	if err := VerifyUpgrade(context.Background(), sys, before); err != nil {
		t.Fatal(err)
	}
	// Служба, работавшая до обновления, не поднялась — проверка падает с её именем.
	old := upgradePoll
	upgradePoll = time.Millisecond
	t.Cleanup(func() { upgradePoll = old })
	running = "cron.service loaded active running Cron\n"
	if err := VerifyUpgrade(context.Background(), sys, before); err == nil || !strings.Contains(err.Error(), "nginx.service") {
		t.Fatalf("%v", err)
	}
	if _, err := PlanUpgrade(context.Background(), sys, 0); err == nil {
		t.Fatal("scope 0 принят")
	}
}

func TestServiceRestart(t *testing.T) {
	for _, u := range []string{"trassa-helper.service", "nginx", "-x.service", "a b.service", ""} {
		if ValidateServiceRestart(&agentv1.ServiceRestartParams{Unit: u}) == nil {
			t.Errorf("%q принят", u)
		}
	}
	if err := ValidateServiceRestart(&agentv1.ServiceRestartParams{Unit: "nginx.service"}); err != nil {
		t.Fatal(err)
	}
	// E18: контейнер — только имя контейнера и без unit; unit — без container.
	for name, p := range map[string]*agentv1.ServiceRestartParams{
		"контейнер без имени":  {Kind: agentv1.ServiceTargetKind_SERVICE_TARGET_KIND_CONTAINER},
		"контейнер и unit":     {Kind: agentv1.ServiceTargetKind_SERVICE_TARGET_KIND_CONTAINER, Container: "web", Unit: "nginx.service"},
		"имя с /":              {Kind: agentv1.ServiceTargetKind_SERVICE_TARGET_KIND_CONTAINER, Container: "../web"},
		"unit и container":     {Unit: "nginx.service", Container: "web"},
		"неизвестный вид цели": {Kind: 9, Unit: "nginx.service"},
	} {
		if ValidateServiceRestart(p) == nil {
			t.Errorf("%s: принято", name)
		}
	}
	if err := ValidateServiceRestart(&agentv1.ServiceRestartParams{Kind: agentv1.ServiceTargetKind_SERVICE_TARGET_KIND_CONTAINER, Container: "web_1"}); err != nil {
		t.Fatal(err)
	}
}

// Чужая блокировка apt/dpkg видна до начала работы: файл, процесс-держатель; снята — свободно.
func TestPackageManagerBusy(t *testing.T) {
	sys := build(t, tree{"var/lib/dpkg/lock-frontend": "", "var/lib/apt/lists/lock": ""})
	if h, err := PackageManagerBusy(sys); err != nil || h != nil {
		t.Fatalf("свободно: %+v %v", h, err)
	}
	pid := holdLock(t, filepath.Join(sys.Root, "var/lib/apt/lists/lock"))
	comm := filepath.Join(sys.Root, "proc", strconv.Itoa(pid), "comm")
	_ = os.MkdirAll(filepath.Dir(comm), 0o755)
	_ = os.WriteFile(comm, []byte("unattended-upgr\n"), 0o644)
	h, err := PackageManagerBusy(sys)
	if err != nil || h == nil || h.Path != "/var/lib/apt/lists/lock" || h.PID != pid || h.Comm != "unattended-upgr" {
		t.Fatalf("занято: %+v %v", h, err)
	}
	if !strings.Contains(h.String(), "unattended-upgr (pid ") {
		t.Fatalf("%s", h)
	}
}
