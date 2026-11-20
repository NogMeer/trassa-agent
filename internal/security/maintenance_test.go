// SPDX-License-Identifier: AGPL-3.0-only

package security

import (
	"context"
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
	sys := build(t, tree{})
	rec := &recorder{out: map[string]string{"systemctl restart": "", "systemctl is-active nginx.service": "active\n"}}
	sys.Run = rec.run
	if err := RestartService(context.Background(), sys, "nginx.service"); err != nil {
		t.Fatal(err)
	}
	old := upgradePoll
	upgradePoll = time.Millisecond
	t.Cleanup(func() { upgradePoll = old })
	if err := RestartService(context.Background(), sys, "redis.service"); err == nil {
		t.Fatal("неактивная служба принята")
	}
}
