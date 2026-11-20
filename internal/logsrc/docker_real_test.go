// SPDX-License-Identifier: AGPL-3.0-only

//go:build dockerint

package logsrc

import (
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/dockerapi"
)

// Настоящий Docker раннера CI (тег dockerint): контейнер без TTY пишет в stdout и stderr, помощник читает
// мультиплексный поток API. Локально не запускается: Docker — только в CI.
func TestDockerReal(t *testing.T) {
	name := "trassa-ci-logs"
	_ = exec.Command("docker", "rm", "-f", name).Run()
	start := time.Now().Add(-time.Second)
	out, err := exec.Command("docker", "run", "--name", name, "busybox:1.37", "sh", "-c",
		"echo out-line; echo 'ERROR err-line token=ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' >&2").CombinedOutput()
	if err != nil {
		t.Fatalf("docker run: %v %s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", name).Run() })
	r := &Reader{Docker: &dockerapi.Client{}, Now: time.Now}
	sub := &Subscription{CreatedAtMs: start.UnixMilli(), Sources: []*agentv1.LogSource{dockerSrc(name)}}
	recs, _, _, errs := r.Poll(context.Background(), sub, nil)
	if len(errs) != 0 || len(recs) != 2 {
		t.Fatalf("%v %v", recs, errs)
	}
	got := map[string]string{}
	for _, x := range recs {
		got[x.GetFields()["stream"]] = x.GetMessage()
	}
	if got["stdout"] != "out-line" || !strings.HasPrefix(got["stderr"], "ERROR err-line") || strings.Contains(got["stderr"], "ghp_") {
		t.Fatalf("%v", got)
	}
}
