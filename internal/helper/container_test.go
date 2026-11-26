// SPDX-License-Identifier: AGPL-3.0-only

package helper

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/imageupdate"
	"github.com/NogMeer/trassa-agent/internal/ops"
)

type imgDocker struct {
	labels map[string]string
	image  string
	health string
}

func (d *imgDocker) Inspect(_ context.Context, name string) (*imageupdate.Container, error) {
	return &imageupdate.Container{ID: "c1", Name: name, ImageID: "sha256:old", Image: "nginx:1.28", Labels: d.labels, Status: "running"}, nil
}

func (d *imgDocker) Service(context.Context, string, string) ([]imageupdate.Container, error) {
	return []imageupdate.Container{{ID: "c2", Name: "shop-web-1", Image: d.image, Status: "running", Health: d.health}}, nil
}

func (d *imgDocker) Tag(context.Context, string, string, string) error { return nil }

func containerBody(f *fixture) []byte {
	b := f.body(ops.TypeContainerUpdate, &agentv1.OperationParams{Params: &agentv1.OperationParams_ContainerUpdate{ContainerUpdate: &agentv1.ContainerUpdateParams{
		Container: "shop-web-1", Project: "shop", Service: "web", CurrentImage: "nginx:1.28", TargetTag: "1.30", WaitSec: 30}}})
	b.Rollback = agentv1.RollbackKind_ROLLBACK_KIND_RELEASE
	return sealed(b)
}

func TestContainerUpdate(t *testing.T) {
	f := newFixture(t)
	if o := f.exec(containerBody(f)); o.result.GetErrorCode() != CodeContainerUpdateUnavailable {
		t.Fatalf("без окружения: %+v", o.result)
	}
	file := filepath.Join(f.root, "srv/shop/compose.yml")
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("services:\n  web:\n    image: nginx:1.28\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	d := &imgDocker{labels: map[string]string{imageupdate.LabelProject: "shop", imageupdate.LabelService: "web",
		imageupdate.LabelWorkingDir: "/srv/shop", imageupdate.LabelConfigFiles: "/srv/shop/compose.yml"}}
	run := func(_ context.Context, _ []string, _ string, args ...string) ([]byte, []byte, error) {
		if args[len(args)-3] == "config" {
			b, _ := os.ReadFile(file)
			img := strings.TrimSpace(strings.TrimPrefix(strings.Split(string(b), "\n")[2], "    image:"))
			out, _ := json.Marshal(map[string]any{"services": map[string]any{"web": map[string]any{"image": img}}})
			return out, nil, nil
		}
		if args[7] == "up" {
			b, _ := os.ReadFile(file)
			d.image = strings.TrimSpace(strings.TrimPrefix(strings.Split(string(b), "\n")[2], "    image:"))
		}
		return nil, nil, nil
	}
	f.e.Images = &imageupdate.Env{Docker: d, Run: run, Root: f.root, Poll: time.Millisecond, PullTimeout: time.Second, UpTimeout: time.Second}
	prev := imageupdate.WriteFile
	imageupdate.WriteFile = func(p string, b []byte, m os.FileMode) error { return os.WriteFile(p, b, m) }
	t.Cleanup(func() { imageupdate.WriteFile = prev })

	o := f.exec(containerBody(f))
	if o.result.GetOutcome() != agentv1.OperationOutcome_OPERATION_OUTCOME_SUCCEEDED || o.result.GetContainerUpdate().GetNewImage() != "nginx:1.30" ||
		o.result.GetRollbackPoint().GetKind() != agentv1.RollbackKind_ROLLBACK_KIND_RELEASE || o.result.GetRollbackPoint().GetFiles() != 1 {
		t.Fatalf("обновление: %+v", o.result)
	}
	// Новый образ нездоров: файл возвращён, итог ROLLED_BACK с кодом.
	if err := os.WriteFile(file, []byte("services:\n  web:\n    image: nginx:1.28\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	d.image, d.health = "nginx:1.28", ""
	run2 := f.e.Images.Run
	f.e.Images.Run = func(ctx context.Context, env []string, name string, args ...string) ([]byte, []byte, error) {
		out, se, err := run2(ctx, env, name, args...)
		if args[7] == "up" && d.image == "nginx:1.30" {
			d.health = "unhealthy"
		} else if args[7] == "up" {
			d.health = ""
		}
		return out, se, err
	}
	o = f.exec(containerBody(f))
	if o.result.GetOutcome() != agentv1.OperationOutcome_OPERATION_OUTCOME_ROLLED_BACK || o.result.GetErrorCode() != "CONTAINER_NOT_HEALTHY" ||
		!o.result.GetContainerUpdate().GetRolledBack() {
		t.Fatalf("возврат: %+v", o.result)
	}
	if b, _ := os.ReadFile(file); !strings.Contains(string(b), "nginx:1.28") {
		t.Fatalf("файл не возвращён: %s", b)
	}
	// Не compose — FAILED с кодом, без точки отката.
	d.labels = map[string]string{}
	if o := f.exec(containerBody(f)); o.result.GetErrorCode() != "CONTAINER_NOT_COMPOSE" || o.result.GetRollbackPoint() != nil {
		t.Fatalf("не compose: %+v", o.result)
	}
}
