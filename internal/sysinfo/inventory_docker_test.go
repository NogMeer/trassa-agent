// SPDX-License-Identifier: AGPL-3.0-only

package sysinfo

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Инвентарь контейнеров: метки compose из списка, политика перезапуска и код выхода — из inspect.
func TestInventoryContainersExpectedFields(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "trs")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "d.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Skip(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if i := strings.Index(p[1:], "/"); strings.HasPrefix(p, "/v1.") && i > 0 {
			p = p[i+1:]
		}
		switch p {
		case "/_ping", "/version":
			_, _ = w.Write([]byte(`{"ApiVersion":"1.44"}`))
		case "/containers/json":
			_, _ = w.Write([]byte(`[{"Id":"a1","Names":["/trassa-api-11"],"Image":"api","State":"running","Labels":{"com.docker.compose.project":"trassa","com.docker.compose.service":"api"}},
			 {"Id":"m1","Names":["/migrate"],"Image":"api","State":"exited","Labels":{}}]`))
		case "/containers/a1/json":
			_, _ = w.Write([]byte(`{"State":{"ExitCode":0},"HostConfig":{"RestartPolicy":{"Name":"unless-stopped"}}}`))
		case "/containers/m1/json":
			_, _ = w.Write([]byte(`{"State":{"ExitCode":3},"HostConfig":{"RestartPolicy":{"Name":"on-failure"}}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
	inv := &Inventory{DockerSocket: sock}
	got, note := inv.containers(context.Background())
	if note != "" || len(got) != 2 {
		t.Fatalf("%q %v", note, got)
	}
	a, m := got[0], got[1]
	if a.ComposeProject != "trassa" || a.ComposeService != "api" || a.RestartPolicy != "unless-stopped" || a.ExitCode != 0 {
		t.Fatalf("api: %+v", a)
	}
	if m.ComposeService != "" || m.RestartPolicy != "on-failure" || m.ExitCode != 3 {
		t.Fatalf("migrate: %+v", m)
	}
	if !ContainerExpected(a.RestartPolicy, a.State, a.ExitCode, a.ComposeService) || !ContainerExpected(m.RestartPolicy, m.State, m.ExitCode, m.ComposeService) {
		t.Fatal("признак")
	}
}
