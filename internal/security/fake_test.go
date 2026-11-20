// SPDX-License-Identifier: AGPL-3.0-only

package security

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
)

// fakeDocker — список контейнеров body и inspect с Privileged для id из privileged.
type fakeDocker struct {
	body       string
	privileged map[string]bool
}

func (f *fakeDocker) Get(_ context.Context, path string) (*http.Response, error) {
	b := f.body
	if path != "/containers/json" && strings.HasPrefix(path, "/containers/") && strings.HasSuffix(path, "/json") {
		id := strings.TrimSuffix(strings.TrimPrefix(path, "/containers/"), "/json")
		b = `{"HostConfig":{"Privileged":` + map[bool]string{true: "true", false: "false"}[f.privileged[id]] + `}}`
	}
	return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader([]byte(b)))}, nil
}
