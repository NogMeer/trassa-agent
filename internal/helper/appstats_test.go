// SPDX-License-Identifier: AGPL-3.0-only

package helper

import (
	"context"
	"testing"

	"google.golang.org/protobuf/proto"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/helperrpc"
)

// app.stats без настроенного сбора — пустая пачка, а не ошибка канала.
func TestAppStatsMethodEmpty(t *testing.T) {
	f := newFixture(t)
	var got helperrpc.Response
	f.e.Serve(context.Background(), helperrpc.Request{Method: helperrpc.MethodAppStats}, func(r helperrpc.Response) error {
		got = r
		return nil
	})
	var b agentv1.MetricsBatch
	if got.Kind != helperrpc.KindAppStats || proto.Unmarshal(got.Result, &b) != nil || len(b.GetMetrics()) != 0 {
		t.Fatalf("%+v", got)
	}
}
