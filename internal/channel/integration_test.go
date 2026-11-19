// SPDX-License-Identifier: AGPL-3.0-only

package channel

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/autorollback"
	"github.com/NogMeer/trassa-agent/internal/config"
	"github.com/NogMeer/trassa-agent/internal/helper"
	"github.com/NogMeer/trassa-agent/internal/helperrpc"
	"github.com/NogMeer/trassa-agent/internal/nonce"
	"github.com/NogMeer/trassa-agent/internal/ops"
	"github.com/NogMeer/trassa-agent/internal/rollback"
)

type staticSystem struct{}

func (staticSystem) Info(context.Context) (*agentv1.SystemInfoResult, []string) {
	return &agentv1.SystemInfoResult{Hostname: "vps-int", Os: "ubuntu", OsVersion: "24.04"}, nil
}

func (staticSystem) Inventory(context.Context, []agentv1.InventoryKind) (*agentv1.SystemInventoryResult, []string) {
	return &agentv1.SystemInventoryResult{}, nil
}

type noTimer struct{}

func (noTimer) Arm(context.Context, string, time.Duration, string) error { return nil }
func (noTimer) Disarm(context.Context, string) error                     { return nil }

// Агент, настоящий помощник за Unix-сокетом и тестовый шлюз: операция system.info проходит путь целиком,
// повтор той же операции после переподключения не выполняется заново, а получает готовый итог.
func TestIntegrationWithHelper(t *testing.T) {
	root := t.TempDir()
	p := config.Under(root)
	for _, d := range []string{p.OpsDir, p.AutoRollbackDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	n, err := nonce.Open(p.Nonces, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	ex := &helper.Executor{
		Checker:  &helper.Checker{Keys: panelKeys(), ServerID: serverID, Catalog: ops.Builtin(), Nonces: n},
		States:   helper.States{Dir: p.OpsDir},
		Nonces:   n,
		Rollback: &rollback.Store{Dir: p.RollbackDir},
		Auto:     autorollback.Store{Dir: p.AutoRollbackDir},
		Timer:    noTimer{},
		Lock:     helper.FileLock{Path: p.HelperLock},
		BootID:   func() (string, error) { return "b", nil },
		Version:  "1.0.0",
		System:   staticSystem{},
		Paths:    p,
	}
	if err := ex.CheckHandlers(); err != nil {
		t.Fatal(err)
	}
	sockDir, _ := os.MkdirTemp("/tmp", "trh")
	t.Cleanup(func() { os.RemoveAll(sockDir) })
	sock := filepath.Join(sockDir, "h.sock")
	l, err := helperrpc.Listen(sock, -1)
	if err != nil {
		t.Fatal(err)
	}
	hctx, hcancel := context.WithCancel(context.Background())
	hdone := make(chan struct{})
	go func() { _ = (&helperrpc.Server{AllowedUID: os.Getuid(), Handler: ex}).Serve(hctx, l); close(hdone) }()
	defer func() { hcancel(); <-hdone }()

	id := newIdentity(t)
	op := signedOp(t, opID(42))
	results := make(chan *agentv1.OperationResult, 4)
	var conns atomic.Int32
	g := newGateway(t, id.PublicKey(), func(ctx context.Context, c *gwConn) {
		n := conns.Add(1)
		if c.hello.GetHelperVersion() != "1.0.0" || len(c.hello.GetCapabilities()) == 0 {
			t.Errorf("Hello без данных помощника: %+v", c.hello)
		}
		_ = c.send(ctx, &agentv1.GatewayMessage{Payload: &agentv1.GatewayMessage_Operation{Operation: op}})
		for {
			m, err := c.read(ctx)
			if err != nil {
				return
			}
			if r := m.GetOperationResult(); r != nil {
				results <- r
				if n == 1 {
					return // первая сессия рвётся без квитанции
				}
				_ = c.send(ctx, &agentv1.GatewayMessage{Payload: &agentv1.GatewayMessage_InboundAck{InboundAck: &agentv1.InboundAck{Seq: m.GetSeq()}}})
			}
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error)
	go func() { done <- newAgent(t, id, g, &helperrpc.Client{Path: sock, Timeout: 5 * time.Second}).Run(ctx) }()
	var first *agentv1.OperationResult
	select {
	case first = <-results:
	case <-time.After(5 * time.Second):
		t.Fatal("нет итога")
	}
	if first.GetSystemInfo().GetHostname() != "vps-int" || first.GetOutcome() != agentv1.OperationOutcome_OPERATION_OUTCOME_SUCCEEDED {
		t.Fatalf("%+v", first)
	}
	waitFor(t, 5*time.Second, func() bool {
		reps, _ := ex.Reports()
		return len(reps) == 0
	}, "итог отмечен доставленным у помощника")
	cancel()
	<-done
	// Повторная доставка дала тот же итог (тот же finished_at), а не новое выполнение.
	for len(results) > 0 {
		if r := <-results; r.GetFinishedAtMs() != first.GetFinishedAtMs() {
			t.Fatal("операция выполнена повторно")
		}
	}
}
