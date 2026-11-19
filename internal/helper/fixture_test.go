// SPDX-License-Identifier: AGPL-3.0-only

package helper

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/autorollback"
	"github.com/NogMeer/trassa-agent/internal/config"
	"github.com/NogMeer/trassa-agent/internal/helperrpc"
	"github.com/NogMeer/trassa-agent/internal/nonce"
	"github.com/NogMeer/trassa-agent/internal/ops"
	"github.com/NogMeer/trassa-agent/internal/rollback"
	"github.com/NogMeer/trassa-agent/internal/verify"
)

const (
	serverID = "01a1f4b6-f327-7a5d-ac23-e95c272c0fe8"
	keyID    = "test-op-key"
)

// Тестовый ключ панели: RFC 8032, 7.1, тест 2 — тот же, что в векторах.
var panelPriv = ed25519.NewKeyFromSeed(must(hex.DecodeString("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")))

func must(b []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return b
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Add(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

type armed struct {
	op     string
	after  time.Duration
	helper string
}

type fakeTimer struct {
	mu     sync.Mutex
	armed  map[string]armed
	failOn bool
}

func (f *fakeTimer) Arm(_ context.Context, op string, after time.Duration, helper string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failOn {
		return os.ErrPermission
	}
	if f.armed == nil {
		f.armed = map[string]armed{}
	}
	f.armed[op] = armed{op, after, helper}
	return nil
}

func (f *fakeTimer) Disarm(_ context.Context, op string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.armed, op)
	return nil
}

func (f *fakeTimer) get(op string) (armed, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	a, ok := f.armed[op]
	return a, ok
}

type scheduled struct {
	unit string
	argv []string
}

type fakeServices struct {
	mu        sync.Mutex
	restarted []string
	scheduled []scheduled
}

func (f *fakeServices) Restart(_ context.Context, units ...string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.restarted = append(f.restarted, units...)
	return nil
}

func (f *fakeServices) Schedule(_ context.Context, unit string, _ time.Duration, argv ...string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.scheduled = append(f.scheduled, scheduled{unit, argv})
	return nil
}

type fakeSystem struct{}

func (fakeSystem) Info(context.Context) (*agentv1.SystemInfoResult, []string) {
	return &agentv1.SystemInfoResult{Hostname: "vps-1", Os: "debian", OsVersion: "12", CpuCores: 2}, nil
}

func (fakeSystem) Inventory(_ context.Context, kinds []agentv1.InventoryKind) (*agentv1.SystemInventoryResult, []string) {
	return &agentv1.SystemInventoryResult{Services: []*agentv1.ServiceEntry{{Name: "ssh.service", State: "active"}}}, nil
}

type fixture struct {
	t        *testing.T
	root     string
	paths    config.Paths
	clock    *clock
	timer    *fakeTimer
	services *fakeServices
	boot     string
	e        *Executor
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	root := t.TempDir()
	f := &fixture{t: t, root: root, paths: config.Under(root), clock: &clock{t: time.Unix(1_800_000_000, 0)},
		timer: &fakeTimer{}, services: &fakeServices{}, boot: "boot-1"}
	for _, d := range []string{f.paths.OpsDir, f.paths.AutoRollbackDir, f.paths.RollbackDir, f.paths.BinDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	f.open()
	return f
}

// open создаёт исполнитель на тех же каталогах — как перезапуск помощника.
func (f *fixture) open() {
	if f.e != nil {
		_ = f.e.Nonces.Close()
	}
	n, err := nonce.Open(f.paths.Nonces, f.clock.Now)
	if err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(func() { _ = n.Close() })
	f.e = &Executor{
		Checker: &Checker{
			Keys:     []verify.PanelKey{{ID: keyID, PublicKey: panelPriv.Public().(ed25519.PublicKey)}},
			ServerID: serverID, Catalog: ops.Builtin(), Nonces: n, Now: f.clock.Now,
		},
		States:   States{Dir: f.paths.OpsDir},
		Nonces:   n,
		Rollback: &rollback.Store{Dir: f.paths.RollbackDir, Now: f.clock.Now},
		Auto:     autorollback.Store{Dir: f.paths.AutoRollbackDir},
		Timer:    f.timer,
		Lock:     FileLock{Path: f.paths.HelperLock},
		BootID:   func() (string, error) { return f.boot, nil },
		Now:      f.clock.Now,
		Version:  "1.0.0",
		System:   fakeSystem{},
		Services: f.services,
		Paths:    f.paths,
	}
	if err := f.e.CheckHandlers(); err != nil {
		f.t.Fatal(err)
	}
}

func newUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

func newNonce() []byte {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return b
}

// body — тело операции по умолчанию: system.info, срок 5 минут.
func (f *fixture) body(typ string, params *agentv1.OperationParams) *agentv1.OperationBody {
	now := f.clock.Now()
	return &agentv1.OperationBody{
		OperationId: newUUID(), ServerId: serverID, Type: typ, Params: params, Nonce: newNonce(),
		NotAfterMs: now.Add(5 * time.Minute).UnixMilli(), IssuedAtMs: now.UnixMilli(),
		Rollback: agentv1.RollbackKind_ROLLBACK_KIND_NONE,
	}
}

func infoParams() *agentv1.OperationParams {
	return &agentv1.OperationParams{Params: &agentv1.OperationParams_SystemInfo{SystemInfo: &agentv1.SystemInfoParams{}}}
}

func signWith(priv ed25519.PrivateKey, kid, context string, body []byte) (sig []byte, k string) {
	return ed25519.Sign(priv, verify.Input(context, body)), kid
}

func sealed(b *agentv1.OperationBody) []byte {
	raw, _ := proto.Marshal(b)
	return sealRaw(raw, panelPriv, keyID, verify.ContextOperation)
}

func sealRaw(body []byte, priv ed25519.PrivateKey, kid, context string) []byte {
	sig, k := signWith(priv, kid, context, body)
	out, _ := proto.Marshal(&agentv1.SignedOperation{Body: body, Signature: sig, KeyId: k})
	return out
}

func sealConfirm(b *agentv1.ConfirmBody) []byte {
	raw, _ := proto.Marshal(b)
	sig, k := signWith(panelPriv, keyID, verify.ContextConfirm, raw)
	out, _ := proto.Marshal(&agentv1.SignedConfirm{Body: raw, Signature: sig, KeyId: k})
	return out
}

type outcome struct {
	accepted bool
	code     string
	progress []*agentv1.OperationProgress
	result   *agentv1.OperationResult
	err      string
}

func (f *fixture) exec(raw []byte) outcome {
	f.t.Helper()
	var o outcome
	f.e.Execute(context.Background(), raw, func(r helperrpc.Response) error {
		switch r.Kind {
		case helperrpc.KindAck:
			o.accepted, o.code = r.Accepted, r.Code
		case helperrpc.KindProgress:
			var p agentv1.OperationProgress
			if err := proto.Unmarshal(r.Progress, &p); err != nil {
				f.t.Fatal(err)
			}
			o.progress = append(o.progress, &p)
		case helperrpc.KindResult:
			var res agentv1.OperationResult
			if err := proto.Unmarshal(r.Result, &res); err != nil {
				f.t.Fatal(err)
			}
			o.result = &res
		case helperrpc.KindError:
			o.err = r.Code
		}
		return nil
	})
	return o
}

func (f *fixture) confirm(op string) (*agentv1.OperationResult, string) {
	raw, code := f.e.Confirm(context.Background(), sealConfirm(&agentv1.ConfirmBody{
		OperationId: op, ServerId: serverID, Nonce: newNonce(), NotAfterMs: f.clock.Now().Add(time.Minute).UnixMilli(),
	}))
	if code != "" {
		return nil, code
	}
	var res agentv1.OperationResult
	if err := proto.Unmarshal(raw, &res); err != nil {
		f.t.Fatal(err)
	}
	return &res, ""
}
