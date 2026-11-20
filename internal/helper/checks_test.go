// SPDX-License-Identifier: AGPL-3.0-only

package helper

import (
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/config"
	"github.com/NogMeer/trassa-agent/internal/helperrpc"
	"github.com/NogMeer/trassa-agent/internal/ops"
	"github.com/NogMeer/trassa-agent/internal/verify"
)

func expectReject(t *testing.T, f *fixture, raw []byte, code string) {
	t.Helper()
	o := f.exec(raw)
	if o.accepted || o.code != code || o.result != nil {
		t.Fatalf("ждали отказ %s, получили accepted=%v code=%q err=%q", code, o.accepted, o.code, o.err)
	}
}

func TestAcceptsValid(t *testing.T) {
	f := newFixture(t)
	o := f.exec(sealed(f.body(ops.TypeSystemInfo, infoParams())))
	if !o.accepted || o.result == nil || o.result.GetOutcome() != agentv1.OperationOutcome_OPERATION_OUTCOME_SUCCEEDED {
		t.Fatalf("%+v", o)
	}
	if o.result.GetSystemInfo().GetHostname() != "vps-1" {
		t.Fatal("нет данных system.info")
	}
}

// Строка 1: подпись верна для одного из ключей панели.
func TestCheck1Signature(t *testing.T) {
	f := newFixture(t)
	b := f.body(ops.TypeSystemInfo, infoParams())
	raw, _ := proto.Marshal(b)
	_, other, _ := ed25519.GenerateKey(nil)
	expectReject(t, f, sealRaw(raw, other, keyID, verify.ContextOperation), ops.CodeSignatureInvalid)
	expectReject(t, f, sealRaw(raw, panelPriv, "unknown-kid", verify.ContextOperation), ops.CodeSignatureInvalid)
	// Подпись подтверждения не годится для операции (разделение назначений).
	expectReject(t, f, sealRaw(raw, panelPriv, keyID, verify.ContextConfirm), ops.CodeSignatureInvalid)
	// Тело изменено после подписи.
	var so agentv1.SignedOperation
	_ = proto.Unmarshal(sealed(b), &so)
	so.Body = append(so.Body, 0x48, 0x01) // dry_run = true
	tampered, _ := proto.Marshal(&so)
	expectReject(t, f, tampered, ops.CodeSignatureInvalid)
	expectReject(t, f, []byte("garbage"), ops.CodeSignatureInvalid)
	// Скомпрометированный шлюз шлёт операцию без подписи (R9).
	unsigned, _ := proto.Marshal(&agentv1.SignedOperation{Body: raw, KeyId: keyID})
	expectReject(t, f, unsigned, ops.CodeSignatureInvalid)
	// Пустой список ключей — отказ всему (R1).
	f.e.Checker.Keys = nil
	expectReject(t, f, sealed(f.body(ops.TypeSystemInfo, infoParams())), ops.CodeSignatureInvalid)
}

// Строка 2: server_id свой.
func TestCheck2Server(t *testing.T) {
	f := newFixture(t)
	b := f.body(ops.TypeSystemInfo, infoParams())
	b.ServerId = "01a1f4b6-0000-7a5d-ac23-e95c272c0fe8"
	expectReject(t, f, sealed(b), ops.CodeServerMismatch)
}

// Строка 3: not_after в будущем и не дальше 10 минут.
func TestCheck3Times(t *testing.T) {
	f := newFixture(t)
	now := f.clock.Now()
	past := f.body(ops.TypeSystemInfo, infoParams())
	past.IssuedAtMs, past.NotAfterMs = now.Add(-10*time.Minute).UnixMilli(), now.Add(-time.Second).UnixMilli()
	expectReject(t, f, sealed(past), ops.CodeExpired)
	far := f.body(ops.TypeSystemInfo, infoParams())
	far.NotAfterMs = now.Add(30 * time.Minute).UnixMilli()
	expectReject(t, f, sealed(far), ops.CodeNotAfterTooFar)
	wide := f.body(ops.TypeSystemInfo, infoParams())
	wide.IssuedAtMs, wide.NotAfterMs = now.Add(-5*time.Minute).UnixMilli(), now.Add(9*time.Minute).UnixMilli()
	expectReject(t, f, sealed(wide), ops.CodeNotAfterTooFar)
	// Часы сервера отстали на 5 минут: операция «из будущего».
	future := f.body(ops.TypeSystemInfo, infoParams())
	future.IssuedAtMs, future.NotAfterMs = now.Add(5*time.Minute).UnixMilli(), now.Add(10*time.Minute).UnixMilli()
	expectReject(t, f, sealed(future), ops.CodeNotAfterTooFar)
	zero := f.body(ops.TypeSystemInfo, infoParams())
	zero.NotAfterMs = 0
	expectReject(t, f, sealed(zero), ops.CodeExpired)
	// В пределах допуска 60 с — принимается.
	skew := f.body(ops.TypeSystemInfo, infoParams())
	skew.IssuedAtMs, skew.NotAfterMs = now.Add(30*time.Second).UnixMilli(), now.Add(10*time.Minute+30*time.Second).UnixMilli()
	if o := f.exec(sealed(skew)); !o.accepted {
		t.Fatalf("расхождение 30 с отклонено: %s", o.code)
	}
}

// Строка 4: nonce не встречался; повтор после перезапуска помощника отклонён.
func TestCheck4Replay(t *testing.T) {
	f := newFixture(t)
	b := f.body(ops.TypeSystemInfo, infoParams())
	first := f.exec(sealed(b))
	if !first.accepted {
		t.Fatal(first.code)
	}
	// Повторная доставка той же операции — не ошибка: тот же итог.
	again := f.exec(sealed(b))
	if !again.accepted || again.result == nil || again.result.GetFinishedAtMs() != first.result.GetFinishedAtMs() {
		t.Fatalf("повтор той же операции: %+v", again)
	}
	// Тот же nonce у другой операции — REPLAY.
	other := f.body(ops.TypeSystemInfo, infoParams())
	other.Nonce = b.Nonce
	expectReject(t, f, sealed(other), ops.CodeReplay)
	// Та же операция с другим nonce — REPLAY.
	renonce := proto.Clone(b).(*agentv1.OperationBody)
	renonce.Nonce = newNonce()
	expectReject(t, f, sealed(renonce), ops.CodeReplay)
	// Перезапуск помощника: окно с диска.
	f.open()
	expectReject(t, f, sealed(other), ops.CodeReplay)
	// nonce не 16 байт.
	short := f.body(ops.TypeSystemInfo, infoParams())
	short.Nonce = short.Nonce[:8]
	expectReject(t, f, sealed(short), ops.CodeParamsInvalid)
}

// Строка 5: тип из зашитого списка.
func TestCheck5Type(t *testing.T) {
	f := newFixture(t)
	for _, typ := range []string{"exec.run", "", "SYSTEM.INFO", "system.info ", "firewall.disable"} {
		expectReject(t, f, sealed(f.body(typ, infoParams())), ops.CodeTypeUnknown)
	}
	if !ops.TestOps {
		expectReject(t, f, sealed(f.body("test.config_write", infoParams())), ops.CodeTypeUnknown)
	}
}

// Строка 6: параметры проходят схему.
func TestCheck6Params(t *testing.T) {
	f := newFixture(t)
	inv := func(kinds ...agentv1.InventoryKind) *agentv1.OperationParams {
		return &agentv1.OperationParams{Params: &agentv1.OperationParams_SystemInventory{SystemInventory: &agentv1.SystemInventoryParams{Include: kinds}}}
	}
	upd := func(mut func(*agentv1.AgentUpdateParams)) *agentv1.OperationParams {
		p := &agentv1.AgentUpdateParams{
			Version:      "1.1.0",
			Artifacts:    []*agentv1.ReleaseArtifact{{Os: "linux", Arch: "amd64", Url: "https://r.example/v1.1.0/trassa-agent-linux-amd64", Sha256: strings.Repeat("a", 64)}},
			SignatureUrl: "https://r.example/v1.1.0/SHA256SUMS.minisig",
		}
		mut(p)
		return &agentv1.OperationParams{Params: &agentv1.OperationParams_AgentUpdate{AgentUpdate: p}}
	}
	cases := map[string]*agentv1.OperationBody{
		"нет params":          f.body(ops.TypeSystemInfo, nil),
		"чужой вариант oneof": f.body(ops.TypeSystemInfo, inv(agentv1.InventoryKind_INVENTORY_KIND_PORTS)),
		"пустой include":      f.body(ops.TypeSystemInventory, inv()),
		"повтор include":      f.body(ops.TypeSystemInventory, inv(1, 1)),
		"неизвестный include": f.body(ops.TypeSystemInventory, inv(9)),
		"версия":              f.body(ops.TypeAgentUpdate, upd(func(p *agentv1.AgentUpdateParams) { p.Version = "latest" })),
		"http":                f.body(ops.TypeAgentUpdate, upd(func(p *agentv1.AgentUpdateParams) { p.Artifacts[0].Url = "http://r.example/trassa-agent-linux-amd64" })),
		"sha256":              f.body(ops.TypeAgentUpdate, upd(func(p *agentv1.AgentUpdateParams) { p.Artifacts[0].Sha256 = "AB" })),
		"arch":                f.body(ops.TypeAgentUpdate, upd(func(p *agentv1.AgentUpdateParams) { p.Artifacts[0].Arch = "riscv64" })),
		"имя файла":           f.body(ops.TypeAgentUpdate, upd(func(p *agentv1.AgentUpdateParams) { p.Artifacts[0].Url = "https://r.example/evil" })),
		"подпись не minisig":  f.body(ops.TypeAgentUpdate, upd(func(p *agentv1.AgentUpdateParams) { p.SignatureUrl = "https://r.example/sig" })),
		"нет артефактов":      f.body(ops.TypeAgentUpdate, upd(func(p *agentv1.AgentUpdateParams) { p.Artifacts = nil })),
		"target не uuid": f.body(ops.TypeRollbackRestore, &agentv1.OperationParams{Params: &agentv1.OperationParams_RollbackRestore{
			RollbackRestore: &agentv1.RollbackRestoreParams{TargetOperationId: "../../etc"}}}),
	}
	badOp := f.body(ops.TypeSystemInfo, infoParams())
	badOp.OperationId = "not-a-uuid"
	cases["operation_id"] = badOp
	rb := f.body(ops.TypeSystemInfo, infoParams())
	rb.Rollback = agentv1.RollbackKind_ROLLBACK_KIND_SNAPSHOT
	cases["rollback не как у типа"] = rb
	cw := f.body(ops.TypeSystemInfo, infoParams())
	cw.ConfirmWithinSec = 30
	cases["confirm_within у READ"] = cw
	for name, b := range cases {
		t.Run(name, func(t *testing.T) {
			if b.GetType() == ops.TypeRollbackRestore {
				b.Rollback = agentv1.RollbackKind_ROLLBACK_KIND_CONFIG
			}
			expectReject(t, f, sealed(b), ops.CodeParamsInvalid)
		})
	}
}

// Строка 7: вызывающий процесс на сокете имеет uid trassa — через настоящий сокет и исполнитель.
func TestCheck7PeerThroughSocket(t *testing.T) {
	f := newFixture(t)
	dir, _ := os.MkdirTemp("/tmp", "trh")
	t.Cleanup(func() { os.RemoveAll(dir) })
	for _, tc := range []struct {
		uid  int
		want string
	}{{os.Getuid() + 1, ops.CodePeerForbidden}, {os.Getuid(), ""}} {
		p := filepath.Join(dir, "h.sock")
		l, err := helperrpc.Listen(p, -1)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() { _ = (&helperrpc.Server{AllowedUID: tc.uid, Handler: f.e}).Serve(ctx, l); close(done) }()
		c := &helperrpc.Client{Path: p, Timeout: 5 * time.Second}
		var code string
		_, err = c.Execute(context.Background(), sealed(f.body(ops.TypeSystemInfo, infoParams())), func(_ bool, c string) { code = c }, nil)
		var re *helperrpc.RemoteError
		if tc.want != "" && (!errors.As(err, &re) || re.Code != tc.want) {
			t.Fatalf("uid %d: ждали %s, получили %v", tc.uid, tc.want, err)
		}
		if tc.want == "" && (err != nil || code != "") {
			t.Fatalf("свой uid: %v %q", err, code)
		}
		cancel()
		<-done
	}
}

// R1: пустой каталог запрещает всё, помощник с ним не стартует.
func TestEmptyCatalog(t *testing.T) {
	if _, err := ops.NewCatalog(); !errors.Is(err, ops.ErrEmptyCatalog) {
		t.Fatal("пустой каталог собран")
	}
	var nilCat *ops.Catalog
	if _, ok := nilCat.Lookup(ops.TypeSystemInfo); ok {
		t.Fatal("nil-каталог знает тип")
	}
	f := newFixture(t)
	f.e.Checker.Catalog = nil
	expectReject(t, f, sealed(f.body(ops.TypeSystemInfo, infoParams())), ops.CodeTypeUnknown)
	if err := (&Executor{Checker: &Checker{}}).CheckHandlers(); !errors.Is(err, ops.ErrEmptyCatalog) {
		t.Fatalf("исполнитель с пустым каталогом: %v", err)
	}
}

// Список типов нельзя изменить конфигурацией: у каталога нет экспортируемых полей и методов изменения, а запись
// о регистрации — единственный файл настроек — не принимает неизвестных полей.
func TestCatalogNotConfigurable(t *testing.T) {
	ct := reflect.TypeOf(ops.Catalog{})
	for i := 0; i < ct.NumField(); i++ {
		if ct.Field(i).IsExported() {
			t.Fatalf("экспортируемое поле каталога %s", ct.Field(i).Name)
		}
	}
	pt := reflect.TypeOf(&ops.Catalog{})
	for i := 0; i < pt.NumMethod(); i++ {
		if name := pt.Method(i).Name; name != "Lookup" && name != "Types" {
			t.Fatalf("метод каталога %s", name)
		}
	}
	et := reflect.TypeOf(config.Enrollment{})
	for i := 0; i < et.NumField(); i++ {
		if n := strings.ToLower(et.Field(i).Name); strings.Contains(n, "type") || strings.Contains(n, "capab") {
			t.Fatalf("поле записи о регистрации %s", et.Field(i).Name)
		}
	}
	want := []string{"agent.uninstall", "agent.update", "firewall.apply", "firewall.plan", "logs.read", "logs.subscribe", "packages.list_updates", "packages.upgrade", "rollback.restore",
		"security.fix.BRUTEFORCE_NO_PROTECTION", "security.fix.KERNEL_ASLR_OFF", "security.fix.PERM_CRON", "security.fix.PERM_SYSTEM_FILES",
		"security.fix.PERM_USER_SSH_DIR", "security.fix.PERM_WORLD_WRITABLE", "security.fix.SSH_CONFIG_PERMS", "security.fix.SYSCTL_NETWORK",
		"security.fix.TIME_SYNC_OFF", "security.fix.UPDATES_AUTO_DISABLED", "security.fix.USER_EMPTY_PASSWORD", "security.fix.USER_SERVICE_SHELL",
		"security.scan", "service.restart", "ssh.harden", "system.info", "system.inventory", "system.reboot"}
	if ops.TestOps {
		want = append(want, "test.config_write")
	}
	if got := ops.Builtin().Types(); !reflect.DeepEqual(got, want) {
		t.Fatalf("список типов %v", got)
	}
}

func TestConfirmChecks(t *testing.T) {
	f := newFixture(t)
	op := newUUID()
	cb := &agentv1.ConfirmBody{OperationId: op, ServerId: serverID, Nonce: newNonce(), NotAfterMs: f.clock.Now().Add(time.Minute).UnixMilli()}
	raw, _ := proto.Marshal(cb)
	// Подпись операции не годится для подтверждения.
	sig, _ := signWith(panelPriv, keyID, verify.ContextOperation, raw)
	wrong, _ := proto.Marshal(&agentv1.SignedConfirm{Body: raw, Signature: sig, KeyId: keyID})
	if _, code := f.e.Confirm(context.Background(), wrong); code != ops.CodeSignatureInvalid {
		t.Fatalf("подпись операции принята для подтверждения: %q", code)
	}
	if _, code := f.confirm(op); code != CodeConfirmUnknown {
		t.Fatalf("подтверждение неизвестной операции: %q", code)
	}
	other := proto.Clone(cb).(*agentv1.ConfirmBody)
	other.ServerId = "01a1f4b6-0000-7a5d-ac23-e95c272c0fe8"
	if _, code := f.e.Confirm(context.Background(), sealConfirm(other)); code != ops.CodeServerMismatch {
		t.Fatalf("чужой сервер: %q", code)
	}
	old := proto.Clone(cb).(*agentv1.ConfirmBody)
	old.NotAfterMs = f.clock.Now().Add(-time.Second).UnixMilli()
	if _, code := f.e.Confirm(context.Background(), sealConfirm(old)); code != ops.CodeExpired {
		t.Fatalf("просроченное: %q", code)
	}
}

func TestDryRunReadAndConcurrency(t *testing.T) {
	f := newFixture(t)
	b := f.body(ops.TypeSystemInfo, infoParams())
	b.DryRun = true
	o := f.exec(sealed(b))
	if o.result.GetPreview() == nil {
		t.Fatal("нет предпросмотра")
	}
	// READ идут параллельно: 8 одновременно завершаются.
	done := make(chan outcome, 8)
	for i := 0; i < 8; i++ {
		go func() { done <- f.exec(sealed(f.body(ops.TypeSystemInfo, infoParams()))) }()
	}
	for i := 0; i < 8; i++ {
		if o := <-done; !o.accepted || o.result == nil {
			t.Fatalf("%+v", o)
		}
	}
}

func TestReportsAndReported(t *testing.T) {
	f := newFixture(t)
	b := f.body(ops.TypeSystemInfo, infoParams())
	o := f.exec(sealed(b))
	reps, err := f.e.Reports()
	if err != nil || len(reps) != 1 {
		t.Fatalf("%d %v", len(reps), err)
	}
	// Подтверждение не того итога ничего не меняет.
	_ = f.e.Reported(b.GetOperationId(), int32(agentv1.OperationOutcome_OPERATION_OUTCOME_FAILED))
	if reps, _ = f.e.Reports(); len(reps) != 1 {
		t.Fatal("подтверждён чужой итог")
	}
	_ = f.e.Reported(b.GetOperationId(), int32(o.result.GetOutcome()))
	if reps, _ = f.e.Reports(); len(reps) != 0 {
		t.Fatal("итог не отмечен доставленным")
	}
}

func TestUninstallSchedules(t *testing.T) {
	f := newFixture(t)
	b := f.body(ops.TypeAgentUninstall, &agentv1.OperationParams{Params: &agentv1.OperationParams_AgentUninstall{AgentUninstall: &agentv1.AgentUninstallParams{PurgeRollback: true}}})
	pv := proto.Clone(b).(*agentv1.OperationBody)
	pv.DryRun, pv.OperationId, pv.Nonce = true, newUUID(), newNonce()
	if o := f.exec(sealed(pv)); len(o.result.GetPreview().GetFiles()) == 0 || len(f.services.scheduled) != 0 {
		t.Fatalf("предпросмотр удаления: %+v", o.result)
	}
	o := f.exec(sealed(b))
	if o.result.GetOutcome() != agentv1.OperationOutcome_OPERATION_OUTCOME_SUCCEEDED || len(f.services.scheduled) != 1 {
		t.Fatalf("%+v %v", o.result, f.services.scheduled)
	}
	s := f.services.scheduled[0]
	if s.unit != "trassa-uninstall" || s.argv[1] != "uninstall" || s.argv[2] != "--purge-rollback" {
		t.Fatalf("%+v", s)
	}
}
