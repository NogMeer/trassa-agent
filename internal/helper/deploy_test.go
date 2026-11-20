// SPDX-License-Identifier: AGPL-3.0-only

package helper

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/deploy"
	"github.com/NogMeer/trassa-agent/internal/verify"
)

func TestReleaseCode(t *testing.T) {
	bg := context.Background()
	for err, want := range map[error]string{
		fmt.Errorf("x: %w", deploy.ErrHealthcheck):   "HEALTHCHECK_FAILED",
		fmt.Errorf("x: %w", deploy.ErrRegistryAuth):  "REGISTRY_AUTH_FAILED",
		fmt.Errorf("x: %w", deploy.ErrImageGone):     "RELEASE_IMAGE_GONE",
		fmt.Errorf("x: %w", deploy.ErrComposeDenied): "DEPLOY_COMPOSE_FORBIDDEN",
		fmt.Errorf("x: %w", deploy.ErrRoutesStale):   "DEPLOY_ROUTES_STALE",
		errors.New("прочее"):                         CodeApplyFailed,
	} {
		if got := releaseCode(bg, err); got != want {
			t.Errorf("%v: %s, ждали %s", err, got, want)
		}
	}
	ctx, cancel := context.WithTimeout(bg, 0)
	defer cancel()
	<-ctx.Done()
	if got := releaseCode(ctx, ctx.Err()); got != "DEPLOY_TIMEOUT" {
		t.Errorf("срок: %s", got)
	}
}

func (f *fixture) signedCancel(t *testing.T, op, server string, nonce []byte) []byte {
	t.Helper()
	body, _ := proto.Marshal(&agentv1.CancelBody{OperationId: op, ServerId: server, Nonce: nonce,
		NotAfterMs: f.clock.Now().Add(time.Minute).UnixMilli()})
	sig, kid := signWith(panelPriv, keyID, verify.ContextCancel, body)
	raw, _ := proto.Marshal(&agentv1.SignedCancel{Body: body, Signature: sig, KeyId: kid})
	return raw
}

func TestCancel(t *testing.T) {
	f := newFixture(t)
	op := newUUID()
	noStep := func(agentv1.DeployStep, uint32) {}
	if code := f.e.Cancel(f.signedCancel(t, op, serverID, newNonce())); code != CodeCancelUnknown {
		t.Fatalf("без операции: %s", code)
	}
	ctx, step, done := f.e.trackCancel(context.Background(), op, noStep)
	// Чужой сервер, подпись операции вместо отмены — отказ, контекст жив.
	if code := f.e.Cancel(f.signedCancel(t, op, "01a1f4b6-0000-7a5d-ac23-e95c272c0fe8", newNonce())); code != CodeCancelInvalid {
		t.Fatalf("чужой сервер: %s", code)
	}
	body, _ := proto.Marshal(&agentv1.CancelBody{OperationId: op, ServerId: serverID, Nonce: newNonce(), NotAfterMs: f.clock.Now().Add(time.Minute).UnixMilli()})
	sig, kid := signWith(panelPriv, keyID, verify.ContextOperation, body)
	wrongCtx, _ := proto.Marshal(&agentv1.SignedCancel{Body: body, Signature: sig, KeyId: kid})
	if code := f.e.Cancel(wrongCtx); code != CodeCancelInvalid || ctx.Err() != nil {
		t.Fatalf("контекст подписи операции: %s", code)
	}
	n := newNonce()
	if code := f.e.Cancel(f.signedCancel(t, op, serverID, n)); code != "" || !cancelled(ctx) {
		t.Fatalf("отмена: %s", code)
	}
	// После отмены SWITCH не отмечается.
	step(agentv1.DeployStep_DEPLOY_STEP_SWITCH, 0)
	done()
	if code := f.e.Cancel(f.signedCancel(t, op, serverID, n)); code != CodeCancelInvalid {
		t.Fatalf("повтор nonce: %s", code)
	}

	// После SWITCH — CANCEL_TOO_LATE, контекст не отменяется.
	op2 := newUUID()
	ctx2, step2, done2 := f.e.trackCancel(context.Background(), op2, noStep)
	defer done2()
	step2(agentv1.DeployStep_DEPLOY_STEP_SWITCH, 0)
	if code := f.e.Cancel(f.signedCancel(t, op2, serverID, newNonce())); code != CodeCancelTooLate || ctx2.Err() != nil {
		t.Fatalf("после SWITCH: %s %v", code, ctx2.Err())
	}
}
