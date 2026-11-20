// SPDX-License-Identifier: AGPL-3.0-only

package helper

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/NogMeer/trassa-agent/internal/deploy"
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
