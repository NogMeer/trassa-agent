// SPDX-License-Identifier: AGPL-3.0-only

package vpnprobe

import "runtime"

func currentArch() string { return runtime.GOARCH }
