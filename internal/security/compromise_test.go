// SPDX-License-Identifier: AGPL-3.0-only

package security

import "testing"

func TestCompromiseInstant(t *testing.T) {
	sys := build(t, tree{
		"proc/10/exe": "->/usr/sbin/sshd", "proc/10/comm": "sshd\n",
		"proc/20/exe": "->/tmp/.x/kworker", "proc/20/comm": "kworker\n",
		"proc/30/exe": "->/usr/bin/python3.12 (deleted)", "proc/30/comm": "python3\n",
		"proc/2/comm":       "kthreadd\n",
		"etc/ld.so.preload": "# comment\n/usr/lib/libhide.so\n",
		// 10.0.0.5:51000 → 203.0.113.9:3333 (ESTABLISHED) и обычное к 443.
		"proc/net/tcp": "  sl  local_address rem_address   st\n" +
			"   0: 0500000A:C738 097100CB:0D05 01 00000000:00000000 00:00000000 00000000 0 0 1 1\n" +
			"   1: 0500000A:C739 097100CB:01BB 01 00000000:00000000 00:00000000 00000000 0 0 2 1\n",
	})
	r := scan(t, sys, "COMPROMISE_TMP_EXEC", "COMPROMISE_LD_PRELOAD", "COMPROMISE_OUTBOUND")
	if got := states(r["COMPROMISE_TMP_EXEC"]); got != "FAIL:/tmp/.x/kworker,FAIL:/usr/bin/python3.12" {
		t.Errorf("%s", got)
	}
	if got := states(r["COMPROMISE_LD_PRELOAD"]); got != "FAIL:/etc/ld.so.preload" {
		t.Errorf("%s", got)
	}
	if got := states(r["COMPROMISE_OUTBOUND"]); got != "FAIL:203.0.113.9:3333 (пул майнинга)" {
		t.Errorf("%s", got)
	}
	clean := build(t, tree{"proc/1/exe": "->/usr/lib/systemd/systemd", "etc/ld.so.preload": "\n", "proc/net/tcp": "  sl\n"})
	r = scan(t, clean, "COMPROMISE_TMP_EXEC", "COMPROMISE_LD_PRELOAD", "COMPROMISE_OUTBOUND")
	for code, rs := range r {
		if states(rs) != "PASS:" {
			t.Errorf("%s на чистой системе: %s", code, states(rs))
		}
	}
}
