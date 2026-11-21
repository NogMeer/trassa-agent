// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"slices"
	"testing"
)

func TestParseInterleaved(t *testing.T) {
	fs := newFlags("ssh")
	ws := workspaceFlag(fs)
	l := fs.String("l", "", "")
	direct := fs.Bool("direct", false, "")
	pos, remote, err := parse(fs, []string{"web-1", "--direct", "-w", "mine", "-l", "ops", "--", "ls", "-la"})
	if err != nil || !slices.Equal(pos, []string{"web-1"}) || !slices.Equal(remote, []string{"ls", "-la"}) ||
		*ws != "mine" || *l != "ops" || !*direct {
		t.Fatalf("%v %v %v %q %q %v", pos, remote, err, *ws, *l, *direct)
	}
	if _, _, err := parse(newFlags("x"), []string{"--nope"}); err == nil {
		t.Fatal("неизвестный флаг принят")
	}
}
