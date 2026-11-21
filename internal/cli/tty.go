// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"os"

	"golang.org/x/term"
)

// osTerminal — терминал процесса: ввод — Stdin, размер — по Stdout.
type osTerminal struct {
	in, out *os.File
}

// NewTerminal — терминал для trassa ssh.
func NewTerminal(in, out *os.File) Terminal { return &osTerminal{in: in, out: out} }

func (t *osTerminal) Size() (int, int) {
	c, r, err := term.GetSize(int(t.out.Fd()))
	if err != nil {
		return 80, 24
	}
	return c, r
}

// Raw — сырой режим ввода, если ввод — терминал; иначе ничего (ввод из канала или файла).
func (t *osTerminal) Raw() (func(), error) {
	restoreOut := enableVT(t.out)
	fd := int(t.in.Fd())
	if !term.IsTerminal(fd) {
		return restoreOut, nil
	}
	st, err := term.MakeRaw(fd)
	if err != nil {
		restoreOut()
		return nil, err
	}
	return func() {
		_ = term.Restore(fd, st)
		restoreOut()
	}, nil
}
