// SPDX-License-Identifier: AGPL-3.0-only

package helper

import (
	"bufio"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// holdLock — другой процесс держит блокировку fcntl на path (как apt); pid держателя, снятие — через Cleanup.
func holdLock(t *testing.T, path string) int {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), "TRASSA_TEST_HOLD_LOCK="+path)
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { in.Close(); _ = cmd.Wait() })
	if line, err := bufio.NewReader(out).ReadString('\n'); err != nil || line != "locked\n" {
		t.Fatalf("держатель блокировки не запустился: %q %v", line, err)
	}
	return cmd.Process.Pid
}

// TestMain — временный каталог по настоящему пути: на macOS /var — ссылка на /private/var, а запись помощника
// по ссылкам не идёт (fsutil.OpenNoFollow).
func TestMain(m *testing.M) {
	// Дочерний процесс теста держит блокировку fcntl, как apt или dpkg (holdLock).
	if path := os.Getenv("TRASSA_TEST_HOLD_LOCK"); path != "" {
		f, err := os.OpenFile(path, os.O_RDWR, 0)
		if err != nil {
			os.Exit(2)
		}
		lk := unix.Flock_t{Type: unix.F_WRLCK}
		if unix.FcntlFlock(f.Fd(), unix.F_SETLKW, &lk) != nil {
			os.Exit(3)
		}
		_, _ = os.Stdout.WriteString("locked\n")
		_, _ = io.Copy(io.Discard, os.Stdin) // держит, пока тест не закроет stdin
		os.Exit(0)
	}
	if real, err := filepath.EvalSymlinks(os.TempDir()); err == nil {
		_ = os.Setenv("TMPDIR", real)
	}
	os.Exit(m.Run())
}
