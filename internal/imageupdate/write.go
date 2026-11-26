// SPDX-License-Identifier: AGPL-3.0-only

package imageupdate

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"github.com/NogMeer/trassa-agent/internal/fsutil"
)

// writeKeepOwner — атомарная запись без ссылок на пути, с прежними правами и владельцем файла.
func writeKeepOwner(path string, data []byte, mode os.FileMode) error {
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	owner := fsutil.Keep
	if s, ok := st.Sys().(*syscall.Stat_t); ok {
		owner = fsutil.Owner{UID: int(s.Uid), GID: int(s.Gid)}
	}
	return fsutil.WriteAtomicNoFollow(path, mode, owner, func(w io.Writer) error {
		_, err := w.Write(data)
		return err
	})
}

var systemPath = []string{"/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"}

// Exec — Runner для сервера: программа из системных каталогов (не из PATH окружения), без оболочки, каталог «/»,
// вывод — до 4 МиБ, ошибки — до 64 КиБ.
func Exec(ctx context.Context, env []string, name string, args ...string) ([]byte, []byte, error) {
	bin := ""
	for _, d := range systemPath {
		p := filepath.Join(d, name)
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() && st.Mode().Perm()&0o111 != 0 {
			bin = p
			break
		}
	}
	if bin == "" {
		return nil, nil, fmt.Errorf("%w: %s не найден", ErrDocker, name)
	}
	c := exec.CommandContext(ctx, bin, args...)
	c.Env, c.Dir, c.WaitDelay = env, "/", 10*time.Second
	var out, stderr bytes.Buffer
	c.Stdout, c.Stderr = &capped{b: &out, n: 4 << 20}, &capped{b: &stderr, n: 64 << 10}
	err := c.Run()
	return out.Bytes(), stderr.Bytes(), err
}

type capped struct {
	b *bytes.Buffer
	n int
}

func (c *capped) Write(p []byte) (int, error) {
	if room := c.n - c.b.Len(); room > 0 {
		if len(p) > room {
			c.b.Write(p[:room])
		} else {
			c.b.Write(p)
		}
	}
	return len(p), nil
}
