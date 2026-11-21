// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"
	"syscall"
)

// Local — локальные настройки сервера из /etc/trassa/agent.toml (E20). Файл пишет только владелец сервера; панель
// и агент изменить его не могут.
type Local struct {
	// AllowExec — разрешена ли exec.run (произвольная команда).
	AllowExec bool
}

// ErrLocalInvalid — файл не прошёл проверку: настройки считаются выключенными.
var ErrLocalInvalid = errors.New("agent.toml invalid")

// MaxLocalBytes — предел размера agent.toml.
const MaxLocalBytes = 16 << 10

// LocalTemplate — файл, который ставит установщик (allow_exec выключена).
const LocalTemplate = `# Локальные настройки агента Trassa. Панель изменить этот файл не может.
# allow_exec = true разрешает ИИ-оператору произвольные команды (exec.run): каждый запуск всё равно
# подтверждается в панели и проходит запреты. После правки: systemctl restart trassa-helper trassa-agent.
allow_exec = false
`

// LoadLocal читает agent.toml. Нет файла — всё выключено без ошибки. Файл не root, доступен на запись группе или
// остальным, ссылка, не обычный файл, больше предела или с неизвестным ключом — всё выключено и ErrLocalInvalid:
// агент работает от trassa, и файл, который он мог бы переписать, не должен включать exec.run.
//
// Разбор — строгое подмножество TOML: строки «ключ = true|false», комментарии «#» и пустые строки.
func LoadLocal(path string) (Local, error) { return loadLocal(path, 0) }

func loadLocal(path string, owner uint32) (Local, error) {
	bad := func(format string, a ...any) (Local, error) {
		return Local{}, fmt.Errorf("%w: %s: %s", ErrLocalInvalid, path, fmt.Sprintf(format, a...))
	}
	// O_NOFOLLOW и O_NONBLOCK: ссылка — отказ, FIFO не повесит помощник; проверки — по открытому дескриптору.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, fs.ErrNotExist) {
		return Local{}, nil
	}
	if errors.Is(err, syscall.ELOOP) {
		return bad("ссылка")
	}
	if err != nil {
		return Local{}, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return Local{}, err
	}
	if !fi.Mode().IsRegular() {
		return bad("не обычный файл")
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return bad("доступен на запись группе или остальным (%#o)", fi.Mode().Perm())
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != owner {
		return bad("владелец не root")
	}
	raw, err := io.ReadAll(io.LimitReader(f, MaxLocalBytes+1))
	if err != nil {
		return bad("%v", err)
	}
	if len(raw) > MaxLocalBytes {
		return bad("больше %d байт", MaxLocalBytes)
	}
	var l Local
	seen := map[string]bool{}
	sc := bufio.NewScanner(bytes.NewReader(raw))
	for n := 1; sc.Scan(); n++ {
		line := sc.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if !ok || seen[k] {
			return bad("строка %d", n)
		}
		seen[k] = true
		switch k {
		case "allow_exec":
			switch v {
			case "true":
				l.AllowExec = true
			case "false":
			default:
				return bad("строка %d: allow_exec — true или false", n)
			}
		default:
			return bad("строка %d: неизвестный ключ", n)
		}
	}
	if err := sc.Err(); err != nil {
		return bad("%v", err)
	}
	return l, nil
}
