// SPDX-License-Identifier: AGPL-3.0-only

package access

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// acceptedRe — строка входа по сертификату (одна для OpenSSH 8.9–10.x, decisions E16 п. 8).
var acceptedRe = regexp.MustCompile(`^Accepted publickey for (\S+) from \S+ port \d+ ssh2: \S+-CERT SHA256:\S+ ID (\S+) \(serial (\d+)\) CA `)

// sshdIdentifiers — идентификаторы журнала монитора sshd: sshd (до 9.7), sshd-session (с 9.8), sshd-auth (10.0).
var sshdIdentifiers = []string{"sshd", "sshd-session", "sshd-auth"}

// clockTicks — USER_HZ для поля starttime /proc/<pid>/stat (на Linux — 100).
const clockTicks = 100

// certLogin — вход по сертификату: монитор сеанса и момент записи (мкс с загрузки, того же boot).
type certLogin struct {
	user   string
	keyID  string
	pid    int
	monoUS uint64
	bootID string
}

// certLogins — входы по сертификатам из журнала за 2 суток (последний по каждому pid).
func (e *Env) certLogins(ctx context.Context) ([]certLogin, error) {
	args := []string{"--no-pager", "--quiet", "--output=json", "--since=-48h"}
	for _, id := range sshdIdentifiers {
		args = append(args, "-t", id)
	}
	out, err := e.Run(ctx, "journalctl", args...)
	if err != nil {
		return nil, fmt.Errorf("journalctl: %w", err)
	}
	var res []certLogin
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		var j struct {
			Message string `json:"MESSAGE"`
			PID     string `json:"_PID"`
			Mono    string `json:"__MONOTONIC_TIMESTAMP"`
			Boot    string `json:"_BOOT_ID"`
		}
		if json.Unmarshal(sc.Bytes(), &j) != nil {
			continue
		}
		m := acceptedRe.FindStringSubmatch(j.Message)
		if m == nil {
			continue
		}
		pid, err1 := strconv.Atoi(j.PID)
		mono, err2 := strconv.ParseUint(j.Mono, 10, 64)
		if err1 != nil || err2 != nil || pid <= 1 {
			continue
		}
		res = append(res, certLogin{user: m[1], keyID: m[2], pid: pid, monoUS: mono, bootID: j.Boot})
	}
	return res, nil
}

// sameMonitor — процесс pid — всё ещё тот монитор sshd, что записал вход: тот же boot, исполняемый файл sshd,
// владелец root и процесс стартовал не позже записи (pid не переиспользован после неё).
func (e *Env) sameMonitor(l certLogin) bool {
	if l.bootID != "" {
		if b, err := os.ReadFile(e.path("/proc/sys/kernel/random/boot_id")); err == nil &&
			strings.ReplaceAll(strings.TrimSpace(string(b)), "-", "") != strings.ReplaceAll(l.bootID, "-", "") {
			return false
		}
	}
	proc := e.path(filepath.Join("/proc", strconv.Itoa(l.pid)))
	exe, err := os.Readlink(filepath.Join(proc, "exe"))
	if err != nil {
		return false
	}
	if b := filepath.Base(exe); b != "sshd" && b != "sshd-session" {
		return false
	}
	status, err := os.ReadFile(filepath.Join(proc, "status"))
	if err != nil || !regexp.MustCompile(`(?m)^Uid:\s+0\s`).Match(status) {
		return false
	}
	stat, err := os.ReadFile(filepath.Join(proc, "stat"))
	if err != nil {
		return false
	}
	// Поле 22 после «(comm)»: comm может содержать пробелы и скобки — берём хвост после последней «)».
	rest := string(stat[bytes.LastIndexByte(stat, ')')+1:])
	f := strings.Fields(rest)
	if len(f) < 20 {
		return false
	}
	start, err := strconv.ParseUint(f[19], 10, 64)
	if err != nil {
		return false
	}
	return start*1_000_000/clockTicks <= l.monoUS
}

// sessionOf — сеанс logind процесса из /proc/<pid>/cgroup (session-N.scope).
func (e *Env) sessionOf(pid int) string {
	b, err := os.ReadFile(e.path(filepath.Join("/proc", strconv.Itoa(pid), "cgroup")))
	if err != nil {
		return ""
	}
	if m := regexp.MustCompile(`/session-([A-Za-z0-9]+)\.scope`).FindSubmatch(b); m != nil {
		return string(m[1])
	}
	return ""
}

// TerminateCerts — закрыть прямые сеансы по keyId сертификатов: сеанс logind монитора целиком, без него —
// SIGTERM монитору, через 2 с SIGKILL. Возвращает закрытые и не найденные keyId.
func (e *Env) TerminateCerts(ctx context.Context, keyIDs []string) (terminated, notFound []string, err error) {
	logins, err := e.certLogins(ctx)
	if err != nil {
		return nil, nil, err
	}
	want := map[string]bool{}
	for _, k := range keyIDs {
		want[k] = true
	}
	done := map[string]bool{}
	for _, l := range logins {
		if !want[l.keyID] || !e.sameMonitor(l) {
			continue
		}
		if s := e.sessionOf(l.pid); s != "" {
			if _, err := e.Run(ctx, "loginctl", "terminate-session", s); err == nil {
				done[l.keyID] = true
				continue
			}
		}
		if e.signal(l.pid) {
			done[l.keyID] = true
		}
	}
	for _, k := range keyIDs {
		if done[k] {
			terminated = append(terminated, k)
		} else {
			notFound = append(notFound, k)
		}
	}
	return terminated, notFound, nil
}

// signal — SIGTERM, через 2 с SIGKILL (если ещё жив).
func (e *Env) signal(pid int) bool {
	if e.Root != "/" {
		return false // в тестах чужим процессам сигналы не шлём
	}
	if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
		return false
	}
	time.Sleep(2 * time.Second)
	_ = syscall.Kill(pid, syscall.SIGKILL)
	return true
}
