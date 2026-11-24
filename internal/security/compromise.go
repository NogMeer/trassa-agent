// SPDX-License-Identifier: AGPL-3.0-only

package security

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/NogMeer/trassa-agent/internal/sysinfo"
)

// Признаки взлома, видимые сразу (E10, раздел 6, детектор). Находки COMPROMISE_* не исправляются кнопкой:
// на взломанном сервере автоматике доверять нельзя.
func init() {
	register(Check{Code: "COMPROMISE_TMP_EXEC", Run: checkTmpExec})
	register(Check{Code: "COMPROMISE_LD_PRELOAD", Run: checkLdPreload})
	register(Check{Code: "COMPROMISE_OUTBOUND", Run: checkOutbound})
}

// Каталоги, из которых запуск подозрителен.
var tmpDirs = []string{"/tmp/", "/var/tmp/", "/dev/shm/"}

// Process — процесс для признаков детектора.
type Process struct {
	PID     int
	Comm    string
	Exe     string
	Deleted bool
}

// Processes — процессы с путём к исполняемому файлу (/proc/<pid>/exe, нужен root). Потоки ядра без exe пропускаются.
func (sys *System) Processes() ([]Process, error) {
	ents, err := os.ReadDir(sys.path("/proc"))
	if err != nil {
		return nil, err
	}
	var out []Process
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		exe, err := os.Readlink(sys.path(fmt.Sprintf("/proc/%d/exe", pid)))
		if err != nil || exe == "" {
			continue
		}
		comm, _ := os.ReadFile(sys.path(fmt.Sprintf("/proc/%d/comm", pid)))
		p := Process{PID: pid, Comm: strings.TrimSpace(string(comm)), Exe: exe}
		if strings.HasSuffix(exe, " (deleted)") {
			p.Deleted = true
			p.Exe = strings.TrimSuffix(exe, " (deleted)")
		}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PID < out[j].PID })
	return out, nil
}

// SuspiciousExec — процесс запущен из временного каталога или его файл удалён.
func SuspiciousExec(p Process) bool {
	if p.Deleted {
		return true
	}
	for _, d := range tmpDirs {
		if strings.HasPrefix(p.Exe, d) {
			return true
		}
	}
	return false
}

func checkTmpExec(_ context.Context, s *Scan) []Finding {
	ps, err := s.sys.Processes()
	if err != nil {
		return []Finding{failed(ErrReadFailed, err)}
	}
	var out []Finding
	for _, p := range ps {
		if !SuspiciousExec(p) {
			continue
		}
		why := "запущен из временного каталога"
		if p.Deleted {
			why = "файл процесса удалён"
		}
		out = append(out, fail(p.Exe, fmt.Sprintf("процесс %d (%s) %s: %s", p.PID, p.Comm, why, p.Exe)))
	}
	return out
}

func checkLdPreload(_ context.Context, s *Scan) []Finding {
	b, err := os.ReadFile(s.sys.path("/etc/ld.so.preload"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return []Finding{failed(ErrReadFailed, err)}
	}
	var libs []string
	for _, l := range strings.Fields(string(b)) {
		if !strings.HasPrefix(l, "#") {
			libs = append(libs, l)
		}
	}
	if len(libs) == 0 {
		return nil
	}
	return []Finding{fail("/etc/ld.so.preload", "во все процессы подгружается: "+strings.Join(libs, ", "))}
}

// SuspiciousPorts — порты назначения исходящих соединений, типичные для пулов майнинга и IRC-управления. Список —
// решение продукта (E10, раздел 13, вопрос 16), на парке не сверен.
var SuspiciousPorts = map[uint16]string{
	3333: "пул майнинга", 4444: "пул майнинга", 5555: "пул майнинга", 7777: "пул майнинга",
	14444: "пул майнинга", 45700: "пул майнинга", 6667: "IRC",
}

// outboundConn — подозрительное исходящее соединение: Subject — «адрес:порт (причина)» (ключ находки), Process —
// владелец сокета («comm, pid N»), пусто — не найден.
type outboundConn struct {
	Subject string
	Process string
}

type tcpRow struct {
	local, remote netip.Addr
	lport, rport  uint16
	state, inode  string
}

func readTCP(sys *System) ([]tcpRow, error) {
	var rows []tcpRow
	for _, n := range []struct {
		file string
		v6   bool
	}{{"tcp", false}, {"tcp6", true}} {
		b, err := os.ReadFile(sys.path("/proc/net/" + n.file))
		if err != nil {
			if os.IsNotExist(err) && n.v6 {
				continue
			}
			return nil, err
		}
		for i, l := range strings.Split(string(b), "\n") {
			f := strings.Fields(l)
			if i == 0 || len(f) < 4 {
				continue
			}
			lh, lp, ok1 := strings.Cut(f[1], ":")
			rh, rp, ok2 := strings.Cut(f[2], ":")
			if !ok1 || !ok2 {
				continue
			}
			lport, err1 := strconv.ParseUint(lp, 16, 16)
			rport, err2 := strconv.ParseUint(rp, 16, 16)
			la, ok3 := procAddr(lh, n.v6)
			ra, ok4 := procAddr(rh, n.v6)
			if err1 != nil || err2 != nil || !ok3 || !ok4 {
				continue
			}
			r := tcpRow{local: la, remote: ra, lport: uint16(lport), rport: uint16(rport), state: f[3]}
			if len(f) > 9 {
				r.inode = f[9]
			}
			rows = append(rows, r)
		}
	}
	return rows, nil
}

// outbound — установленные исходящие TCP-соединения (st 01) к удалённому порту из списка. Входящее соединение к
// службе сервера тоже ESTABLISHED, и у него удалённый порт — случайный исходный порт клиента (прод, MeerGuard: клиенты
// VPN с портами 3333, 5555, 6667…). Поэтому соединение, чей локальный порт прослушивается (LISTEN, st 0A) на том же
// адресе или на 0.0.0.0 и ::, — входящее и не считается.
func outbound(sys *System) ([]outboundConn, error) {
	rows, err := readTCP(sys)
	if err != nil {
		return nil, err
	}
	type lkey struct {
		addr netip.Addr
		port uint16
	}
	listen := map[lkey]bool{}
	for _, r := range rows {
		if r.state == "0A" {
			listen[lkey{r.local, r.lport}] = true
		}
	}
	wild4, wild6 := netip.IPv4Unspecified(), netip.IPv6Unspecified()
	incoming := func(r tcpRow) bool {
		return listen[lkey{r.local, r.lport}] || listen[lkey{wild4, r.lport}] || listen[lkey{wild6, r.lport}]
	}
	var found []tcpRow
	for _, r := range rows {
		if r.state != "01" || incoming(r) {
			continue
		}
		if _, bad := SuspiciousPorts[r.rport]; bad {
			found = append(found, r)
		}
	}
	var owners map[string]string
	if len(found) > 0 {
		owners = socketOwners(sys)
	}
	out := make([]outboundConn, 0, len(found))
	for _, r := range found {
		out = append(out, outboundConn{
			// AddrPort: IPv6 в скобках ([2001:db8::2]:6667), IPv4 — как раньше (ключ прежних находок не меняется).
			Subject: fmt.Sprintf("%s (%s)", netip.AddrPortFrom(r.remote, r.rport), SuspiciousPorts[r.rport]),
			Process: owners[r.inode],
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Subject < out[j].Subject })
	return out, nil
}

// socketOwners — inode сокета → «comm, pid N» по /proc/<pid>/fd. Исчезнувшие во время обхода процессы пропускаются.
func socketOwners(sys *System) map[string]string {
	out := map[string]string{}
	ents, err := os.ReadDir(sys.path("/proc"))
	if err != nil {
		return out
	}
	for _, e := range ents {
		pid := e.Name()
		if _, err := strconv.Atoi(pid); err != nil {
			continue
		}
		fdDir := sys.path("/proc/" + pid + "/fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		owner := ""
		for _, fd := range fds {
			link, err := os.Readlink(fdDir + "/" + fd.Name())
			if err != nil || !strings.HasPrefix(link, "socket:[") {
				continue
			}
			inode := strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")
			if owner == "" {
				comm, _ := os.ReadFile(sys.path("/proc/" + pid + "/comm"))
				owner = sysinfo.Clean(string(comm)) + ", pid " + pid
			}
			if _, ok := out[inode]; !ok {
				out[inode] = owner
			}
		}
	}
	return out
}

// outboundText — текст находки: куда и, если найден, какой процесс.
func outboundText(c outboundConn) string {
	if c.Process == "" {
		return "исходящее соединение на " + c.Subject
	}
	return "исходящее соединение на " + c.Subject + " — процесс " + c.Process
}

func checkOutbound(_ context.Context, s *Scan) []Finding {
	conns, err := outbound(s.sys)
	if err != nil {
		return []Finding{failed(ErrReadFailed, err)}
	}
	var out []Finding
	for _, c := range conns {
		out = append(out, fail(c.Subject, outboundText(c)))
	}
	return out
}
