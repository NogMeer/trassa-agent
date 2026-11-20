// SPDX-License-Identifier: AGPL-3.0-only

package security

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
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

// outbound — установленные исходящие TCP-соединения (st 01) к удалённому порту из списка.
func outbound(sys *System) ([]string, error) {
	var out []string
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
			if i == 0 || len(f) < 4 || f[3] != "01" {
				continue
			}
			host, portHex, ok := strings.Cut(f[2], ":")
			if !ok {
				continue
			}
			port, err := strconv.ParseUint(portHex, 16, 16)
			if err != nil {
				continue
			}
			if why, bad := SuspiciousPorts[uint16(port)]; bad {
				addr, ok := procAddr(host, n.v6)
				if ok {
					out = append(out, fmt.Sprintf("%s:%d (%s)", addr, port, why))
				}
			}
		}
	}
	sort.Strings(out)
	return out, nil
}

func checkOutbound(_ context.Context, s *Scan) []Finding {
	conns, err := outbound(s.sys)
	if err != nil {
		return []Finding{failed(ErrReadFailed, err)}
	}
	var out []Finding
	for _, c := range conns {
		out = append(out, fail(c, "исходящее соединение на "+c))
	}
	return out
}
