// SPDX-License-Identifier: AGPL-3.0-only

// Package sysinfo собирает сведения о системе для system.info и system.inventory (E05-T14) без вызова оболочки:
// /etc/os-release, /proc, /sys, statfs, uname, D-Bus systemd и Docker Engine API (decisions п. 14). Собирает
// помощник (root): сокет Docker и /proc/<pid>/fd чужих процессов агенту недоступны (R11).
package sysinfo

import (
	"bufio"
	"bytes"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"unicode/utf8"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
)

// Пределы ответа (раздел 6).
const (
	MaxEntries = 500
	MaxString  = 200
)

// Clean делает строку пригодной для ответа: валидный UTF-8 (proto3 string иначе не сериализуется), без
// управляющих символов, не длиннее 200 символов.
func Clean(s string) string {
	s = strings.ToValidUTF8(s, "�")
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if utf8.RuneCountInString(s) > MaxString {
		s = string([]rune(s)[:MaxString])
	}
	return s
}

// Host — доступ к системе. Root — корень (в тестах — каталог с сохранёнными образцами).
type Host struct {
	Root string
	// Statfs возвращает размер раздела в байтах; Uname — release ядра. Подменяются в тестах.
	Statfs func(path string) (uint64, error)
	Uname  func() (string, error)
	// Addrs — адреса интерфейсов.
	Addrs func() ([]net.Addr, error)
	// Hostname — имя узла.
	Hostname func() (string, error)
}

func (h *Host) path(p string) string { return filepath.Join(h.Root, p) }

func (h *Host) read(p string) ([]byte, error) {
	f, err := os.Open(h.path(p))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var buf bytes.Buffer
	_, err = buf.ReadFrom(&limited{f, 4 << 20})
	return buf.Bytes(), err
}

type limited struct {
	f *os.File
	n int64
}

func (l *limited) Read(p []byte) (int, error) {
	if l.n <= 0 {
		return 0, errors.New("файл больше предела")
	}
	if int64(len(p)) > l.n {
		p = p[:l.n]
	}
	n, err := l.f.Read(p)
	l.n -= int64(n)
	return n, err
}

// OSRelease — ID и VERSION_ID из os-release.
func (h *Host) OSRelease() (id, version string, err error) {
	raw, err := h.read("etc/os-release")
	if err != nil {
		raw, err = h.read("usr/lib/os-release")
		if err != nil {
			return "", "", err
		}
	}
	kv := parseOSRelease(raw)
	return kv["ID"], kv["VERSION_ID"], nil
}

func parseOSRelease(raw []byte) map[string]string {
	out := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(raw))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
			v = v[1 : len(v)-1]
		}
		out[strings.TrimSpace(k)] = v
	}
	return out
}

// CPUCores — число процессоров в сети (/sys/devices/system/cpu/online, «0-3,6»), иначе runtime.NumCPU.
func (h *Host) CPUCores() uint32 {
	raw, err := h.read("sys/devices/system/cpu/online")
	if err == nil {
		if n := countCPUList(strings.TrimSpace(string(raw))); n > 0 {
			return uint32(n)
		}
	}
	return uint32(runtime.NumCPU())
}

func countCPUList(s string) int {
	n := 0
	for _, part := range strings.Split(s, ",") {
		a, b, isRange := strings.Cut(part, "-")
		lo, err := strconv.Atoi(a)
		if err != nil {
			return 0
		}
		hi := lo
		if isRange {
			if hi, err = strconv.Atoi(b); err != nil || hi < lo {
				return 0
			}
		}
		n += hi - lo + 1
	}
	return n
}

// RAMMB — MemTotal из /proc/meminfo в МиБ.
func (h *Host) RAMMB() (uint64, error) {
	raw, err := h.read("proc/meminfo")
	if err != nil {
		return 0, err
	}
	sc := bufio.NewScanner(bytes.NewReader(raw))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) >= 2 && f[0] == "MemTotal:" {
			kb, err := strconv.ParseUint(f[1], 10, 64)
			if err != nil {
				return 0, err
			}
			return kb / 1024, nil
		}
	}
	return 0, errors.New("в meminfo нет MemTotal")
}

// BootTimeMs — btime из /proc/stat.
func (h *Host) BootTimeMs() (int64, error) {
	raw, err := h.read("proc/stat")
	if err != nil {
		return 0, err
	}
	sc := bufio.NewScanner(bytes.NewReader(raw))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 2 && f[0] == "btime" {
			s, err := strconv.ParseInt(f[1], 10, 64)
			if err != nil {
				return 0, err
			}
			return s * 1000, nil
		}
	}
	return 0, errors.New("в /proc/stat нет btime")
}

// Virtualization — контейнер, гипервизор по DMI, флаг hypervisor или «none».
func (h *Host) Virtualization() string {
	if raw, err := h.read("run/systemd/container"); err == nil {
		if v := strings.TrimSpace(string(raw)); v != "" {
			return Clean(v)
		}
	}
	vendor, _ := h.read("sys/class/dmi/id/sys_vendor")
	product, _ := h.read("sys/class/dmi/id/product_name")
	dmi := strings.ToLower(string(vendor) + " " + string(product))
	for _, m := range []struct{ needle, name string }{
		{"qemu", "kvm"}, {"kvm", "kvm"}, {"openstack", "kvm"}, {"vmware", "vmware"},
		{"virtualbox", "oracle"}, {"microsoft", "microsoft"}, {"xen", "xen"}, {"amazon ec2", "amazon"},
		{"google", "google"}, {"digitalocean", "kvm"}, {"hetzner", "kvm"}, {"parallels", "parallels"},
		{"bochs", "bochs"},
	} {
		if strings.Contains(dmi, m.needle) {
			return m.name
		}
	}
	if raw, err := h.read("proc/cpuinfo"); err == nil {
		sc := bufio.NewScanner(bytes.NewReader(raw))
		for sc.Scan() {
			line := sc.Text()
			if strings.HasPrefix(line, "flags") && strings.Contains(" "+line+" ", " hypervisor ") {
				return "vm"
			}
		}
	}
	return "none"
}

// PublicIPs — первые глобальные адреса интерфейсов: не частные, не CGNAT, не локальные. За NAT пусто — панель
// знает адрес соединения.
func PublicIPs(addrs []net.Addr) (v4, v6 string) {
	cgnat := &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipn.IP
		if !ip.IsGlobalUnicast() || ip.IsPrivate() || cgnat.Contains(ip) {
			continue
		}
		if ip.To4() != nil {
			if v4 == "" {
				v4 = ip.String()
			}
		} else if v6 == "" {
			v6 = ip.String()
		}
	}
	return v4, v6
}

// Info собирает system.info. Нечитаемое поле остаётся пустым, а не проваливает операцию; ошибки — в notes.
func (h *Host) Info(version string) (*agentv1.SystemInfoResult, []string) {
	var notes []string
	note := func(what string, err error) {
		if err != nil {
			notes = append(notes, what+": "+Clean(err.Error()))
		}
	}
	r := &agentv1.SystemInfoResult{
		Arch: runtime.GOARCH, AgentVersion: version, HelperVersion: version, CpuCores: h.CPUCores(),
		Virtualization: h.Virtualization(),
	}
	if h.Hostname != nil {
		hn, err := h.Hostname()
		note("hostname", err)
		r.Hostname = Clean(hn)
	}
	id, ver, err := h.OSRelease()
	note("os-release", err)
	r.Os, r.OsVersion = Clean(id), Clean(ver)
	if h.Uname != nil {
		k, err := h.Uname()
		note("uname", err)
		r.Kernel = Clean(k)
	}
	ram, err := h.RAMMB()
	note("meminfo", err)
	r.RamMb = ram
	if h.Statfs != nil {
		b, err := h.Statfs("/")
		note("statfs", err)
		r.DiskGb = (b + (1<<30)/2) >> 30
	}
	bt, err := h.BootTimeMs()
	note("btime", err)
	r.BootTimeMs = bt
	if h.Addrs != nil {
		addrs, err := h.Addrs()
		note("addrs", err)
		r.PublicIpv4, r.PublicIpv6 = PublicIPs(addrs)
	}
	// exec.run и allow_exec — E20; в этой сборке выполнения команд нет.
	r.AllowExec = false
	return r, notes
}
