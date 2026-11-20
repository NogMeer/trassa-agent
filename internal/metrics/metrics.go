// SPDX-License-Identifier: AGPL-3.0-only

// Package metrics — сбор метрик сервера в агенте (E08-T5). Читает /proc и statfs без оболочки и без прав root:
// процесс агента работает от trassa в песочнице. Имена — каталог метрик E08 (раздел 4), лимиты меток — там же.
package metrics

import (
	"bufio"
	"bytes"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
)

// Лимиты E08 (раздел 4) и канала (раздел 6).
const (
	MaxMounts     = 32
	MaxIfaces     = 16
	MaxPoints     = 2000
	maxLabelValue = 200
)

// FS — сведения statfs о разделе.
type FS struct {
	Blocks, Bfree, Bavail uint64
	Files, Ffree          uint64
	Bsize                 int64
}

// Collector читает счётчики. Proc и Sys — корни /proc и /sys (в тестах — каталоги с образцами).
type Collector struct {
	Proc   string
	Sys    string
	Statfs func(path string) (FS, error)
	// IsDir — точка монтирования каталог; файлы, смонтированные поверх файлов (/etc/hostname в контейнере),
	// не разделы. nil — не проверять.
	IsDir func(path string) bool

	prevCPU  *cpuTimes
	prevNet  map[string][2]uint64
	prevTime time.Time
}

// New — сборщик реальной системы.
func New() *Collector { return &Collector{Proc: "/proc", Sys: "/sys", Statfs: statfs, IsDir: isDir} }

func isDir(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

// Collect снимает одну пачку. Скорости (CPU, сеть) появляются со второго вызова: им нужна разность счётчиков.
// Источник, который не прочитался, пропускается: его метрик в пачке нет, остальные уходят; ошибки — в errs.
func (c *Collector) Collect(now time.Time) (*agentv1.MetricsBatch, []error) {
	var out []*agentv1.Metric
	var errs []error
	add := func(name string, v float64, labels map[string]string) {
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return
		}
		out = append(out, &agentv1.Metric{Name: name, Value: v, Labels: labels})
	}
	fail := func(src string, err error) { errs = append(errs, fmt.Errorf("%s: %w", src, err)) }
	dt := now.Sub(c.prevTime).Seconds()

	if cur, err := c.cpu(); err != nil {
		fail("cpu", err)
	} else {
		if c.prevCPU != nil {
			if p, ok := cur.usage(*c.prevCPU); ok {
				add("cpu_usage_percent", p, nil)
			}
		}
		c.prevCPU = &cur
	}
	if total, avail, err := c.mem(); err != nil {
		fail("mem", err)
	} else if total > 0 && avail <= total {
		add("mem_used_bytes", float64(total-avail), nil)
		add("mem_used_percent", 100*float64(total-avail)/float64(total), nil)
	}
	if l, err := c.load(); err != nil {
		fail("loadavg", err)
	} else {
		add("load1", l[0], nil)
		add("load5", l[1], nil)
		add("load15", l[2], nil)
	}
	if up, err := c.uptime(); err != nil {
		fail("uptime", err)
	} else {
		add("uptime_seconds", up, nil)
	}
	if n, err := c.procs(); err != nil {
		fail("procs", err)
	} else {
		add("procs_total", float64(n), nil)
	}
	if n, err := c.tcpEstablished(); err != nil {
		fail("tcp", err)
	} else {
		add("tcp_connections", float64(n), nil)
	}
	if mounts, err := c.mounts(); err != nil {
		fail("mountinfo", err)
	} else {
		for _, m := range mounts {
			fs, err := c.Statfs(m)
			if err != nil {
				fail("statfs "+m, err)
				continue
			}
			l := map[string]string{"mount": m}
			// Как df: занято от доступного обычному пользователю, без резерва root.
			if used := fs.Blocks - fs.Bfree; fs.Blocks >= fs.Bfree && used+fs.Bavail > 0 {
				add("disk_used_percent", 100*float64(used)/float64(used+fs.Bavail), l)
			}
			add("disk_free_bytes", float64(fs.Bavail)*float64(fs.Bsize), l)
			if fs.Files > 0 && fs.Files >= fs.Ffree {
				add("inodes_used_percent", 100*float64(fs.Files-fs.Ffree)/float64(fs.Files), l)
			}
		}
	}
	if cur, err := c.net(); err != nil {
		fail("net", err)
	} else {
		if c.prevNet != nil && dt > 0 {
			for _, ifc := range c.ifaces(cur) {
				prev, ok := c.prevNet[ifc]
				now := cur[ifc]
				// Счётчик сбросился (интерфейс пересоздан) — точки нет, со следующей пачки скорость снова верна.
				if !ok || now[0] < prev[0] || now[1] < prev[1] {
					continue
				}
				l := map[string]string{"iface": ifc}
				add("net_rx_bps", float64(now[0]-prev[0])*8/dt, l)
				add("net_tx_bps", float64(now[1]-prev[1])*8/dt, l)
			}
		}
		c.prevNet = cur
	}
	c.prevTime = now
	if len(out) > MaxPoints {
		out = out[:MaxPoints]
	}
	return &agentv1.MetricsBatch{CollectedAtMs: now.UnixMilli(), Metrics: out}, errs
}

type cpuTimes struct{ busy, total uint64 }

func (cur cpuTimes) usage(prev cpuTimes) (float64, bool) {
	if cur.total <= prev.total || cur.busy < prev.busy {
		return 0, false
	}
	p := 100 * float64(cur.busy-prev.busy) / float64(cur.total-prev.total)
	return math.Min(math.Max(p, 0), 100), true
}

// cpu — первая строка /proc/stat: user nice system idle iowait irq softirq steal (guest уже входит в user).
func (c *Collector) cpu() (cpuTimes, error) {
	b, err := os.ReadFile(filepath.Join(c.Proc, "stat"))
	if err != nil {
		return cpuTimes{}, err
	}
	line, _, _ := bytes.Cut(b, []byte("\n"))
	f := strings.Fields(string(line))
	if len(f) < 9 || f[0] != "cpu" {
		return cpuTimes{}, fmt.Errorf("неожиданная строка %q", line)
	}
	var v [8]uint64
	for i := range v {
		if v[i], err = strconv.ParseUint(f[i+1], 10, 64); err != nil {
			return cpuTimes{}, err
		}
	}
	var total uint64
	for _, x := range v {
		total += x
	}
	return cpuTimes{busy: total - v[3] - v[4], total: total}, nil
}

// mem — MemTotal и MemAvailable из /proc/meminfo, байты.
func (c *Collector) mem() (total, avail uint64, err error) {
	f, err := os.Open(filepath.Join(c.Proc, "meminfo"))
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()
	var gotT, gotA bool
	s := bufio.NewScanner(f)
	for s.Scan() {
		k, rest, ok := strings.Cut(s.Text(), ":")
		if !ok || (k != "MemTotal" && k != "MemAvailable") {
			continue
		}
		fl := strings.Fields(rest)
		if len(fl) != 2 || fl[1] != "kB" {
			return 0, 0, fmt.Errorf("неожиданная строка %s", k)
		}
		n, err := strconv.ParseUint(fl[0], 10, 64)
		if err != nil {
			return 0, 0, err
		}
		if k == "MemTotal" {
			total, gotT = n*1024, true
		} else {
			avail, gotA = n*1024, true
		}
	}
	if err := s.Err(); err != nil {
		return 0, 0, err
	}
	if !gotT || !gotA {
		return 0, 0, fmt.Errorf("нет MemTotal или MemAvailable")
	}
	return total, avail, nil
}

func (c *Collector) load() ([3]float64, error) {
	var l [3]float64
	b, err := os.ReadFile(filepath.Join(c.Proc, "loadavg"))
	if err != nil {
		return l, err
	}
	f := strings.Fields(string(b))
	if len(f) < 3 {
		return l, fmt.Errorf("неожиданный loadavg %q", b)
	}
	for i := range l {
		if l[i], err = strconv.ParseFloat(f[i], 64); err != nil {
			return l, err
		}
	}
	return l, nil
}

func (c *Collector) uptime() (float64, error) {
	b, err := os.ReadFile(filepath.Join(c.Proc, "uptime"))
	if err != nil {
		return 0, err
	}
	f := strings.Fields(string(b))
	if len(f) < 1 {
		return 0, fmt.Errorf("пустой uptime")
	}
	return strconv.ParseFloat(f[0], 64)
}

// procs — число процессов: числовые каталоги /proc.
func (c *Collector) procs() (int, error) {
	ents, err := os.ReadDir(c.Proc)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, e := range ents {
		if e.IsDir() && isDigits(e.Name()) {
			n++
		}
	}
	return n, nil
}

// tcpEstablished — соединения в состоянии ESTABLISHED (01) из /proc/net/tcp и tcp6. tcp6 может не быть
// (IPv6 выключен) — это не ошибка.
func (c *Collector) tcpEstablished() (int, error) {
	n := 0
	for i, name := range []string{"tcp", "tcp6"} {
		f, err := os.Open(filepath.Join(c.Proc, "net", name))
		if err != nil {
			if i == 1 && os.IsNotExist(err) {
				break
			}
			return 0, err
		}
		s := bufio.NewScanner(f)
		s.Scan() // заголовок
		for s.Scan() {
			fl := strings.Fields(s.Text())
			if len(fl) > 3 && fl[3] == "01" {
				n++
			}
		}
		err = s.Err()
		f.Close()
		if err != nil {
			return 0, err
		}
	}
	return n, nil
}

// Файловые системы на локальных дисках. Сетевые (nfs, cifs) не опрашиваются: statfs на зависшем сервере
// блокирует сбор. Псевдо-системы (tmpfs, overlay, squashfs) не диски сервера.
var diskFS = map[string]bool{
	"ext2": true, "ext3": true, "ext4": true, "xfs": true, "btrfs": true, "zfs": true, "f2fs": true,
	"jfs": true, "reiserfs": true, "vfat": true, "exfat": true, "bcachefs": true,
}

// Каталоги, разделы под которыми — внутренности контейнеров и снапшотов, а не диски сервера.
var skipUnder = []string{"/var/lib/docker/", "/var/lib/containers/", "/run/", "/snap/", "/proc/", "/sys/"}

// mounts — точки монтирования дисков из /proc/self/mountinfo: по одной на устройство, «/» первой, не больше
// MaxMounts. Точка, поверх которой смонтировано другое (песочница службы закрывает /home и /root), пропускается:
// statfs по её пути вернул бы сведения о закрывшей её системе.
func (c *Collector) mounts() ([]string, error) {
	b, err := os.ReadFile(filepath.Join(c.Proc, "self", "mountinfo"))
	if err != nil {
		return nil, err
	}
	type entry struct{ dev, fstype string }
	last := map[string]entry{}
	var order []string
	for _, line := range strings.Split(string(b), "\n") {
		pre, post, ok := strings.Cut(line, " - ")
		if !ok {
			continue
		}
		f := strings.Fields(pre)
		pf := strings.Fields(post)
		if len(f) < 5 || len(pf) < 1 {
			continue
		}
		mp := unescapeMount(f[4])
		if _, seen := last[mp]; !seen {
			order = append(order, mp)
		}
		last[mp] = entry{dev: f[2], fstype: pf[0]}
	}
	devs := map[string]bool{}
	var out []string
	for _, mp := range order {
		e := last[mp]
		if !diskFS[e.fstype] || devs[e.dev] || skipped(mp) || len(mp) > maxLabelValue || (c.IsDir != nil && !c.IsDir(mp)) {
			continue
		}
		devs[e.dev] = true
		out = append(out, mp)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i] == "/" && out[j] != "/" })
	if len(out) > MaxMounts {
		out = out[:MaxMounts]
	}
	return out, nil
}

func skipped(mp string) bool {
	for _, p := range skipUnder {
		if strings.HasPrefix(mp+"/", p) {
			return true
		}
	}
	return false
}

// unescapeMount — mountinfo кодирует пробел, табуляцию, перевод строки и «\» как \040, \011, \012, \134.
func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// net — байты приёма и передачи по интерфейсам из /proc/net/dev.
func (c *Collector) net() (map[string][2]uint64, error) {
	b, err := os.ReadFile(filepath.Join(c.Proc, "net", "dev"))
	if err != nil {
		return nil, err
	}
	out := map[string][2]uint64{}
	for _, line := range strings.Split(string(b), "\n") {
		name, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		f := strings.Fields(rest)
		if len(f) < 16 || name == "" {
			continue
		}
		rx, err1 := strconv.ParseUint(f[0], 10, 64)
		tx, err2 := strconv.ParseUint(f[8], 10, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		out[name] = [2]uint64{rx, tx}
	}
	return out, nil
}

// ifaces — какие интерфейсы отправлять: без lo и veth* (концы контейнерных пар), сначала физические (есть
// /sys/class/net/<имя>/device), не больше MaxIfaces.
func (c *Collector) ifaces(cur map[string][2]uint64) []string {
	var phys, virt []string
	for name := range cur {
		if name == "lo" || strings.HasPrefix(name, "veth") || len(name) > maxLabelValue {
			continue
		}
		if _, err := os.Stat(filepath.Join(c.Sys, "class", "net", name, "device")); err == nil {
			phys = append(phys, name)
		} else {
			virt = append(virt, name)
		}
	}
	sort.Strings(phys)
	sort.Strings(virt)
	out := append(phys, virt...)
	if len(out) > MaxIfaces {
		out = out[:MaxIfaces]
	}
	return out
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
