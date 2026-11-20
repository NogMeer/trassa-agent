// SPDX-License-Identifier: AGPL-3.0-only

package metrics

import (
	"errors"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
)

// Образцы — фрагменты настоящих файлов Ubuntu 24.04 и Debian 12.
const (
	stat1 = "cpu  1000 0 500 8000 500 0 0 0 0 0\ncpu0 1000 0 500 8000 500 0 0 0 0 0\nintr 1\n"
	// +600 занято (user+system), +400 простоя → 60%.
	stat2   = "cpu  1400 0 700 8300 600 0 0 0 0 0\ncpu0 1400 0 700 8300 600 0 0 0 0 0\n"
	meminfo = "MemTotal:        2000000 kB\nMemFree:          100000 kB\nMemAvailable:     500000 kB\nBuffers:           1000 kB\n"
	loadavg = "0.52 0.41 0.30 2/345 12345\n"
	uptime  = "12345.67 23456.78\n"
	tcp     = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		"   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1 0 100 0 0 10 0\n" +
		"   1: 0100007F:1F90 0100007F:D2B4 01 00000000:00000000 00:00000000 00000000   999        0 2 1 0 20 4 30 10 -1\n" +
		"   2: 0A000002:0016 0A000001:C350 01 00000000:00000000 02:0009BC1F 00000000     0        0 3 2 0 20 4 30 10 -1\n"
	tcp6 = "  sl  local_address remote_address st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		"   0: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 4 1 0 100 0 0 10 0\n" +
		"   1: 0000000000000000FFFF00000100007F:1F90 0000000000000000FFFF00000100007F:D2B6 01 00000000:00000000 00:00000000 00000000 999 0 5 1 0 20 4 30 10 -1\n"
	netdev1 = "Inter-|   Receive                                                |  Transmit\n" +
		" face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n" +
		"    lo:  999999    10    0    0    0     0          0         0   999999    10    0    0    0     0       0          0\n" +
		"  eth0: 1000000  1000    0    0    0     0          0         0  2000000  1000    0    0    0     0       0          0\n" +
		"docker0:    0       0    0    0    0     0          0         0        0     0    0    0    0     0       0          0\n" +
		"veth1a2b:  500     5    0    0    0     0          0         0      500     5    0    0    0     0       0          0\n"
	// За 15 с: eth0 +1 500 000 байт приёма (800 000 бит/с) и +3 000 000 передачи (1 600 000 бит/с).
	netdev2 = "Inter-|   Receive\n face |bytes\n" +
		"  eth0: 2500000  2000    0    0    0     0          0         0  5000000  2000    0    0    0     0       0          0\n" +
		"docker0:   150       1    0    0    0     0          0         0      300     1    0    0    0     0       0          0\n" +
		"veth1a2b:  900     5    0    0    0     0          0         0      900     5    0    0    0     0       0          0\n"
	// Корень ext4; /boot отдельно; /home закрыт песочницей службы (tmpfs поверх); /data дважды (bind);
	// tmpfs, overlay контейнера, nfs и раздел внутри /var/lib/docker не диски сервера; пробел в имени.
	mountinfo = "22 1 252:1 / / rw,relatime shared:1 - ext4 /dev/vda1 rw\n" +
		"23 22 0:21 / /proc rw - proc proc rw\n" +
		"24 22 252:2 / /boot rw - ext4 /dev/vda2 rw\n" +
		"25 22 252:3 / /home rw - xfs /dev/vda3 rw\n" +
		"26 22 0:5 / /run rw - tmpfs tmpfs rw\n" +
		"27 22 252:4 / /data rw - btrfs /dev/vdb rw\n" +
		"28 22 252:4 / /srv/data rw - btrfs /dev/vdb rw\n" +
		"29 22 0:40 / /var/lib/docker/overlay2/x/merged rw - overlay overlay rw\n" +
		"30 22 252:5 / /var/lib/docker/volumes rw - ext4 /dev/vdc rw\n" +
		"31 22 0:41 / /mnt/nfs rw - nfs4 srv:/x rw\n" +
		"32 22 252:6 / /mnt/my\\040disk rw - ext4 /dev/vdd rw\n" +
		"33 25 0:5 /systemd/inaccessible/dir /home ro - tmpfs tmpfs rw\n" +
		"34 22 252:7 /x/hostname /etc/hostname rw - ext4 /dev/vde rw\n"
)

func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, body := range files {
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func fakeStatfs(path string) (FS, error) {
	if path == "/mnt/my disk" {
		return FS{}, errors.New("EACCES")
	}
	// 1000 блоков по 4 КиБ: свободно 300, доступно 250 (резерв root 50); 100 инодов, свободно 25.
	return FS{Blocks: 1000, Bfree: 300, Bavail: 250, Files: 100, Ffree: 25, Bsize: 4096}, nil
}

type point struct {
	name, label string
}

func byKey(b *agentv1.MetricsBatch) map[point]float64 {
	out := map[point]float64{}
	for _, m := range b.GetMetrics() {
		l := m.GetLabels()["mount"] + m.GetLabels()["iface"]
		out[point{m.GetName(), l}] = m.GetValue()
	}
	return out
}

func near(a, b float64) bool { return math.Abs(a-b) < 1e-6 }

func TestCollect(t *testing.T) {
	proc := writeTree(t, map[string]string{
		"stat": stat1, "meminfo": meminfo, "loadavg": loadavg, "uptime": uptime,
		"net/tcp": tcp, "net/tcp6": tcp6, "net/dev": netdev1, "self/mountinfo": mountinfo,
		"1/stat": "", "42/stat": "", "self/x": "", "sys/x": "",
	})
	sys := writeTree(t, map[string]string{"class/net/eth0/device/x": "", "class/net/docker0/x": ""})
	c := &Collector{Proc: proc, Sys: sys, Statfs: fakeStatfs, IsDir: func(p string) bool { return p != "/etc/hostname" }}
	t0 := time.Unix(1_700_000_000, 0)

	first, errs := c.Collect(t0)
	if len(errs) != 1 || !strings.Contains(errs[0].Error(), "my disk") {
		t.Fatalf("ошибки: %v", errs)
	}
	got := byKey(first)
	if _, ok := got[point{"cpu_usage_percent", ""}]; ok {
		t.Fatal("CPU по одному снимку")
	}
	if _, ok := got[point{"net_rx_bps", "eth0"}]; ok {
		t.Fatal("скорость сети по одному снимку")
	}
	want := map[point]float64{
		{"mem_used_bytes", ""}: 1_500_000 * 1024, {"mem_used_percent", ""}: 75,
		{"load1", ""}: 0.52, {"load5", ""}: 0.41, {"load15", ""}: 0.30,
		{"uptime_seconds", ""}: 12345.67, {"procs_total", ""}: 2, {"tcp_connections", ""}: 3,
		{"disk_used_percent", "/"}: 700.0 / 950 * 100, {"disk_free_bytes", "/"}: 250 * 4096,
		{"inodes_used_percent", "/"}:   75,
		{"disk_used_percent", "/boot"}: 700.0 / 950 * 100, {"disk_used_percent", "/data"}: 700.0 / 950 * 100,
	}
	for k, v := range want {
		if g, ok := got[k]; !ok || !near(g, v) {
			t.Errorf("%v = %v (есть: %v), ждали %v", k, g, ok, v)
		}
	}
	for _, m := range []string{"/home", "/srv/data", "/run", "/proc", "/var/lib/docker/volumes", "/var/lib/docker/overlay2/x/merged", "/mnt/nfs", "/etc/hostname"} {
		if _, ok := got[point{"disk_used_percent", m}]; ok {
			t.Errorf("раздел %s не должен отправляться", m)
		}
	}
	if first.GetMetrics()[0].GetName() == "" || first.GetCollectedAtMs() != t0.UnixMilli() {
		t.Fatalf("пачка: %+v", first)
	}

	if err := os.WriteFile(filepath.Join(proc, "stat"), []byte(stat2), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(proc, "net/dev"), []byte(netdev2), 0o644); err != nil {
		t.Fatal(err)
	}
	second, _ := c.Collect(t0.Add(15 * time.Second))
	got = byKey(second)
	for k, v := range map[point]float64{
		{"cpu_usage_percent", ""}: 60,
		{"net_rx_bps", "eth0"}:    800_000, {"net_tx_bps", "eth0"}: 1_600_000,
		{"net_rx_bps", "docker0"}: 80, {"net_tx_bps", "docker0"}: 160,
	} {
		if g, ok := got[k]; !ok || !near(g, v) {
			t.Errorf("%v = %v (есть: %v), ждали %v", k, g, ok, v)
		}
	}
	for _, ifc := range []string{"lo", "veth1a2b"} {
		if _, ok := got[point{"net_rx_bps", ifc}]; ok {
			t.Errorf("интерфейс %s не должен отправляться", ifc)
		}
	}

	// Счётчик интерфейса сбросился — точки нет, остальное на месте.
	if err := os.WriteFile(filepath.Join(proc, "net/dev"), []byte(strings.Replace(netdev2, "2500000", "10", 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	third, _ := c.Collect(t0.Add(30 * time.Second))
	got = byKey(third)
	if _, ok := got[point{"net_rx_bps", "eth0"}]; ok {
		t.Error("скорость по сброшенному счётчику")
	}
	if _, ok := got[point{"net_rx_bps", "docker0"}]; !ok {
		t.Error("docker0 пропал вместе с eth0")
	}
}

// Источник пропал — пачка уходит без его метрик, ошибка названа; плохие строки не дают NaN и паники.
func TestCollectBrokenSources(t *testing.T) {
	proc := writeTree(t, map[string]string{
		"stat": "garbage\n", "meminfo": "MemTotal: 10 kB\n", "loadavg": "x y z\n",
		"net/tcp": tcp, "net/dev": "junk\n", "self/mountinfo": "nonsense\n",
	})
	c := &Collector{Proc: proc, Sys: t.TempDir(), Statfs: fakeStatfs}
	b, errs := c.Collect(time.Now())
	names := map[string]bool{}
	for _, m := range b.GetMetrics() {
		names[m.GetName()] = true
		if math.IsNaN(m.GetValue()) || math.IsInf(m.GetValue(), 0) {
			t.Errorf("%s = %v", m.GetName(), m.GetValue())
		}
	}
	if !names["tcp_connections"] || !names["procs_total"] {
		t.Fatalf("исправные источники пропали: %v", names)
	}
	var srcs []string
	for _, e := range errs {
		srcs = append(srcs, strings.SplitN(e.Error(), ":", 2)[0])
	}
	for _, want := range []string{"cpu", "mem", "loadavg", "uptime"} {
		if !strings.Contains(strings.Join(srcs, ","), want) {
			t.Errorf("нет ошибки источника %s: %v", want, errs)
		}
	}
}

func TestMountLimits(t *testing.T) {
	var b strings.Builder
	b.WriteString("1 0 8:0 / / rw - ext4 /dev/sda rw\n")
	for i := 1; i <= 40; i++ {
		b.WriteString("2 1 8:" + strconv.Itoa(i) + " / /m" + strconv.Itoa(i) + " rw - ext4 /dev/x rw\n")
	}
	b.WriteString("3 1 9:1 / /" + strings.Repeat("a", 250) + " rw - ext4 /dev/y rw\n")
	proc := writeTree(t, map[string]string{"self/mountinfo": b.String()})
	c := &Collector{Proc: proc}
	m, err := c.mounts()
	if err != nil {
		t.Fatal(err)
	}
	if len(m) != MaxMounts || m[0] != "/" {
		t.Fatalf("%d разделов, первый %q", len(m), m[0])
	}
	for _, x := range m {
		if len(x) > maxLabelValue {
			t.Fatal("метка длиннее 200 символов")
		}
	}
	if unescapeMount(`/a\040b\134c`) != `/a b\c` {
		t.Fatal(unescapeMount(`/a\040b\134c`))
	}
}

func TestIfaceLimit(t *testing.T) {
	cur := map[string][2]uint64{}
	for i := 0; i < 30; i++ {
		cur["br-"+strconv.Itoa(i)] = [2]uint64{}
	}
	cur["eth0"] = [2]uint64{}
	sys := writeTree(t, map[string]string{"class/net/eth0/device/x": ""})
	got := (&Collector{Sys: sys}).ifaces(cur)
	if len(got) != MaxIfaces || got[0] != "eth0" {
		t.Fatalf("%v", got)
	}
}
