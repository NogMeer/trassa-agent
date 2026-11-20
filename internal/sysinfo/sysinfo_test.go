// SPDX-License-Identifier: AGPL-3.0-only

package sysinfo

import (
	"context"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/dockerapi"
)

// Сохранённые образцы четырёх ОС на двух архитектурах (8 сочетаний).
func TestInfoSamples(t *testing.T) {
	want := map[string][2]string{
		"ubuntu-22.04": {"ubuntu", "22.04"}, "ubuntu-24.04": {"ubuntu", "24.04"},
		"debian-12": {"debian", "12"}, "debian-13": {"debian", "13"},
	}
	n := 0
	for name, osv := range want {
		for _, arch := range []string{"amd64", "arm64"} {
			n++
			h := &Host{
				Root:     filepath.Join("testdata", name+"-"+arch),
				Statfs:   func(string) (uint64, error) { return 40 << 30, nil },
				Uname:    func() (string, error) { return "6.8.0-48-generic", nil },
				Hostname: func() (string, error) { return "vps-1", nil },
				Addrs: func() ([]net.Addr, error) {
					return []net.Addr{
						&net.IPNet{IP: net.ParseIP("10.0.0.5")}, &net.IPNet{IP: net.ParseIP("100.64.1.1")},
						&net.IPNet{IP: net.ParseIP("203.0.113.7")}, &net.IPNet{IP: net.ParseIP("fe80::1")},
						&net.IPNet{IP: net.ParseIP("2001:db8::7")},
					}, nil
				},
			}
			r, notes := h.Info("1.2.3")
			if len(notes) != 0 {
				t.Fatalf("%s/%s: %v", name, arch, notes)
			}
			if r.Os != osv[0] || r.OsVersion != osv[1] || r.Hostname != "vps-1" || r.Kernel != "6.8.0-48-generic" {
				t.Fatalf("%s/%s: %+v", name, arch, r)
			}
			wantCores := uint32(4)
			if r.CpuCores != wantCores || r.DiskGb != 40 || r.BootTimeMs != 1795000000000 || r.RamMb == 0 {
				t.Fatalf("%s/%s: ядра %d диск %d btime %d", name, arch, r.CpuCores, r.DiskGb, r.BootTimeMs)
			}
			if r.PublicIpv4 != "203.0.113.7" || r.PublicIpv6 != "2001:db8::7" || r.Virtualization != "kvm" {
				t.Fatalf("%s/%s: %s %s %s", name, arch, r.PublicIpv4, r.PublicIpv6, r.Virtualization)
			}
			ports, err := h.Ports()
			if err != nil {
				t.Fatal(err)
			}
			got := map[string]string{}
			for _, p := range ports {
				got[p.Protocol+" "+net.JoinHostPort(p.Address, itoa(p.Port))] = p.Process
			}
			for k, proc := range map[string]string{
				"tcp 0.0.0.0:22": "sshd", "tcp 127.0.0.1:3306": "", "tcp6 [::1]:443": "", "udp 127.0.0.53:53": "",
			} {
				if p, ok := got[k]; !ok || p != proc {
					t.Fatalf("%s/%s: порт %s → %q (%v)", name, arch, k, p, got)
				}
			}
			if len(ports) != 4 {
				t.Fatalf("установленное соединение попало в список: %v", got)
			}
		}
	}
	if n != 8 {
		t.Fatal(n)
	}
}

func itoa(p uint32) string { return strconv.FormatUint(uint64(p), 10) }

func TestCleanAndLimits(t *testing.T) {
	s := Clean("a\x00b\x1b[31m" + string([]byte{0xff}) + strings.Repeat("я", 300))
	if !utf8.ValidString(s) || strings.ContainsAny(s, "\x00\x1b") || utf8.RuneCountInString(s) != MaxString {
		t.Fatalf("%q", s)
	}
	var units []Unit
	for i := 0; i < 700; i++ {
		units = append(units, Unit{Name: "u" + strconv.Itoa(i) + ".service", ActiveState: "active"})
	}
	units = append(units, Unit{Name: "x.socket", ActiveState: "active"})
	inv := &Inventory{
		Host:         &Host{Root: "testdata/debian-12-amd64"},
		Units:        func(context.Context) ([]Unit, error) { return units, nil },
		DockerSocket: filepath.Join(t.TempDir(), "none.sock"),
	}
	r, notes := inv.Collect(context.Background(), []agentv1.InventoryKind{
		agentv1.InventoryKind_INVENTORY_KIND_SERVICES, agentv1.InventoryKind_INVENTORY_KIND_CONTAINERS,
	})
	if len(r.Services) != MaxEntries || len(r.Containers) != 0 {
		t.Fatalf("служб %d", len(r.Services))
	}
	if len(notes) != 1 || !strings.Contains(notes[0], "Docker не установлен") {
		t.Fatalf("%v", notes)
	}
}

func TestParseContainers(t *testing.T) {
	in := `[{"Names":["/web"],"Image":"nginx:1.27","State":"running","Ports":[
	  {"IP":"0.0.0.0","PrivatePort":80,"PublicPort":8080,"Type":"tcp"},
	  {"IP":"::","PrivatePort":80,"PublicPort":8080,"Type":"tcp"},
	  {"PrivatePort":9000,"Type":"tcp"}]},
	  {"Names":["/db"],"Image":"postgres:17","State":"exited","Ports":[]}]`
	got, err := ParseContainers(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Name != "web" || got[1].State != "exited" {
		t.Fatalf("%v", got)
	}
	if len(got[0].PublishedPorts) != 2 || got[0].PublishedPorts[0] != "0.0.0.0:8080->80/tcp" || got[0].PublishedPorts[1] != "[::]:8080->80/tcp" {
		t.Fatalf("%v", got[0].PublishedPorts)
	}
	if dockerapi.Version("1.41") != "1.41" || dockerapi.Version("1.57") != "1.44" || dockerapi.Version("") != "1.44" {
		t.Fatal("версия API")
	}
}

func TestCountCPUList(t *testing.T) {
	for in, want := range map[string]int{"0": 1, "0-3": 4, "0-1,4-5": 4, "0,2,4": 3, "x": 0, "3-1": 0} {
		if got := countCPUList(in); got != want {
			t.Errorf("%q: %d", in, got)
		}
	}
}
