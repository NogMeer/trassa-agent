// SPDX-License-Identifier: AGPL-3.0-only

package sysinfo

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
)

// Unit — служба systemd.
type Unit struct{ Name, ActiveState string }

// UnitLister — источник служб (D-Bus systemd).
type UnitLister func(ctx context.Context) ([]Unit, error)

// Inventory — источники system.inventory.
type Inventory struct {
	Host         *Host
	Units        UnitLister
	DockerSocket string // /var/run/docker.sock
}

// Collect собирает выбранные виды. Сбой одного источника — пометка в notes, остальные виды отдаются.
func (inv *Inventory) Collect(ctx context.Context, kinds []agentv1.InventoryKind) (*agentv1.SystemInventoryResult, []string) {
	r := &agentv1.SystemInventoryResult{}
	var notes []string
	for _, k := range kinds {
		switch k {
		case agentv1.InventoryKind_INVENTORY_KIND_SERVICES:
			s, err := inv.services(ctx)
			if err != nil {
				notes = append(notes, "services: "+Clean(err.Error()))
			}
			r.Services = s
		case agentv1.InventoryKind_INVENTORY_KIND_CONTAINERS:
			c, note := inv.containers(ctx)
			if note != "" {
				notes = append(notes, "containers: "+note)
			}
			r.Containers = c
		case agentv1.InventoryKind_INVENTORY_KIND_PORTS:
			p, err := inv.Host.Ports()
			if err != nil {
				notes = append(notes, "ports: "+Clean(err.Error()))
			}
			r.Ports = p
		}
	}
	return r, notes
}

func (inv *Inventory) services(ctx context.Context) ([]*agentv1.ServiceEntry, error) {
	if inv.Units == nil {
		return nil, errors.New("D-Bus systemd недоступен")
	}
	units, err := inv.Units(ctx)
	if err != nil {
		return nil, err
	}
	sort.Slice(units, func(i, j int) bool { return units[i].Name < units[j].Name })
	var out []*agentv1.ServiceEntry
	for _, u := range units {
		if !strings.HasSuffix(u.Name, ".service") {
			continue
		}
		if len(out) == MaxEntries {
			break
		}
		out = append(out, &agentv1.ServiceEntry{Name: Clean(u.Name), State: Clean(u.ActiveState)})
	}
	return out, nil
}

// ---------- Docker ----------

type dockerPort struct {
	IP          string `json:"IP"`
	PrivatePort int    `json:"PrivatePort"`
	PublicPort  int    `json:"PublicPort"`
	Type        string `json:"Type"`
}

type dockerContainer struct {
	Names []string     `json:"Names"`
	Image string       `json:"Image"`
	State string       `json:"State"`
	Ports []dockerPort `json:"Ports"`
}

// maxDockerAPI — версия API, которой говорит клиент; с демоном договариваемся на min(своя, его).
const maxDockerAPI = "1.44"

func (inv *Inventory) containers(ctx context.Context) ([]*agentv1.ContainerEntry, string) {
	sock := inv.DockerSocket
	if sock == "" {
		sock = "/var/run/docker.sock"
	}
	if _, err := os.Stat(sock); errors.Is(err, os.ErrNotExist) {
		return nil, "Docker не установлен"
	}
	c := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", sock)
			},
			DisableKeepAlives: true,
		},
	}
	get := func(path string) (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker"+path, nil)
		if err != nil {
			return nil, err
		}
		return c.Do(req)
	}
	resp, err := get("/_ping")
	if err != nil {
		return nil, "ошибка Docker API: " + Clean(err.Error())
	}
	resp.Body.Close()
	ver := DockerAPIVersion(resp.Header.Get("Api-Version"))
	resp, err = get("/v" + ver + "/containers/json?all=true")
	if err != nil {
		return nil, "ошибка Docker API: " + Clean(err.Error())
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Sprintf("ошибка Docker API: HTTP %d", resp.StatusCode)
	}
	list, err := ParseContainers(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, "ошибка Docker API: " + Clean(err.Error())
	}
	return list, ""
}

// DockerAPIVersion — min(1.44, версия демона); пустой или кривой заголовок — 1.44.
func DockerAPIVersion(daemon string) string {
	if cmpVersion(daemon, maxDockerAPI) < 0 {
		return daemon
	}
	return maxDockerAPI
}

func cmpVersion(a, b string) int {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	if len(pa) != 2 || len(pb) != 2 {
		return 1
	}
	for i := 0; i < 2; i++ {
		x, e1 := strconv.Atoi(pa[i])
		y, e2 := strconv.Atoi(pb[i])
		if e1 != nil || e2 != nil {
			return 1
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

// ParseContainers разбирает ответ GET /containers/json.
func ParseContainers(r io.Reader) ([]*agentv1.ContainerEntry, error) {
	var raw []dockerContainer
	if err := json.NewDecoder(r).Decode(&raw); err != nil {
		return nil, err
	}
	var out []*agentv1.ContainerEntry
	for _, c := range raw {
		if len(out) == MaxEntries {
			break
		}
		name := ""
		if len(c.Names) > 0 {
			name = strings.TrimPrefix(c.Names[0], "/")
		}
		e := &agentv1.ContainerEntry{Name: Clean(name), Image: Clean(c.Image), State: Clean(c.State)}
		seen := map[string]bool{}
		for _, p := range c.Ports {
			if p.PublicPort == 0 {
				continue
			}
			s := fmt.Sprintf("%d->%d/%s", p.PublicPort, p.PrivatePort, p.Type)
			if p.IP != "" {
				s = net.JoinHostPort(p.IP, strconv.Itoa(p.PublicPort)) + fmt.Sprintf("->%d/%s", p.PrivatePort, p.Type)
			}
			s = Clean(s)
			if !seen[s] && len(e.PublishedPorts) < 64 {
				seen[s] = true
				e.PublishedPorts = append(e.PublishedPorts, s)
			}
		}
		out = append(out, e)
	}
	return out, nil
}

// ---------- Порты ----------

type socket struct {
	addr  string
	port  uint32
	proto string
	inode string
}

// Ports — слушающие сокеты из /proc/net/{tcp,tcp6,udp,udp6} и процессы по /proc/<pid>/fd.
func (h *Host) Ports() ([]*agentv1.PortEntry, error) {
	var socks []socket
	var errs []error
	for _, t := range []struct {
		file, proto string
		v6          bool
		state       string
	}{
		{"tcp", "tcp", false, "0A"}, {"tcp6", "tcp6", true, "0A"},
		{"udp", "udp", false, "07"}, {"udp6", "udp6", true, "07"},
	} {
		raw, err := h.read("proc/net/" + t.file)
		if errors.Is(err, os.ErrNotExist) {
			continue // IPv6 выключен
		}
		if err != nil {
			errs = append(errs, err)
			continue
		}
		s, err := ParseNetTable(raw, t.proto, t.v6, t.state)
		if err != nil {
			errs = append(errs, err)
		}
		socks = append(socks, s...)
	}
	procs := h.socketOwners()
	sort.Slice(socks, func(i, j int) bool {
		if socks[i].port != socks[j].port {
			return socks[i].port < socks[j].port
		}
		return socks[i].proto+socks[i].addr < socks[j].proto+socks[j].addr
	})
	var out []*agentv1.PortEntry
	seen := map[string]bool{}
	for _, s := range socks {
		key := s.proto + "|" + s.addr + "|" + strconv.Itoa(int(s.port))
		if seen[key] {
			continue
		}
		seen[key] = true
		if len(out) == MaxEntries {
			break
		}
		out = append(out, &agentv1.PortEntry{Address: s.addr, Port: s.port, Protocol: s.proto, Process: Clean(procs[s.inode])})
	}
	return out, errors.Join(errs...)
}

// ParseNetTable разбирает таблицу /proc/net/*: строки с нужным состоянием (0A — LISTEN для TCP, 07 —
// неподключённый UDP).
func ParseNetTable(raw []byte, proto string, v6 bool, state string) ([]socket, error) {
	var out []socket
	sc := bufio.NewScanner(bytes.NewReader(raw))
	first := true
	for sc.Scan() {
		if first {
			first = false
			continue
		}
		f := strings.Fields(sc.Text())
		if len(f) < 10 || f[3] != state {
			continue
		}
		hostHex, portHex, ok := strings.Cut(f[1], ":")
		if !ok {
			return out, fmt.Errorf("%s: адрес %q", proto, f[1])
		}
		ip, err := parseHexIP(hostHex, v6)
		if err != nil {
			return out, fmt.Errorf("%s: %w", proto, err)
		}
		port, err := strconv.ParseUint(portHex, 16, 16)
		if err != nil {
			return out, fmt.Errorf("%s: порт %q", proto, portHex)
		}
		out = append(out, socket{addr: ip.String(), port: uint32(port), proto: proto, inode: f[9]})
	}
	return out, sc.Err()
}

// parseHexIP: адрес в /proc/net — 32-битные слова в порядке байт хоста (little-endian на amd64 и arm64).
func parseHexIP(s string, v6 bool) (net.IP, error) {
	b, err := hex.DecodeString(s)
	if err != nil || (!v6 && len(b) != 4) || (v6 && len(b) != 16) {
		return nil, fmt.Errorf("адрес %q", s)
	}
	ip := make(net.IP, len(b))
	for i := 0; i < len(b); i += 4 {
		binary.BigEndian.PutUint32(ip[i:], binary.LittleEndian.Uint32(b[i:]))
	}
	return ip, nil
}

// socketOwners — inode сокета → имя процесса (comm). Процессы, исчезнувшие во время обхода, пропускаются.
func (h *Host) socketOwners() map[string]string {
	out := map[string]string{}
	ents, err := os.ReadDir(h.path("proc"))
	if err != nil {
		return out
	}
	for _, e := range ents {
		pid := e.Name()
		if _, err := strconv.Atoi(pid); err != nil {
			continue
		}
		fdDir := h.path(filepath.Join("proc", pid, "fd"))
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		var comm string
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil || !strings.HasPrefix(link, "socket:[") {
				continue
			}
			inode := strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")
			if comm == "" {
				raw, _ := h.read(filepath.Join("proc", pid, "comm"))
				comm = strings.TrimSpace(string(raw))
			}
			if _, ok := out[inode]; !ok {
				out[inode] = comm
			}
		}
	}
	return out
}
