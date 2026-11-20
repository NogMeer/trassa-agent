// SPDX-License-Identifier: AGPL-3.0-only

package wireguard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/fsutil"
	"github.com/NogMeer/trassa-agent/internal/rollback"
)

// Env — окружение операций: System, корень файлов (в тестах — временный каталог), Docker API, путь помощника.
type Env struct {
	*System
	Root       string // "/"
	HelperPath string // /usr/local/bin/trassa-helper — команда синхронизации после отката
	Docker     interface {
		Get(ctx context.Context, path string) (*http.Response, error)
	}
	Addrs func() ([]netip.Prefix, []string, error) // адреса интерфейсов и их имена
}

func (e *Env) path(p string) string { return filepath.Join(e.Root, p) }

// Plan — что сделает apply или remove (как security.FixPlan).
type Plan struct {
	Summary string
	Paths   []string
	State   rollback.State
	Changes []*agentv1.FileChange
	Notes   []string
	Apply   func(ctx context.Context) error
	Verify  func(ctx context.Context) error
}

// udpPortUsed — порт UDP занят (/proc/net/udp[6], состояние 07).
func (e *Env) udpPortUsed(port uint32) bool {
	for _, f := range []string{"/proc/net/udp", "/proc/net/udp6"} {
		b, err := os.ReadFile(e.path(f))
		if err != nil {
			continue
		}
		for i, l := range strings.Split(string(b), "\n") {
			fl := strings.Fields(l)
			if i == 0 || len(fl) < 4 || fl[3] != "07" {
				continue
			}
			if _, ph, ok := strings.Cut(fl[1], ":"); ok {
				if n, err := strconv.ParseUint(ph, 16, 16); err == nil && uint32(n) == port {
					return true
				}
			}
		}
	}
	return false
}

// localSubnets — подсети интерфейсов (кроме iface), маршрутов и сетей Docker.
func (e *Env) localSubnets(ctx context.Context, iface string) ([]*agentv1.LocalSubnet, []string, []string) {
	var out []*agentv1.LocalSubnet
	var warns, addrs []string
	if e.Addrs != nil {
		ps, names, err := e.Addrs()
		if err != nil {
			warns = append(warns, "адреса интерфейсов не прочитаны: "+err.Error())
		}
		for i, p := range ps {
			if names[i] == iface || p.Addr().IsLoopback() || p.Addr().IsLinkLocalUnicast() {
				continue
			}
			addrs = append(addrs, p.String())
			out = append(out, &agentv1.LocalSubnet{Cidr: p.Masked().String(), Source: agentv1.LocalSubnetSource_LOCAL_SUBNET_SOURCE_INTERFACE, Name: names[i]})
		}
	}
	if b, err := os.ReadFile(e.path("/proc/net/route")); err == nil {
		for i, l := range strings.Split(string(b), "\n") {
			f := strings.Fields(l)
			if i == 0 || len(f) < 8 || f[0] == iface || f[1] == "00000000" {
				continue
			}
			dst, ok1 := hexIPv4(f[1])
			mask, ok2 := hexIPv4(f[7])
			if ok1 && ok2 {
				bits := 0
				for _, b := range mask.AsSlice() {
					for ; b != 0; b <<= 1 {
						bits++
					}
				}
				out = append(out, &agentv1.LocalSubnet{Cidr: netip.PrefixFrom(dst, bits).Masked().String(), Source: agentv1.LocalSubnetSource_LOCAL_SUBNET_SOURCE_ROUTE, Name: f[0]})
			}
		}
	}
	if e.Docker != nil {
		dctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		if resp, err := e.Docker.Get(dctx, "/networks"); err == nil {
			var nets []struct {
				Name string `json:"Name"`
				IPAM struct {
					Config []struct {
						Subnet string `json:"Subnet"`
					} `json:"Config"`
				} `json:"IPAM"`
			}
			if json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&nets) == nil {
				for _, n := range nets {
					for _, c := range n.IPAM.Config {
						if _, err := netip.ParsePrefix(c.Subnet); err == nil {
							out = append(out, &agentv1.LocalSubnet{Cidr: c.Subnet, Source: agentv1.LocalSubnetSource_LOCAL_SUBNET_SOURCE_DOCKER, Name: n.Name})
						}
					}
				}
			}
			resp.Body.Close()
		}
	}
	return out, addrs, warns
}

// hexIPv4 — адрес из /proc/net/route (little-endian).
func hexIPv4(h string) (netip.Addr, bool) {
	n, err := strconv.ParseUint(h, 16, 32)
	if err != nil {
		return netip.Addr{}, false
	}
	return netip.AddrFrom4([4]byte{byte(n), byte(n >> 8), byte(n >> 16), byte(n >> 24)}), true
}

func conflicts(cidr netip.Prefix, subnets []*agentv1.LocalSubnet) []string {
	var out []string
	seen := map[string]bool{}
	for _, s := range subnets {
		p, err := netip.ParsePrefix(s.GetCidr())
		if err == nil && p.Overlaps(cidr) && !seen[s.GetCidr()] {
			seen[s.GetCidr()] = true
			out = append(out, s.GetCidr()+" ("+s.GetName()+")")
		}
	}
	return out
}

// cloudInitManagesHosts — cloud-init перерисовывает /etc/hosts при загрузке (manage_etc_hosts: true).
func (e *Env) cloudInitManagesHosts() bool {
	files := []string{"/etc/cloud/cloud.cfg"}
	ents, _ := os.ReadDir(e.path("/etc/cloud/cloud.cfg.d"))
	for _, x := range ents {
		files = append(files, "/etc/cloud/cloud.cfg.d/"+x.Name())
	}
	for _, f := range files {
		b, _ := os.ReadFile(e.path(f))
		for _, l := range strings.Split(string(b), "\n") {
			if k, v, ok := strings.Cut(strings.TrimSpace(l), ":"); ok && k == "manage_etc_hosts" {
				v = strings.Trim(strings.TrimSpace(v), `"'`)
				if v == "true" || v == "True" || v == "localhost" || v == "template" {
					return true
				}
			}
		}
	}
	return false
}

// Inspect — wireguard.inspect: поддержка, порт, локальные подсети и пересечения, адреса, своё и чужие устройства.
func (e *Env) Inspect(ctx context.Context, p *agentv1.WireguardInspectParams) *agentv1.WireguardInspectResult {
	res := &agentv1.WireguardInspectResult{Supported: true}
	iface := p.GetIfaceName()
	mine := e.Kernel.Exists(iface)
	if !mine {
		if err := e.Kernel.Probe(); err != nil {
			res.Supported, res.UnsupportedReason = false, err.Error()
		}
	}
	cur, _ := e.Store.Load(iface)
	res.PortFree = !e.udpPortUsed(p.GetListenPort()) || (cur != nil && cur.ListenPort == int(p.GetListenPort()))
	subnets, addrs, warns := e.localSubnets(ctx, iface)
	res.LocalSubnets, res.Addresses, res.Warnings = subnets, addrs, warns
	if cidr, err := netip.ParsePrefix(p.GetCidr()); err == nil {
		res.Conflicts = conflicts(cidr, subnets)
	}
	for _, a := range addrs {
		if pr, err := netip.ParsePrefix(a); err == nil && pr.Addr().Is4() && !pr.Addr().IsPrivate() && !pr.Addr().IsLoopback() {
			res.HasPublicIpv4 = true
		}
	}
	if mine {
		if dev, err := e.Kernel.Device(iface); err == nil {
			d := &agentv1.WireguardDevice{PublicKey: dev.PublicKey.String(), ListenPort: uint32(dev.ListenPort)}
			if a, mtu, err := e.Kernel.Address(iface); err == nil {
				d.Address, d.Mtu = a, uint32(mtu)
			}
			if cur != nil {
				d.ConfigHash = cur.Hash()
			}
			for _, pe := range dev.Peers {
				d.Peers = append(d.Peers, peerState(pe.PublicKey.String(), pe.Endpoint, pe.AllowedIPs, pe.LastHandshakeTime, pe.ReceiveBytes, pe.TransmitBytes, pe.PersistentKeepaliveInterval))
			}
			res.Device = d
		}
	}
	ours := map[string]bool{}
	for _, n := range e.Store.Ifaces() {
		ours[n] = true
	}
	ours[iface] = true
	if devs, err := e.Kernel.Devices(); err == nil {
		for _, d := range devs {
			if !ours[d.Name] {
				res.Foreign = append(res.Foreign, &agentv1.ForeignWireguard{Iface: d.Name, PublicKey: d.PublicKey.String(), ListenPort: uint32(d.ListenPort)})
			}
		}
	}
	if e.cloudInitManagesHosts() {
		res.Warnings = append(res.Warnings, "cloud-init перерисовывает /etc/hosts при загрузке (manage_etc_hosts): помощник восстанавливает блок имён при старте")
	}
	if e.DockerPresent != nil && e.DockerPresent() && !e.DockerChain(ctx) {
		res.Warnings = append(res.Warnings, "Docker без цепочки DOCKER-USER: узел HUB с пересылкой на этом сервере невозможен")
	}
	return res
}

func peerState(pub string, ep *net.UDPAddr, ips []net.IPNet, hs time.Time, rx, tx int64, ka time.Duration) *agentv1.WireguardPeerState {
	ps := &agentv1.WireguardPeerState{PublicKey: pub, RxBytes: uint64(rx), TxBytes: uint64(tx), KeepaliveSeconds: uint32(ka / time.Second)}
	if ep != nil {
		ps.Endpoint = ep.String()
	}
	for _, a := range ips {
		ps.AllowedIps = append(ps.AllowedIps, a.String())
	}
	sort.Strings(ps.AllowedIps)
	if !hs.IsZero() {
		ps.LastHandshakeMs = hs.UnixMilli()
	}
	return ps
}

func (e *Env) syncCommand(iface string) []string {
	return []string{e.HelperPath, "wireguard-sync", iface}
}

func (e *Env) basePaths(iface string) []string {
	return []string{e.Store.DesiredPath(iface), e.Store.RemovedPath(iface), e.Hosts, e.path(SysctlFile(iface))}
}

// prevSysctl — прежние значения пересылки (если интерфейс уже есть).
func (e *Env) prevSysctl(iface string) map[string]string {
	out := map[string]string{}
	for _, k := range SysctlKeys(iface) {
		if b, err := os.ReadFile(filepath.Join(e.ProcSys, strings.ReplaceAll(k, ".", "/"))); err == nil {
			out[k] = strings.TrimSpace(string(b))
		}
	}
	return out
}

// PlanApply — wireguard.apply: проверки на сервере (поддержка, порт, пересечения, ключ, DOCKER-USER), точка
// отката (файлы состояния, имён, пересылки; после возврата — синхронизация ядра), применение и проверка.
func (e *Env) PlanApply(ctx context.Context, p *agentv1.WireguardApplyParams) (*Plan, error) {
	iface := p.GetIfaceName()
	cur, err := e.Store.Load(iface)
	if err != nil {
		return nil, err
	}
	if !e.Kernel.Exists(iface) {
		if err := e.Kernel.Probe(); err != nil {
			return nil, err
		}
	}
	if e.udpPortUsed(p.GetListenPort()) && (cur == nil || cur.ListenPort != int(p.GetListenPort())) {
		return nil, precond(CodePortBusy, "порт UDP %d занят", p.GetListenPort())
	}
	addr := netip.MustParsePrefix(p.GetAddress())
	subnets, _, _ := e.localSubnets(ctx, iface)
	if c := conflicts(addr.Masked(), subnets); len(c) > 0 {
		return nil, precond(CodeConflict, "диапазон %s пересекается с %s", addr.Masked(), strings.Join(c, ", "))
	}
	keyFile, err := e.Store.MatchKey(iface, p.GetExpectPublicKey())
	if err != nil {
		return nil, err
	}
	docker := e.DockerPresent != nil && e.DockerPresent()
	if p.GetForwarding() && docker && !e.DockerChain(ctx) {
		return nil, precond("FIX_PRECONDITION", "Docker без цепочки DOCKER-USER: транзит wg → wg на этом сервере не настроить, чужие цепочки Trassa не меняет")
	}
	d := FromParams(p, keyFile, docker)
	if cur != nil && cur.KeyFile != keyFile {
		d.Retired = []string{cur.KeyFile}
	}
	oldHosts, _ := os.ReadFile(e.Hosts)
	plan := &Plan{
		Summary: fmt.Sprintf("Интерфейс %s %s: пиров %d", iface, d.Address, len(d.Peers)),
		Paths:   e.basePaths(iface),
		State:   rollback.State{Sysctl: e.prevSysctl(iface), Commands: [][]string{e.syncCommand(iface)}},
		Changes: []*agentv1.FileChange{{Path: "/etc/hosts", Kind: agentv1.FileChangeKind_FILE_CHANGE_KIND_MODIFY,
			Diff: diffLines(string(oldHosts), RenderHosts(string(oldHosts), iface, d.Hosts))}},
		Notes: peerNotes(cur, d),
	}
	if d.Forwarding {
		plan.Notes = append(plan.Notes, "Пересылка между пирами на "+iface+" включится")
		if d.DockerRule {
			plan.Notes = append(plan.Notes, "В DOCKER-USER добавится одно правило транзита "+DockerComment(iface))
		}
	}
	plan.Apply = func(ctx context.Context) error {
		sf := e.path(SysctlFile(iface))
		if d.Forwarding {
			if err := os.MkdirAll(filepath.Dir(sf), 0o755); err != nil {
				return err
			}
			if err := fsutil.WriteFileAtomic(sf, []byte(sysctlContent(iface)), 0o644, fsutil.Keep); err != nil {
				return err
			}
		} else if err := fsutil.RemoveSync(sf); err != nil {
			return err
		}
		if err := fsutil.RemoveSync(e.Store.RemovedPath(iface)); err != nil {
			return err
		}
		if err := e.Store.Save(d); err != nil {
			return err
		}
		if err := e.SyncHosts(iface); err != nil {
			return err
		}
		return e.Sync(ctx, iface)
	}
	plan.Verify = func(ctx context.Context) error {
		if err := e.System.Verify(ctx, iface); err != nil {
			return err
		}
		if !e.udpPortUsed(p.GetListenPort()) {
			return fmt.Errorf("порт UDP %d не слушается", p.GetListenPort())
		}
		return nil
	}
	return plan, nil
}

// peerNotes — какие пиры добавятся, уйдут, изменятся.
func peerNotes(cur, next *Desired) []string {
	old := map[string]Peer{}
	if cur != nil {
		for _, p := range cur.Peers {
			old[p.PublicKey] = p
		}
	}
	var notes []string
	for _, p := range next.Peers {
		o, ok := old[p.PublicKey]
		switch {
		case !ok:
			notes = append(notes, "пир добавится: "+p.PublicKey)
		case strings.Join(o.AllowedIPs, ",") != strings.Join(p.AllowedIPs, ",") || o.Endpoint != p.Endpoint || o.Keepalive != p.Keepalive:
			notes = append(notes, "пир изменится: "+p.PublicKey)
		}
		delete(old, p.PublicKey)
	}
	for k := range old {
		notes = append(notes, "пир уйдёт: "+k)
	}
	sort.Strings(notes)
	return notes
}

func diffLines(a, b string) string {
	if a == b {
		return ""
	}
	in := func(s string) map[string]bool {
		m := map[string]bool{}
		for _, l := range strings.Split(s, "\n") {
			m[l] = true
		}
		return m
	}
	ma, mb := in(a), in(b)
	var sb strings.Builder
	for _, l := range strings.Split(a, "\n") {
		if !mb[l] {
			sb.WriteString("-" + l + "\n")
		}
	}
	for _, l := range strings.Split(b, "\n") {
		if !ma[l] {
			sb.WriteString("+" + l + "\n")
		}
	}
	return sb.String()
}

// PlanRemove — wireguard.remove: интерфейс, имена, пересылка и правило Docker снимаются; ключ — только после
// подтверждения (метка .removed), чтобы откат был возможен. Нет интерфейса — успех.
func (e *Env) PlanRemove(_ context.Context, p *agentv1.WireguardRemoveParams) (*Plan, error) {
	iface := p.GetIfaceName()
	cur, err := e.Store.Load(iface)
	if err != nil {
		return nil, err
	}
	purge := p.PurgeKey == nil || p.GetPurgeKey()
	n := 0
	if cur != nil {
		n = len(cur.Peers)
	}
	plan := &Plan{
		Summary: fmt.Sprintf("Удалить %s: пиров %d", iface, n),
		Paths:   e.basePaths(iface),
		State:   rollback.State{Sysctl: e.prevSysctl(iface), Commands: [][]string{e.syncCommand(iface)}},
	}
	if purge {
		plan.Notes = append(plan.Notes, "Ключ удалится после подтверждения")
	}
	plan.Apply = func(ctx context.Context) error {
		mark := "keep"
		if purge {
			mark = "purge"
		}
		if err := os.MkdirAll(e.Store.Dir, 0o700); err != nil {
			return err
		}
		if err := fsutil.WriteFileAtomic(e.Store.RemovedPath(iface), []byte(mark+"\n"), 0o600, fsutil.Keep); err != nil {
			return err
		}
		if err := fsutil.RemoveSync(e.Store.DesiredPath(iface)); err != nil {
			return err
		}
		if err := fsutil.RemoveSync(e.path(SysctlFile(iface))); err != nil {
			return err
		}
		if err := e.SyncHosts(iface); err != nil {
			return err
		}
		return e.Sync(ctx, iface)
	}
	plan.Verify = func(ctx context.Context) error { return e.System.Verify(ctx, iface) }
	return plan, nil
}

// Stats — метрики пиров своих интерфейсов (wg.stats): возраст рукопожатия, байты.
func (e *Env) Stats(now time.Time) ([]*agentv1.Metric, error) {
	var out []*agentv1.Metric
	var errs []error
	for _, iface := range e.Store.Ifaces() {
		dev, err := e.Kernel.Device(iface)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		for _, p := range dev.Peers {
			l := map[string]string{"iface": iface, "peer": p.PublicKey.String()}
			age := -1.0
			if !p.LastHandshakeTime.IsZero() {
				age = now.Sub(p.LastHandshakeTime).Seconds()
			}
			out = append(out,
				&agentv1.Metric{Name: "wg_peer_handshake_age_seconds", Value: age, Labels: l},
				&agentv1.Metric{Name: "wg_peer_rx_bytes", Value: float64(p.ReceiveBytes), Labels: l},
				&agentv1.Metric{Name: "wg_peer_tx_bytes", Value: float64(p.TransmitBytes), Labels: l})
		}
	}
	return out, errors.Join(errs...)
}

// SyncAll — при старте помощника: все интерфейсы и блоки имён по файлам (после перезагрузки и cloud-init).
func (e *Env) SyncAll(ctx context.Context) error {
	var errs []error
	for _, iface := range e.Store.Ifaces() {
		errs = append(errs, e.SyncHosts(iface), e.Sync(ctx, iface))
	}
	return errors.Join(errs...)
}

// Purge — при удалении агента: все интерфейсы Trassa, правила Docker, блоки имён и пересылка снимаются, ключи
// удаляются.
func (e *Env) Purge(ctx context.Context) error {
	var errs []error
	for _, iface := range e.Store.Ifaces() {
		errs = append(errs, fsutil.RemoveSync(e.Store.DesiredPath(iface)), fsutil.RemoveSync(e.path(SysctlFile(iface))),
			e.SyncHosts(iface), e.Sync(ctx, iface))
	}
	return errors.Join(errs...)
}
