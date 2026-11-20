// SPDX-License-Identifier: AGPL-3.0-only

// Package wireguard — приватная сеть Trassa в помощнике (E14). Источник истины — файл желаемого состояния
// /etc/trassa/wireguard/<iface>.json: apply пишет его и приводит ядро к нему (Sync), откат возвращает файлы и
// снова вызывает Sync. Приватный ключ создаётся здесь и наружу не уходит (decisions E14).
package wireguard

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/fsutil"
)

// Значения по умолчанию (decisions E14, п. 7–8).
const (
	DefaultMTU       = 1420
	DefaultKeepalive = 25
	// StaleAfter — связь устарела, если рукопожатия нет дольше (REJECT_AFTER_TIME ядра; решение продукта).
	StaleAfter = 180 * time.Second
	maxPeers   = 250
	maxHosts   = 500
)

// Коды итога.
const (
	CodeUnsupported = "WG_UNSUPPORTED"
	CodePortBusy    = "WG_PORT_BUSY"
	CodeConflict    = "ADDRESS_CONFLICT"
	CodeKeyMismatch = "WG_KEY_MISMATCH"
)

// ErrPrecondition — условие на сервере не выполнено; Code — код итога.
type ErrPrecondition struct {
	Code string
	Msg  string
}

func (e *ErrPrecondition) Error() string { return e.Code + ": " + e.Msg }

func precond(code, format string, a ...any) error {
	return &ErrPrecondition{Code: code, Msg: fmt.Sprintf(format, a...)}
}

// Имя интерфейса — до 15 байт (IFNAMSIZ), только ASCII, без «/», «:», пробелов и «%» (decisions E14, п. 15).
var ifaceRe = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,14}$`)

// Имя хоста в блоке имён.
var fqdnRe = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// ValidIface — имя интерфейса Trassa.
func ValidIface(n string) error {
	if !ifaceRe.MatchString(n) {
		return fmt.Errorf("iface_name %q: до 15 символов a-z0-9_-, с буквы", n)
	}
	return nil
}

func validKey(s string) error {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b) != wgtypes.KeyLen {
		return fmt.Errorf("ключ %q: base64 32 байта", s)
	}
	return nil
}

// ValidateInspect, ValidateKeygen, ValidateApply, ValidateRemove — схемы параметров.
func ValidateInspect(p *agentv1.WireguardInspectParams) error {
	if err := ValidIface(p.GetIfaceName()); err != nil {
		return err
	}
	if _, err := netip.ParsePrefix(p.GetCidr()); err != nil {
		return errors.New("cidr")
	}
	if p.GetListenPort() < 1 || p.GetListenPort() > 65535 {
		return errors.New("listen_port")
	}
	return nil
}

func ValidateKeygen(p *agentv1.WireguardKeygenParams) error { return ValidIface(p.GetIfaceName()) }

func ValidateRemove(p *agentv1.WireguardRemoveParams) error { return ValidIface(p.GetIfaceName()) }

func ValidateApply(p *agentv1.WireguardApplyParams) error {
	if err := ValidIface(p.GetIfaceName()); err != nil {
		return err
	}
	if _, err := netip.ParsePrefix(p.GetAddress()); err != nil {
		return errors.New("address: адрес с префиксом")
	}
	if p.GetListenPort() < 1 || p.GetListenPort() > 65535 {
		return errors.New("listen_port")
	}
	if p.GetMtu() != 0 && (p.GetMtu() < 1280 || p.GetMtu() > 9000) {
		return errors.New("mtu: 1280–9000")
	}
	if err := validKey(p.GetExpectPublicKey()); err != nil {
		return fmt.Errorf("expect_public_key: %w", err)
	}
	if len(p.GetPeers()) > maxPeers || len(p.GetHosts()) > maxHosts {
		return errors.New("слишком много пиров или имён")
	}
	seenKey := map[string]bool{}
	var prefixes []netip.Prefix
	for _, peer := range p.GetPeers() {
		if err := validKey(peer.GetPublicKey()); err != nil {
			return err
		}
		if peer.GetPublicKey() == p.GetExpectPublicKey() || seenKey[peer.GetPublicKey()] {
			return fmt.Errorf("пир %s повторяется или совпадает с ключом сервера", peer.GetPublicKey())
		}
		seenKey[peer.GetPublicKey()] = true
		if e := peer.GetEndpoint(); e != "" {
			if _, err := netip.ParseAddrPort(e); err != nil {
				return fmt.Errorf("endpoint %q: адрес:порт", e)
			}
		}
		if peer.GetKeepaliveSeconds() > 3600 {
			return errors.New("keepalive_seconds: до 3600")
		}
		if len(peer.GetAllowedIps()) == 0 {
			return fmt.Errorf("пир %s без allowed_ips", peer.GetPublicKey())
		}
		for _, a := range peer.GetAllowedIps() {
			pr, err := netip.ParsePrefix(a)
			if err != nil || pr.Masked() != pr {
				return fmt.Errorf("allowed_ips %q: CIDR без лишних битов", a)
			}
			// Ядро молча переносит одинаковый префикс к последнему пиру (decisions E14, п. 9) — повтор запрещён.
			for _, q := range prefixes {
				if q.Overlaps(pr) {
					return fmt.Errorf("allowed_ips %s пересекается с %s у другого пира", pr, q)
				}
			}
			prefixes = append(prefixes, pr)
		}
	}
	for _, h := range p.GetHosts() {
		if !fqdnRe.MatchString(h.GetFqdn()) || len(h.GetFqdn()) > 253 {
			return fmt.Errorf("hosts: имя %q", h.GetFqdn())
		}
		if _, err := netip.ParseAddr(h.GetAddress()); err != nil {
			return fmt.Errorf("hosts: адрес %q", h.GetAddress())
		}
	}
	return nil
}

// Peer — пир в файле состояния.
type Peer struct {
	PublicKey  string   `json:"public_key"`
	Endpoint   string   `json:"endpoint,omitempty"`
	AllowedIPs []string `json:"allowed_ips"`
	Keepalive  uint32   `json:"keepalive_seconds,omitempty"`
}

// Host — строка блока имён.
type Host struct {
	FQDN    string `json:"fqdn"`
	Address string `json:"address"`
}

// Desired — желаемое состояние интерфейса.
type Desired struct {
	Iface      string `json:"iface"`
	Address    string `json:"address"`
	ListenPort int    `json:"listen_port"`
	MTU        int    `json:"mtu"`
	// KeyFile — имя файла ключа в каталоге (<iface>.key или <iface>.key.next после ротации).
	KeyFile    string `json:"key_file"`
	Peers      []Peer `json:"peers"`
	Forwarding bool   `json:"forwarding"`
	Hosts      []Host `json:"hosts,omitempty"`
	// DockerRule — правило транзита wg → wg в DOCKER-USER (decisions E14, п. 11а).
	DockerRule bool `json:"docker_rule,omitempty"`
	// Retired — файлы ключей, которые удаляются после подтверждения (ротация).
	Retired []string `json:"retired,omitempty"`
}

// Hash — хэш желаемого состояния без служебных полей (config_hash).
func (d *Desired) Hash() string {
	c := *d
	c.Retired = nil
	b, _ := json.Marshal(c)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// FromParams — желаемое состояние из параметров apply; keyFile — ключ, который совпал с expect_public_key.
func FromParams(p *agentv1.WireguardApplyParams, keyFile string, docker bool) *Desired {
	d := &Desired{Iface: p.GetIfaceName(), Address: p.GetAddress(), ListenPort: int(p.GetListenPort()), MTU: int(p.GetMtu()),
		KeyFile: keyFile, Forwarding: p.GetForwarding(), DockerRule: p.GetForwarding() && docker}
	if d.MTU == 0 {
		d.MTU = DefaultMTU
	}
	for _, x := range p.GetPeers() {
		ka := x.GetKeepaliveSeconds()
		d.Peers = append(d.Peers, Peer{PublicKey: x.GetPublicKey(), Endpoint: x.GetEndpoint(), AllowedIPs: append([]string{}, x.GetAllowedIps()...), Keepalive: ka})
	}
	sort.Slice(d.Peers, func(i, j int) bool { return d.Peers[i].PublicKey < d.Peers[j].PublicKey })
	for _, h := range p.GetHosts() {
		d.Hosts = append(d.Hosts, Host{FQDN: h.GetFqdn(), Address: h.GetAddress()})
	}
	return d
}

// ---------- Файлы ----------

// Store — каталог состояния и ключей (/etc/trassa/wireguard, root, 0700).
type Store struct{ Dir string }

func (s Store) path(name string) string { return filepath.Join(s.Dir, name) }

// DesiredPath — файл состояния интерфейса.
func (s Store) DesiredPath(iface string) string { return s.path(iface + ".json") }

// RemovedPath — метка удаления: ключи удаляются после подтверждения.
func (s Store) RemovedPath(iface string) string { return s.path(iface + ".removed") }

// Load — желаемое состояние; нет файла — nil.
func (s Store) Load(iface string) (*Desired, error) {
	b, err := os.ReadFile(s.DesiredPath(iface))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var d Desired
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, fmt.Errorf("%s: %w", s.DesiredPath(iface), err)
	}
	return &d, nil
}

func (s Store) Save(d *Desired) error {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(s.DesiredPath(d.Iface), b, 0o600, fsutil.Keep)
}

// Ifaces — интерфейсы с файлом состояния.
func (s Store) Ifaces() []string {
	ents, _ := os.ReadDir(s.Dir)
	var out []string
	for _, e := range ents {
		n := strings.TrimSuffix(e.Name(), ".json")
		if n != e.Name() && ValidIface(n) == nil {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

// readKey — приватный ключ из файла (0600, root).
func (s Store) readKey(file string) (wgtypes.Key, error) {
	b, err := fsutil.ReadLimited(s.path(file), 256)
	if err != nil {
		return wgtypes.Key{}, err
	}
	return wgtypes.ParseKey(strings.TrimSpace(string(b)))
}

// Keygen — wireguard.keygen: ключ создаётся один раз (повтор отдаёт тот же публичный); rotate — новый
// «следующий» рядом, текущий не трогается.
func (s Store) Keygen(iface string, rotate bool) (string, bool, error) {
	file := iface + ".key"
	if rotate {
		file = iface + ".key.next"
	}
	if k, err := s.readKey(file); err == nil {
		return k.PublicKey().String(), rotate, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", false, err
	}
	if rotate {
		if _, err := s.readKey(iface + ".key"); err != nil {
			return "", false, fmt.Errorf("ротация без текущего ключа: %w", err)
		}
	}
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return "", false, err
	}
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return "", false, err
	}
	if err := fsutil.WriteFileAtomic(s.path(file), []byte(k.String()+"\n"), 0o600, fsutil.Keep); err != nil {
		return "", false, err
	}
	return k.PublicKey().String(), rotate, nil
}

// MatchKey — какой файл ключа даёт публичный ключ want (текущий или «следующий»).
func (s Store) MatchKey(iface, want string) (string, error) {
	for _, f := range []string{iface + ".key", iface + ".key.next"} {
		if k, err := s.readKey(f); err == nil && k.PublicKey().String() == want {
			return f, nil
		}
	}
	return "", precond(CodeKeyMismatch, "ключ %s не совпадает с ключами сервера (нужен wireguard.keygen)", want)
}

// AfterConfirm — после подтверждения apply или remove: удалить ключи, отправленные в отставку ротацией, и
// ключи удалённого интерфейса (метка remove с purge). Откат до подтверждения ключей не теряет.
func (s Store) AfterConfirm() error {
	var errs []error
	for _, iface := range s.Ifaces() {
		d, err := s.Load(iface)
		if err != nil || d == nil || len(d.Retired) == 0 {
			continue
		}
		for _, f := range d.Retired {
			if strings.HasPrefix(f, iface+".key") && f != d.KeyFile {
				errs = append(errs, fsutil.RemoveSync(s.path(f)))
			}
		}
		d.Retired = nil
		errs = append(errs, s.Save(d))
	}
	ents, _ := os.ReadDir(s.Dir)
	for _, e := range ents {
		iface, ok := strings.CutSuffix(e.Name(), ".removed")
		if !ok || ValidIface(iface) != nil {
			continue
		}
		b, _ := os.ReadFile(s.path(e.Name()))
		if strings.TrimSpace(string(b)) == "purge" {
			for _, f := range []string{iface + ".key", iface + ".key.next"} {
				errs = append(errs, fsutil.RemoveSync(s.path(f)))
			}
		}
		errs = append(errs, fsutil.RemoveSync(s.path(e.Name())))
	}
	return errors.Join(errs...)
}

// ---------- Блок имён и пересылка ----------

func hostsMarkers(iface string) (string, string) {
	return "# BEGIN trassa:" + iface + " (управляет Trassa)", "# END trassa:" + iface
}

// RenderHosts — /etc/hosts с блоком интерфейса вместо прежнего; hosts пуст — блока нет.
func RenderHosts(old, iface string, hosts []Host) string {
	begin, end := hostsMarkers(iface)
	var keep []string
	in := false
	for _, l := range strings.Split(strings.TrimSuffix(old, "\n"), "\n") {
		switch {
		case l == begin:
			in = true
		case in && l == end:
			in = false
		case !in:
			keep = append(keep, l)
		}
	}
	out := strings.Join(keep, "\n")
	if out != "" {
		out += "\n"
	}
	if len(hosts) > 0 {
		out += begin + "\n"
		for _, h := range hosts {
			out += h.Address + " " + h.FQDN + "\n"
		}
		out += end + "\n"
	}
	return out
}

// SysctlFile — файл пересылки интерфейса (decisions E14, п. 11): только conf.<iface>.forwarding, ip_forward не
// трогается. Префикс «-»: нет интерфейса при загрузке — не ошибка.
func SysctlFile(iface string) string { return "/etc/sysctl.d/90-trassa-" + iface + ".conf" }

func sysctlContent(iface string) string {
	return "# Trassa: пересылка в приватной сети " + iface + ".\n-net.ipv4.conf." + iface + ".forwarding = 1\n-net.ipv6.conf." + iface + ".forwarding = 1\n"
}

// SysctlKeys — параметры пересылки интерфейса.
func SysctlKeys(iface string) []string {
	return []string{"net.ipv4.conf." + iface + ".forwarding", "net.ipv6.conf." + iface + ".forwarding"}
}

// DockerComment — комментарий правила транзита в DOCKER-USER.
func DockerComment(iface string) string { return "trassa:e14:" + iface }

func dockerRule(iface string) []string {
	return []string{"-i", iface, "-o", iface, "-m", "comment", "--comment", DockerComment(iface), "-j", "ACCEPT"}
}

// ---------- Ядро ----------

// Kernel — интерфейс и устройство WireGuard (netlink и wgctrl; в тестах — подделка).
type Kernel interface {
	// Probe — поддерживает ли ядро WireGuard (создание и удаление пробного интерфейса).
	Probe() error
	Devices() ([]*wgtypes.Device, error)
	Device(name string) (*wgtypes.Device, error)
	// Ensure — интерфейс есть, адрес ровно address, MTU, поднят.
	Ensure(name, address string, mtu int) error
	Configure(name string, cfg wgtypes.Config) error
	Delete(name string) error
	// Exists — интерфейс с таким именем есть.
	Exists(name string) bool
	// Address — адрес интерфейса (первый) и MTU.
	Address(name string) (string, int, error)
}

// Runner — внешние команды без оболочки (iptables).
type Runner func(ctx context.Context, name string, args ...string) ([]byte, error)

// System — всё, чем пользуется Sync.
type System struct {
	Store   Store
	Kernel  Kernel
	Run     Runner
	Hosts   string // /etc/hosts
	ProcSys string // /proc/sys
	// DockerPresent — Docker стоит на сервере (сокет есть).
	DockerPresent func() bool
}

// Sync — привести ядро к файлу состояния iface: нет файла — интерфейс, правило Docker и пересылка снимаются;
// есть — интерфейс создаётся или обновляется, список пиров заменяется целиком.
func (sys *System) Sync(ctx context.Context, iface string) error {
	d, err := sys.Store.Load(iface)
	if err != nil {
		return err
	}
	if d == nil {
		var errs []error
		if sys.Kernel.Exists(iface) {
			errs = append(errs, sys.Kernel.Delete(iface))
		}
		errs = append(errs, sys.dockerRule(ctx, iface, false))
		return errors.Join(errs...)
	}
	key, err := sys.Store.readKey(d.KeyFile)
	if err != nil {
		return fmt.Errorf("ключ %s: %w", d.KeyFile, err)
	}
	if err := sys.Kernel.Ensure(iface, d.Address, d.MTU); err != nil {
		return err
	}
	port := d.ListenPort
	cfg := wgtypes.Config{PrivateKey: &key, ListenPort: &port, ReplacePeers: true}
	for _, p := range d.Peers {
		pk, err := wgtypes.ParseKey(p.PublicKey)
		if err != nil {
			return err
		}
		pc := wgtypes.PeerConfig{PublicKey: pk, ReplaceAllowedIPs: true}
		if p.Endpoint != "" {
			ap, err := netip.ParseAddrPort(p.Endpoint)
			if err != nil {
				return err
			}
			pc.Endpoint = netAddr(ap)
		}
		if p.Keepalive > 0 {
			ka := time.Duration(p.Keepalive) * time.Second
			pc.PersistentKeepaliveInterval = &ka
		}
		for _, a := range p.AllowedIPs {
			pr, err := netip.ParsePrefix(a)
			if err != nil {
				return err
			}
			pc.AllowedIPs = append(pc.AllowedIPs, ipNet(pr))
		}
		cfg.Peers = append(cfg.Peers, pc)
	}
	if err := sys.Kernel.Configure(iface, cfg); err != nil {
		return err
	}
	if d.Forwarding {
		for _, k := range SysctlKeys(iface) {
			p := filepath.Join(sys.ProcSys, strings.ReplaceAll(k, ".", "/"))
			if _, err := os.Stat(p); err == nil {
				if err := os.WriteFile(p, []byte("1\n"), 0o644); err != nil {
					return fmt.Errorf("%s: %w", k, err)
				}
			}
		}
	}
	return sys.dockerRule(ctx, iface, d.DockerRule)
}

// SyncHosts — блок имён интерфейса в /etc/hosts по файлу состояния (cloud-init может перерисовать файл при
// загрузке — помощник восстанавливает блок при старте).
func (sys *System) SyncHosts(iface string) error {
	d, err := sys.Store.Load(iface)
	if err != nil {
		return err
	}
	var hosts []Host
	if d != nil {
		hosts = d.Hosts
	}
	old, err := os.ReadFile(sys.Hosts)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	next := RenderHosts(string(old), iface, hosts)
	if next == string(old) {
		return nil
	}
	mode := os.FileMode(0o644)
	if st, err := os.Stat(sys.Hosts); err == nil {
		mode = st.Mode().Perm()
	}
	return fsutil.WriteFileAtomic(sys.Hosts, []byte(next), mode, fsutil.Keep)
}

// DockerChain — есть ли цепочка DOCKER-USER (iptables).
func (sys *System) DockerChain(ctx context.Context) bool {
	_, err := sys.Run(ctx, "iptables", "-S", "DOCKER-USER")
	return err == nil
}

// dockerRuleCount — сколько правил Trassa для iface в DOCKER-USER.
func (sys *System) dockerRuleCount(ctx context.Context, iface string) (int, error) {
	out, err := sys.Run(ctx, "iptables", "-S", "DOCKER-USER")
	if err != nil {
		return 0, err
	}
	n := 0
	for _, l := range strings.Split(string(out), "\n") {
		f := strings.Fields(l)
		for i := 0; i+1 < len(f); i++ {
			if f[i] == "--comment" && strings.Trim(f[i+1], `"`) == DockerComment(iface) {
				n++
			}
		}
	}
	return n, nil
}

// dockerRule — правило транзита есть ровно один раз (want) или его нет. Нет цепочки и нет правила — ничего.
func (sys *System) dockerRule(ctx context.Context, iface string, want bool) error {
	if sys.Run == nil {
		if want {
			return errors.New("iptables недоступен")
		}
		return nil
	}
	n, err := sys.dockerRuleCount(ctx, iface)
	if err != nil {
		if want {
			return precond("FIX_PRECONDITION", "цепочки DOCKER-USER нет — транзит wg → wg на сервере с Docker не настроить")
		}
		return nil
	}
	for ; n > 1 || (!want && n > 0); n-- {
		if out, err := sys.Run(ctx, "iptables", append([]string{"-D", "DOCKER-USER"}, dockerRule(iface)...)...); err != nil {
			return fmt.Errorf("iptables -D DOCKER-USER: %v %s", err, out)
		}
	}
	if want && n == 0 {
		if out, err := sys.Run(ctx, "iptables", append([]string{"-I", "DOCKER-USER", "1"}, dockerRule(iface)...)...); err != nil {
			return fmt.Errorf("iptables -I DOCKER-USER: %v %s", err, out)
		}
	}
	return nil
}

// Verify — устройство совпадает с файлом: ключ, порт, набор пиров и их адреса; интерфейс с нужным адресом;
// правило Docker ровно одно, если нужно.
func (sys *System) Verify(ctx context.Context, iface string) error {
	d, err := sys.Store.Load(iface)
	if err != nil {
		return err
	}
	if d == nil {
		if sys.Kernel.Exists(iface) {
			return fmt.Errorf("интерфейс %s остался", iface)
		}
		if n, err := sys.dockerRuleCount(ctx, iface); err == nil && n > 0 {
			return errors.New("правило DOCKER-USER осталось")
		}
		return nil
	}
	dev, err := sys.Kernel.Device(iface)
	if err != nil {
		return fmt.Errorf("устройство %s: %w", iface, err)
	}
	key, err := sys.Store.readKey(d.KeyFile)
	if err != nil {
		return err
	}
	if dev.PublicKey != key.PublicKey() || dev.ListenPort != d.ListenPort {
		return errors.New("ключ или порт устройства не совпали")
	}
	want := map[string]string{}
	for _, p := range d.Peers {
		ips := append([]string{}, p.AllowedIPs...)
		sort.Strings(ips)
		want[p.PublicKey] = strings.Join(ips, ",")
	}
	if len(dev.Peers) != len(want) {
		return fmt.Errorf("пиров %d, ждали %d", len(dev.Peers), len(want))
	}
	for _, p := range dev.Peers {
		var ips []string
		for _, a := range p.AllowedIPs {
			ips = append(ips, a.String())
		}
		sort.Strings(ips)
		if w, ok := want[p.PublicKey.String()]; !ok || w != strings.Join(ips, ",") {
			return fmt.Errorf("пир %s не совпал", p.PublicKey)
		}
	}
	addr, mtu, err := sys.Kernel.Address(iface)
	if err != nil {
		return err
	}
	if addr != d.Address || mtu != d.MTU {
		return fmt.Errorf("адрес %s MTU %d, ждали %s %d", addr, mtu, d.Address, d.MTU)
	}
	if d.DockerRule {
		if n, err := sys.dockerRuleCount(ctx, iface); err != nil || n != 1 {
			return fmt.Errorf("правило DOCKER-USER: %d (%v), ждали ровно одно", n, err)
		}
	}
	return nil
}

func netAddr(ap netip.AddrPort) *net.UDPAddr { return net.UDPAddrFromAddrPort(ap) }

func ipNet(p netip.Prefix) net.IPNet {
	return net.IPNet{IP: p.Addr().AsSlice(), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())}
}
