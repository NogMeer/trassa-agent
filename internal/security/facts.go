// SPDX-License-Identifier: AGPL-3.0-only

package security

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/dockerapi"
	"github.com/NogMeer/trassa-agent/internal/metrics"
)

// System — система, которую проверяет скан. В тестах Root — каталог с образцами файлов.
type System struct {
	Root   string
	Run    func(ctx context.Context, name string, args ...string) ([]byte, error)
	Docker interface {
		Get(ctx context.Context, path string) (*http.Response, error)
	}
	Statfs    func(path string) (metrics.FS, error)
	Addresses func() ([]netip.Prefix, error)
	Now       func() time.Time
	// Adjtimex — maxerror часов ядра в микросекундах (adjtimex, modes=0).
	Adjtimex func() (int64, error)
	// Detector — наблюдение (E10-T7): ожидающие объекты для проверок COMPROMISE_* и базовый список для снимка.
	Detector *Detector
	// RootUID — uid владельца системных файлов: 0, в тестах — uid того, кто запускает тест.
	RootUID int
}

// Real — система, на которой работает помощник.
func Real() *System {
	return &System{
		Root: "/", Run: runCmd, Docker: &dockerapi.Client{}, Statfs: metrics.New().Statfs, Addresses: ifaceAddrs, Now: time.Now, Adjtimex: adjtimex,
	}
}

// runCmd запускает программу без оболочки, с чистым окружением и пределом вывода 4 МиБ.
func runCmd(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = []string{"LANG=C", "LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin", "DEBIAN_FRONTEND=noninteractive"}
	var out limitedBuffer
	out.max = 4 << 20
	cmd.Stdout = &out
	cmd.Stderr = io.Discard
	err := cmd.Run()
	return out.b, err
}

type limitedBuffer struct {
	b   []byte
	max int
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	if room := l.max - len(l.b); room > 0 {
		l.b = append(l.b, p[:min(len(p), room)]...)
	}
	return len(p), nil
}

func ifaceAddrs() ([]netip.Prefix, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	var out []netip.Prefix
	for _, a := range addrs {
		if p, err := netip.ParsePrefix(a.String()); err == nil {
			out = append(out, p)
		}
	}
	return out, nil
}

func (s *System) path(p string) string { return filepath.Join(s.Root, p) }

// run запускает программу через Run; без Run (тесты, которым программы не нужны) — ошибка.
func (s *System) run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if s.Run == nil {
		return nil, fmt.Errorf("%s: запуск программ недоступен", name)
	}
	return s.Run(ctx, name, args...)
}

// Scan — один скан: факты читаются один раз и делятся между проверками.
type Scan struct {
	sys *System
	mu  sync.Mutex

	users     []User
	usersErr  error
	usersDone bool

	listeners     []*agentv1.Listener
	listenersErr  error
	listenersDone bool

	containers     []container
	containersErr  error
	containersDone bool

	fw    *firewall
	fwErr error

	ssh    *agentv1.SshEffective
	sshErr error
}

func newScan(sys *System) *Scan { return &Scan{sys: sys} }

// ---------- Учётные записи ----------

// User — строка /etc/passwd с полем пароля из /etc/shadow (только признаки, не хэш).
type User struct {
	Name     string
	UID, GID int
	Home     string
	Shell    string
	// EmptyPassword — в shadow пустое поле пароля (вход без пароля); Locked — пароль заблокирован (! или *).
	EmptyPassword bool
	Locked        bool
}

func (s *Scan) Users() ([]User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.usersDone {
		s.users, s.usersErr = readUsers(s.sys)
		s.usersDone = true
	}
	return s.users, s.usersErr
}

func readUsers(sys *System) ([]User, error) {
	pw, err := os.ReadFile(sys.path("/etc/passwd"))
	if err != nil {
		return nil, err
	}
	shadow := map[string]string{}
	if sh, err := os.ReadFile(sys.path("/etc/shadow")); err == nil {
		for _, l := range strings.Split(string(sh), "\n") {
			f := strings.Split(l, ":")
			if len(f) >= 2 {
				shadow[f[0]] = f[1]
			}
		}
	}
	var out []User
	for _, l := range strings.Split(string(pw), "\n") {
		f := strings.Split(l, ":")
		if len(f) < 7 || strings.HasPrefix(l, "#") {
			continue
		}
		uid, err1 := strconv.Atoi(f[2])
		gid, err2 := strconv.Atoi(f[3])
		if err1 != nil || err2 != nil {
			continue
		}
		u := User{Name: f[0], UID: uid, GID: gid, Home: f[5], Shell: f[6]}
		pwField := f[1]
		if pwField == "x" {
			pwField = shadow[f[0]]
		}
		u.EmptyPassword = pwField == ""
		u.Locked = strings.HasPrefix(pwField, "!") || strings.HasPrefix(pwField, "*")
		out = append(out, u)
	}
	return out, nil
}

// noLoginShells — оболочки, которые не дают войти.
var noLoginShells = map[string]bool{
	"/usr/sbin/nologin": true, "/sbin/nologin": true, "/bin/false": true, "/usr/bin/false": true,
	"/bin/sync": true, "/sbin/shutdown": true, "/sbin/halt": true, "": true,
}

// CanLogin — у записи оболочка для входа.
func (u User) CanLogin() bool { return !noLoginShells[u.Shell] }

// groupMembers — участники групп из /etc/group (только явный список; основная группа пользователя не в нём).
func (s *Scan) groupMembers() (map[string][]string, map[int]string, error) {
	b, err := os.ReadFile(s.sys.path("/etc/group"))
	if err != nil {
		return nil, nil, err
	}
	members := map[string][]string{}
	byGID := map[int]string{}
	for _, l := range strings.Split(string(b), "\n") {
		f := strings.Split(l, ":")
		if len(f) < 4 {
			continue
		}
		if gid, err := strconv.Atoi(f[2]); err == nil {
			byGID[gid] = f[0]
		}
		for _, m := range strings.Split(f[3], ",") {
			if m != "" {
				members[f[0]] = append(members[f[0]], m)
			}
		}
	}
	return members, byGID, nil
}

// ---------- Сокеты ----------

// Listeners — слушающие сокеты TCP и UDP с процессом и контейнером.
func (s *Scan) Listeners(ctx context.Context) ([]*agentv1.Listener, error) {
	s.mu.Lock()
	done := s.listenersDone
	s.mu.Unlock()
	if done {
		return s.listeners, s.listenersErr
	}
	l, err := readListeners(ctx, s)
	s.mu.Lock()
	s.listeners, s.listenersErr, s.listenersDone = l, err, true
	s.mu.Unlock()
	return l, err
}

type rawSocket struct {
	proto string
	addr  netip.Addr
	port  uint16
	inode string
}

// parseProcNet разбирает /proc/net/{tcp,udp}[6]: слушающие TCP (st 0A) и несвязанные UDP (st 07).
func parseProcNet(b []byte, proto string, v6 bool) []rawSocket {
	var out []rawSocket
	want := "0A"
	if strings.HasPrefix(proto, "udp") {
		want = "07"
	}
	for i, l := range strings.Split(string(b), "\n") {
		f := strings.Fields(l)
		if i == 0 || len(f) < 10 || f[3] != want {
			continue
		}
		hostHex, portHex, ok := strings.Cut(f[1], ":")
		if !ok {
			continue
		}
		port, err := strconv.ParseUint(portHex, 16, 16)
		if err != nil {
			continue
		}
		addr, ok := procAddr(hostHex, v6)
		if !ok {
			continue
		}
		out = append(out, rawSocket{proto: strings.TrimSuffix(proto, "6"), addr: addr, port: uint16(port), inode: f[9]})
	}
	return out
}

// procAddr — адрес из /proc/net: 32-битные слова в порядке байтов хоста (little-endian на amd64 и arm64).
func procAddr(h string, v6 bool) (netip.Addr, bool) {
	b, err := hex.DecodeString(h)
	if err != nil || (!v6 && len(b) != 4) || (v6 && len(b) != 16) {
		return netip.Addr{}, false
	}
	for i := 0; i+4 <= len(b); i += 4 {
		b[i], b[i+1], b[i+2], b[i+3] = b[i+3], b[i+2], b[i+1], b[i]
	}
	a, ok := netip.AddrFromSlice(b)
	return a.Unmap(), ok
}

var dockerCgroupRe = regexp.MustCompile(`(?:docker-|/docker/)([0-9a-f]{64})`)

func readListeners(ctx context.Context, s *Scan) ([]*agentv1.Listener, error) {
	var socks []rawSocket
	for _, n := range []struct {
		file string
		v6   bool
	}{{"tcp", false}, {"tcp6", true}, {"udp", false}, {"udp6", true}} {
		b, err := os.ReadFile(s.sys.path("/proc/net/" + n.file))
		if err != nil {
			if os.IsNotExist(err) && n.v6 {
				continue // IPv6 выключен
			}
			return nil, err
		}
		socks = append(socks, parseProcNet(b, n.file, n.v6)...)
	}
	// inode сокета → pid по /proc/<pid>/fd (помощник — root).
	owner := map[string]int{}
	procs, _ := os.ReadDir(s.sys.path("/proc"))
	for _, p := range procs {
		pid, err := strconv.Atoi(p.Name())
		if err != nil {
			continue
		}
		fds, _ := os.ReadDir(s.sys.path(fmt.Sprintf("/proc/%d/fd", pid)))
		for _, fd := range fds {
			t, err := os.Readlink(s.sys.path(fmt.Sprintf("/proc/%d/fd/%s", pid, fd.Name())))
			if err == nil && strings.HasPrefix(t, "socket:[") {
				owner[strings.TrimSuffix(strings.TrimPrefix(t, "socket:["), "]")] = pid
			}
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	conts, _ := s.Containers(ctx)
	byID := map[string]string{}
	byPort := map[string]string{}
	for _, c := range conts {
		byID[c.id] = c.name
		for _, p := range c.publicPorts {
			byPort[p] = c.name
		}
	}
	seen := map[string]bool{}
	var out []*agentv1.Listener
	for _, sk := range socks {
		key := fmt.Sprintf("%s/%s/%d", sk.proto, sk.addr, sk.port)
		if seen[key] {
			continue
		}
		seen[key] = true
		l := &agentv1.Listener{Protocol: sk.proto, Address: sk.addr.String(), Port: uint32(sk.port), Public: isPublic(sk.addr)}
		if pid, ok := owner[sk.inode]; ok {
			comm, _ := os.ReadFile(s.sys.path(fmt.Sprintf("/proc/%d/comm", pid)))
			l.Process = strings.TrimSpace(string(comm))
			if cg, err := os.ReadFile(s.sys.path(fmt.Sprintf("/proc/%d/cgroup", pid))); err == nil {
				if m := dockerCgroupRe.FindStringSubmatch(string(cg)); m != nil {
					l.Container = byID[m[1]]
				}
			}
		}
		if l.Container == "" && (l.Process == "docker-proxy" || l.Process == "dockerd") {
			l.Container = byPort[fmt.Sprintf("%s/%d", sk.proto, sk.port)]
		}
		out = append(out, l)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Port != out[j].Port {
			return out[i].Port < out[j].Port
		}
		return out[i].Protocol+out[i].Address < out[j].Protocol+out[j].Address
	})
	return out, nil
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// isPublic — адрес может быть виден снаружи: не loopback, не link-local и не только частный. 0.0.0.0 и ::
// слушают все адреса, в том числе публичные.
func isPublic(a netip.Addr) bool {
	if a.IsUnspecified() {
		return true
	}
	return !(a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsPrivate() || cgnat.Contains(a))
}

// ---------- Docker ----------

type container struct {
	id          string
	name        string
	publicPorts []string // «tcp/8080»
	privileged  bool
	dockerSock  bool
}

// Containers — работающие контейнеры. Docker нет — пустой список без ошибки.
func (s *Scan) Containers(ctx context.Context) ([]container, error) {
	s.mu.Lock()
	if s.containersDone {
		defer s.mu.Unlock()
		return s.containers, s.containersErr
	}
	s.mu.Unlock()
	c, err := readContainers(ctx, s.sys)
	s.mu.Lock()
	s.containers, s.containersErr, s.containersDone = c, err, true
	s.mu.Unlock()
	return c, err
}

func readContainers(ctx context.Context, sys *System) ([]container, error) {
	if sys.Docker == nil {
		return nil, nil
	}
	dctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	resp, err := sys.Docker.Get(dctx, "/containers/json")
	if err == dockerapi.ErrNoDocker {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("docker api: HTTP %d", resp.StatusCode)
	}
	var list []struct {
		ID    string   `json:"Id"`
		Names []string `json:"Names"`
		Ports []struct {
			PublicPort uint16 `json:"PublicPort"`
			Type       string `json:"Type"`
		} `json:"Ports"`
		HostConfig struct{} `json:"HostConfig"`
		Mounts     []struct {
			Source string `json:"Source"`
		} `json:"Mounts"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(&list); err != nil {
		return nil, err
	}
	var out []container
	for _, c := range list {
		name := c.ID
		if len(c.Names) > 0 {
			name = strings.TrimPrefix(c.Names[0], "/")
		}
		ct := container{id: c.ID, name: name}
		for _, p := range c.Ports {
			if p.PublicPort != 0 {
				ct.publicPorts = append(ct.publicPorts, fmt.Sprintf("%s/%d", p.Type, p.PublicPort))
			}
		}
		for _, m := range c.Mounts {
			if m.Source == "/var/run/docker.sock" || m.Source == "/run/docker.sock" {
				ct.dockerSock = true
			}
		}
		// Privileged есть только в inspect.
		if r, err := sys.Docker.Get(dctx, "/containers/"+c.ID+"/json"); err == nil {
			var in struct {
				HostConfig struct {
					Privileged bool `json:"Privileged"`
				} `json:"HostConfig"`
			}
			_ = json.NewDecoder(io.LimitReader(r.Body, 4<<20)).Decode(&in)
			r.Body.Close()
			ct.privileged = in.HostConfig.Privileged
		}
		out = append(out, ct)
	}
	return out, nil
}

// ---------- Файлы ----------

// lines читает файл построчно без комментариев и пустых строк.
func (s *System) lines(p string) ([]string, error) {
	// Файлы пользователя (authorized_keys) могут оказаться каналом или устройством по ссылке: O_NONBLOCK не даёт
	// повиснуть на открытии, читается только обычный файл.
	f, err := os.OpenFile(s.path(p), os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if st, err := f.Stat(); err != nil {
		return nil, err
	} else if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: не обычный файл", p)
	}
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out, sc.Err()
}
