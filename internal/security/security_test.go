// SPDX-License-Identifier: AGPL-3.0-only

package security

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/metrics"
)

type tree map[string]string

func build(t *testing.T, files tree) *System {
	t.Helper()
	root := t.TempDir()
	for p, body := range files {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if strings.HasPrefix(body, "->") {
			if err := os.Symlink(strings.TrimPrefix(body, "->"), full); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return &System{Root: root, Now: time.Now, RootUID: os.Getuid()}
}

func scan(t *testing.T, sys *System, codes ...string) map[string][]*agentv1.CheckResult {
	t.Helper()
	if err := ValidateParams(&agentv1.SecurityScanParams{Checks: codes}); err != nil {
		t.Fatal(err)
	}
	res := Run(context.Background(), sys, &agentv1.SecurityScanParams{Checks: codes})
	out := map[string][]*agentv1.CheckResult{}
	for _, c := range res.GetChecks() {
		out[c.GetCode()] = append(out[c.GetCode()], c)
	}
	return out
}

func states(rs []*agentv1.CheckResult) string {
	var b []string
	for _, r := range rs {
		b = append(b, strings.TrimPrefix(r.GetState().String(), "CHECK_STATE_")+":"+r.GetSubject())
	}
	return strings.Join(b, ",")
}

const passwd = `root:x:0:0:root:/root:/bin/bash
toor:x:0:0::/root:/bin/sh
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/bin/bash
alice:x:1000:1000::/home/alice:/bin/bash
bob:x:1001:1001::/home/bob:/bin/bash
`

const shadow = `root:$6$hash:19000:0:99999:7:::
toor:!:19000::::::
daemon:*:19000::::::
www-data:*:19000::::::
alice:$y$hash:19000::::::
bob::19000::::::
`

func TestUsersAndSudo(t *testing.T) {
	sys := build(t, tree{
		"etc/passwd": passwd, "etc/shadow": shadow,
		"etc/group":                "root:x:0:\nsudo:x:27:alice\nbob:x:1001:\n",
		"etc/sudoers":              "Defaults env_reset\nroot ALL=(ALL:ALL) ALL\n%sudo ALL=(ALL:ALL) ALL\n@includedir /etc/sudoers.d\n",
		"etc/sudoers.d/90-bob":     "bob ALL=(ALL) NOPASSWD: ALL\n",
		"etc/sudoers.d/README":     "# пусто\n",
		"etc/sudoers.d/skip.dpkg~": "eve ALL=(ALL) NOPASSWD: ALL\n",
	})
	r := scan(t, sys, "USER_UID0_EXTRA", "USER_EMPTY_PASSWORD", "USER_NO_ADMIN", "SUDO_NOPASSWD_ALL", "USER_SERVICE_SHELL")
	for code, want := range map[string]string{
		"USER_UID0_EXTRA":     "FAIL:toor",
		"USER_EMPTY_PASSWORD": "FAIL:bob",
		"USER_NO_ADMIN":       "PASS:",
		"SUDO_NOPASSWD_ALL":   "FAIL:bob",
		"USER_SERVICE_SHELL":  "FAIL:www-data",
	} {
		if got := states(r[code]); got != want {
			t.Errorf("%s: %s, ждали %s", code, got, want)
		}
	}
	for _, c := range r["USER_EMPTY_PASSWORD"] {
		if strings.Contains(c.GetEvidence(), "$") {
			t.Fatal("хэш пароля в evidence")
		}
	}
	// Без пользователя с sudo.
	sys = build(t, tree{"etc/passwd": "root:x:0:0::/root:/bin/bash\n", "etc/group": "sudo:x:27:\n", "etc/shadow": "root:x::::::::\n"})
	if got := states(scan(t, sys, "USER_NO_ADMIN")["USER_NO_ADMIN"]); got != "FAIL:" {
		t.Fatal(got)
	}
}

func TestPerms(t *testing.T) {
	sys := build(t, tree{
		"etc/passwd": passwd, "etc/shadow": shadow, "etc/group": "g:x:1:\n", "etc/crontab": "",
		"home/alice/.ssh/authorized_keys": "", "etc/ok.conf": "", "etc/bad.conf": "", "etc/link": "->/tmp/x",
	})
	chmod := func(p string, m os.FileMode) {
		if err := os.Chmod(filepath.Join(sys.Root, p), m); err != nil {
			t.Fatal(err)
		}
	}
	chmod("etc/shadow", 0o644)
	chmod("home/alice/.ssh", 0o777)
	chmod("etc/bad.conf", 0o666)
	if err := os.MkdirAll(filepath.Join(sys.Root, "etc/sticky"), 0o755); err != nil {
		t.Fatal(err)
	}
	chmod("etc/sticky", os.ModeSticky|0o777)
	r := scan(t, sys, "PERM_SYSTEM_FILES", "PERM_USER_SSH_DIR", "PERM_WORLD_WRITABLE", "PERM_CRON")
	for code, want := range map[string]string{
		"PERM_SYSTEM_FILES":   "FAIL:/etc/shadow",
		"PERM_USER_SSH_DIR":   "FAIL:/home/alice/.ssh",
		"PERM_WORLD_WRITABLE": "FAIL:/etc/bad.conf",
		"PERM_CRON":           "PASS:",
	} {
		if got := states(r[code]); got != want {
			t.Errorf("%s: %s, ждали %s", code, got, want)
		}
	}
}

func TestKernelAndReboot(t *testing.T) {
	sys := build(t, tree{
		"proc/sys/kernel/randomize_va_space":                  "0\n",
		"proc/sys/net/ipv4/conf/all/accept_redirects":         "1\n",
		"proc/sys/net/ipv4/conf/default/accept_redirects":     "0\n",
		"proc/sys/net/ipv4/conf/all/send_redirects":           "0\n",
		"proc/sys/net/ipv4/conf/all/accept_source_route":      "0\n",
		"proc/sys/net/ipv4/conf/all/log_martians":             "1\n",
		"proc/sys/net/ipv4/icmp_echo_ignore_broadcasts":       "1\n",
		"proc/sys/net/ipv4/icmp_ignore_bogus_error_responses": "1\n",
		"proc/sys/net/ipv4/tcp_syncookies":                    "1\n",
		"run/reboot-required":                                 "*** System restart required ***\n",
		"run/reboot-required.pkgs":                            "linux-image-6.8.0-50-generic\n",
	})
	r := scan(t, sys, "KERNEL_ASLR_OFF", "SYSCTL_NETWORK", "REBOOT_REQUIRED")
	if got := states(r["KERNEL_ASLR_OFF"]); got != "FAIL:kernel.randomize_va_space" {
		t.Error(got)
	}
	if got := states(r["SYSCTL_NETWORK"]); got != "FAIL:net.ipv4.conf.all.accept_redirects" {
		t.Error(got)
	}
	if rb := r["REBOOT_REQUIRED"]; len(rb) != 1 || !strings.Contains(rb[0].GetEvidence(), "linux-image") {
		t.Errorf("%+v", rb)
	}
	if got := states(scan(t, build(t, tree{}), "REBOOT_REQUIRED")["REBOOT_REQUIRED"]); got != "PASS:" {
		t.Error(got)
	}
}

func TestDisk(t *testing.T) {
	sys := build(t, tree{"proc/self/mountinfo": "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n2 1 8:2 / /data rw - xfs /dev/sdb rw\n"})
	sys.Statfs = func(p string) (metrics.FS, error) {
		if p == "/data" {
			return metrics.FS{Blocks: 100, Bfree: 5, Bavail: 5, Files: 100, Ffree: 50}, nil
		}
		return metrics.FS{Blocks: 100, Bfree: 50, Bavail: 45, Files: 100, Ffree: 5}, nil
	}
	r := scan(t, sys, "DISK_SPACE_LOW", "DISK_INODES_LOW")
	if states(r["DISK_SPACE_LOW"]) != "FAIL:/data" || states(r["DISK_INODES_LOW"]) != "FAIL:/" {
		t.Fatalf("%s | %s", states(r["DISK_SPACE_LOW"]), states(r["DISK_INODES_LOW"]))
	}
}

// /proc/net/tcp: 0.0.0.0:22 (sshd), 127.0.0.1:5432, 0.0.0.0:6379 (redis), 10.0.0.5:8080; tcp6 [::]:2375 (dockerd).
const procTCP = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1001 1 0 100 0 0 10 0
   1: 0100007F:1538 00000000:0000 0A 00000000:00000000 00:00000000 00000000   111        0 1002 1 0 100 0 0 10 0
   2: 00000000:18EB 00000000:0000 0A 00000000:00000000 00:00000000 00000000   999        0 1003 1 0 100 0 0 10 0
   3: 0500000A:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1004 1 0 100 0 0 10 0
   4: 0500000A:1F91 0600000A:C350 01 00000000:00000000 00:00000000 00000000     0        0 1005 1 0 100 0 0 10 0
`
const procTCP6 = `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:0947 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2001 1 0 100 0 0 10 0
`

func TestListenersAndPorts(t *testing.T) {
	sys := build(t, tree{
		"proc/net/tcp": procTCP, "proc/net/tcp6": procTCP6, "proc/net/udp": "  sl\n",
		"proc/10/fd/3": "->socket:[1001]", "proc/10/comm": "sshd\n", "proc/10/cgroup": "0::/system.slice/ssh.service\n",
		"proc/20/fd/5": "->socket:[1003]", "proc/20/comm": "redis-server\n",
		"proc/20/cgroup": "0::/system.slice/docker-" + strings.Repeat("ab", 32) + ".scope\n",
		"proc/30/fd/7":   "->socket:[2001]", "proc/30/comm": "dockerd\n",
	})
	sys.Docker = &fakeDocker{body: `[{"Id":"` + strings.Repeat("ab", 32) + `","Names":["/cache"],"Ports":[{"PublicPort":6379,"Type":"tcp"}]}]`}
	sys.Addresses = func() ([]netip.Prefix, error) { return []netip.Prefix{netip.MustParsePrefix("203.0.113.5/24")}, nil }
	res := Run(context.Background(), sys, &agentv1.SecurityScanParams{Checks: []string{"OPEN_PORTS", "DB_PORT_PUBLIC", "DOCKER_API_EXPOSED"}})
	byCode := map[string][]*agentv1.CheckResult{}
	for _, c := range res.GetChecks() {
		byCode[c.GetCode()] = append(byCode[c.GetCode()], c)
	}
	if got := states(byCode["OPEN_PORTS"]); got != "FAIL:tcp/22,FAIL:tcp/2375,FAIL:tcp/6379" {
		t.Errorf("OPEN_PORTS: %s", got)
	}
	if got := states(byCode["DB_PORT_PUBLIC"]); got != "FAIL:tcp/6379" {
		t.Errorf("DB_PORT_PUBLIC: %s", got)
	}
	if got := states(byCode["DOCKER_API_EXPOSED"]); got != "FAIL:tcp/2375" {
		t.Errorf("DOCKER_API_EXPOSED: %s", got)
	}
	if len(res.GetListeners()) != 5 || res.GetAddresses()[0] != "203.0.113.5/24" {
		t.Fatalf("снимок: %+v", res.GetListeners())
	}
	var redis *agentv1.Listener
	for _, l := range res.GetListeners() {
		if l.GetPort() == 6379 {
			redis = l
		}
	}
	if redis.GetProcess() != "redis-server" || redis.GetContainer() != "cache" || !redis.GetPublic() {
		t.Fatalf("redis: %+v", redis)
	}
}

func TestParamsAndTimeout(t *testing.T) {
	for _, p := range []*agentv1.SecurityScanParams{
		{}, {Checks: []string{"NOPE"}}, {Checks: []string{"OPEN_PORTS", "OPEN_PORTS"}},
	} {
		if ValidateParams(p) == nil {
			t.Errorf("принято: %v", p.GetChecks())
		}
	}
	register(Check{Code: "TEST_SLOW", Run: func(ctx context.Context, _ *Scan) []Finding { <-ctx.Done(); return nil }})
	register(Check{Code: "TEST_PANIC", Run: func(context.Context, *Scan) []Finding { panic("x") }})
	register(Check{Code: "TEST_SECRET", Run: func(context.Context, *Scan) []Finding {
		return []Finding{fail("s", "password=hunter2hunter2 "+strings.Repeat("x", 5000))}
	}})
	t.Cleanup(func() { delete(registry, "TEST_SLOW"); delete(registry, "TEST_PANIC"); delete(registry, "TEST_SECRET") })
	old := checkTimeout
	checkTimeout = 50 * time.Millisecond
	t.Cleanup(func() { checkTimeout = old })
	res := Run(context.Background(), build(t, tree{}), &agentv1.SecurityScanParams{Checks: []string{"TEST_SLOW", "TEST_PANIC", "TEST_SECRET"}})
	c := res.GetChecks()
	if c[0].GetError() != ErrTimeout || c[1].GetError() != ErrReadFailed {
		t.Fatalf("%+v", c)
	}
	if strings.Contains(c[2].GetEvidence(), "hunter2") || len(c[2].GetEvidence()) > MaxEvidence {
		t.Fatalf("evidence: %d %q", len(c[2].GetEvidence()), c[2].GetEvidence()[:40])
	}
}
