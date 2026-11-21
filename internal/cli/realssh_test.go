// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// sshd — SSH-сервер на x/crypto/ssh: пускает по сертификату нашего CA с принципалом-логином, на exec отвечает
// «ok:<команда>». reject — отклонять всё и только записывать, какие ключи предложил клиент.
type sshd struct {
	addr    *net.TCPAddr
	hostKey ssh.PublicKey
	mu      sync.Mutex
	offered []string
}

func startSSHD(t *testing.T, ca ssh.PublicKey, reject bool) *sshd {
	t.Helper()
	_, hpriv, _ := ed25519.GenerateKey(rand.Reader)
	hs, _ := ssh.NewSignerFromKey(hpriv)
	d := &sshd{hostKey: hs.PublicKey()}
	checker := &ssh.CertChecker{IsUserAuthority: func(k ssh.PublicKey) bool { return bytes.Equal(k.Marshal(), ca.Marshal()) }}
	cfg := &ssh.ServerConfig{PublicKeyCallback: func(c ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
		d.mu.Lock()
		d.offered = append(d.offered, k.Type()+" "+string(ssh.MarshalAuthorizedKey(k)))
		d.mu.Unlock()
		if reject {
			return nil, errors.New("rejected")
		}
		return checker.Authenticate(c, k)
	}}
	cfg.AddHostKey(hs)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	d.addr = l.Addr().(*net.TCPAddr)
	go func() {
		for {
			nc, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer nc.Close()
				_, chans, reqs, err := ssh.NewServerConn(nc, cfg)
				if err != nil {
					return
				}
				go ssh.DiscardRequests(reqs)
				for nch := range chans {
					ch, creqs, err := nch.Accept()
					if err != nil {
						return
					}
					for r := range creqs {
						if r.Type != "exec" {
							_ = r.Reply(false, nil)
							continue
						}
						_ = r.Reply(true, nil)
						var cmd struct{ Command string }
						_ = ssh.Unmarshal(r.Payload, &cmd)
						_, _ = ch.Write([]byte("ok:" + cmd.Command + "\n"))
						_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
						ch.Close()
						break
					}
				}
			}()
		}
	}()
	return d
}

// TestDirectRealSSH — настоящий ssh этой системы с нашими опциями: вход по сертификату через агент trassa, ключ
// хоста из ответа панели; при отказе сервера предлагаются только временный ключ и сертификат, не ключи из ~/.ssh.
func TestDirectRealSSH(t *testing.T) {
	sshPath, err := exec.LookPath("ssh")
	if err != nil {
		t.Skip("нет ssh")
	}
	_, capriv, _ := ed25519.GenerateKey(rand.Reader)
	ca, _ := ssh.NewSignerFromKey(capriv)
	for _, reject := range []bool{false, true} {
		d := startSSHD(t, ca.PublicKey(), reject)
		p := newPanel(t)
		p.servers = []myServer{{ServerID: srvA, Name: "local", Logins: []login{{UnixUser: "ops", Ready: true}}}}
		var subject ssh.PublicKey
		p.cert = func(line string) certReply {
			subject, _, _, _, _ = ssh.ParseAuthorizedKey([]byte(line))
			c := &ssh.Certificate{Key: subject, CertType: ssh.UserCert, KeyId: "trassa:w:m:1", ValidPrincipals: []string{"ops"},
				ValidAfter: uint64(time.Now().Add(-30 * time.Second).Unix()), ValidBefore: uint64(time.Now().Add(10 * time.Minute).Unix()),
				Permissions: ssh.Permissions{Extensions: map[string]string{"permit-pty": ""}}}
			if err := c.SignCert(rand.Reader, ca); err != nil {
				t.Error(err)
			}
			host := "127.0.0.1"
			return certReply{Certificate: string(ssh.MarshalAuthorizedKey(c)), UnixUser: "ops", Host: &host, Port: d.addr.Port,
				HostKeys: []string{strings.TrimSpace(string(ssh.MarshalAuthorizedKey(d.hostKey)))}}
		}
		a, _, _, _ := newApp(t, p)
		loggedIn(t, a, p, tokA)
		a.LookPath = func(string) (string, error) { return sshPath, nil }
		var out, errb bytes.Buffer
		a.RunSSH = func(ctx context.Context, path string, args, env []string) (int, error) {
			cmd := exec.CommandContext(ctx, path, append([]string{"-o", "BatchMode=yes", "-o", "ConnectTimeout=10"}, args...)...)
			cmd.Env, cmd.Stdout, cmd.Stderr = env, &out, &errb
			err := cmd.Run()
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				return ee.ExitCode(), nil
			}
			return 0, err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		code, err := a.SSH(ctx, SSHOptions{Server: "local", Direct: true, Remote: []string{"uptime"}}, nil)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		if !reject {
			if code != 0 || out.String() != "ok:uptime\n" {
				t.Fatalf("вход по сертификату: код %d, вывод %q, ssh: %s", code, out.String(), errb.String())
			}
			continue
		}
		if code == 0 {
			t.Fatal("вход при отказе сервера")
		}
		d.mu.Lock()
		offered := d.offered
		d.mu.Unlock()
		if len(offered) == 0 {
			t.Fatalf("ключи не предлагались: %s", errb.String())
		}
		want := string(ssh.MarshalAuthorizedKey(subject))
		for _, k := range offered {
			if strings.HasPrefix(k, ssh.CertAlgoED25519v01) {
				continue // сертификат на временный ключ
			}
			if !strings.HasSuffix(k, want) {
				t.Fatalf("ssh предложил чужой ключ: %s (порт %s)", k, strconv.Itoa(d.addr.Port))
			}
		}
	}
}
