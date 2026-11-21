// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// unixUserRe — логин на сервере (apps/api access.dto.ts, UNIX_USER).
var unixUserRe = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

// safePathRe — путь, который ssh_config не раскроет по-своему (%-токены, ~, ${} и пробелы-разделители).
var safePathRe = regexp.MustCompile(`^[A-Za-z0-9/._-]+$`)

// certReply — POST /access/certificates (AccessCertificateDto).
type certReply struct {
	Certificate   string    `json:"certificate"`
	KeyID         string    `json:"keyId"`
	ValidBefore   time.Time `json:"validBefore"`
	UnixUser      string    `json:"unixUser"`
	CaFingerprint string    `json:"caFingerprint"`
	HostKeys      []string  `json:"hostKeys"`
	Host          *string   `json:"host"`
	Port          int       `json:"port"`
}

// directTarget — проверенный ответ: куда и с чем идёт ssh.
type directTarget struct {
	cert     *ssh.Certificate
	host     string
	port     int
	user     string
	hostKeys []ssh.PublicKey
}

// checkCert — ответ панели перед запуском ssh: сертификат на наш ключ, тип user, ещё действует; адрес — IP, порт и
// логин — допустимые; ключи хоста разбираются и это не сертификаты. Без ключей хоста вход не выполняется: иначе ssh
// спросил бы человека «доверять ли» ключу, который никто не проверял.
func checkCert(r *certReply, pub ssh.PublicKey, now time.Time) (*directTarget, error) {
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(r.Certificate))
	if err != nil {
		return nil, fmt.Errorf("%w: сертификат: %v", errBadResponse, err)
	}
	cert, ok := pk.(*ssh.Certificate)
	if !ok || cert.CertType != ssh.UserCert || !bytes.Equal(cert.Key.Marshal(), pub.Marshal()) || len(cert.ValidPrincipals) == 0 {
		return nil, errCertMismatch
	}
	if cert.ValidBefore != ssh.CertTimeInfinity && !now.Before(time.Unix(int64(cert.ValidBefore), 0)) {
		return nil, fmt.Errorf("%w: сертификат уже истёк", errBadResponse)
	}
	if !unixUserRe.MatchString(r.UnixUser) {
		return nil, fmt.Errorf("%w: логин", errBadResponse)
	}
	if r.Port < 1 || r.Port > 65535 {
		return nil, fmt.Errorf("%w: порт", errBadResponse)
	}
	if r.Host == nil || *r.Host == "" {
		return nil, errNoAddress
	}
	ip := net.ParseIP(*r.Host)
	if ip == nil {
		return nil, fmt.Errorf("%w: адрес %q", errBadResponse, clean(*r.Host))
	}
	t := &directTarget{cert: cert, host: ip.String(), port: r.Port, user: r.UnixUser}
	for _, line := range r.HostKeys {
		k, _, _, rest, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil || len(bytes.TrimSpace(rest)) != 0 {
			return nil, fmt.Errorf("%w: ключ хоста", errBadResponse)
		}
		if _, isCert := k.(*ssh.Certificate); isCert {
			return nil, fmt.Errorf("%w: ключ хоста", errBadResponse)
		}
		t.hostKeys = append(t.hostKeys, k)
	}
	if len(t.hostKeys) == 0 {
		return nil, errNoHostKeys
	}
	return t, nil
}

var (
	errCertMismatch = errors.New("certificate mismatch")
	errNoAddress    = errors.New("no address")
	errNoHostKeys   = errors.New("no host keys")
)

// knownHosts — строки known_hosts: для порта 22 — адрес, иначе [адрес]:порт (ssh(1), VERIFYING HOST KEYS).
func knownHosts(t *directTarget) []byte {
	pattern := t.host
	if t.port != 22 {
		pattern = "[" + t.host + "]:" + strconv.Itoa(t.port)
	}
	var b bytes.Buffer
	for _, k := range t.hostKeys {
		b.WriteString(pattern + " " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k))) + "\n")
	}
	return b.Bytes()
}

// Файлы во временном каталоге --direct: ключ хоста, открытый ключ и сертификат (закрытый ключ — только в агенте).
const (
	knownHostsName = "known_hosts"
	pubName        = "id.pub"
	certName       = "id-cert.pub"
)

// sshArgs — системный ssh без файлов настроек (-F none: ни ~/.ssh/config, ни /etc/ssh/ssh_config не подменят
// проверку ключа хоста, ControlMaster или KnownHostsCommand). Ключ — только временный: IdentitiesOnly с открытым
// ключом из dir выбирает его в нашем агенте, личные ключи из ~/.ssh серверу не предлагаются (иначе подменённый
// адрес узнал бы их, а отказ в сертификате кончился бы входом личным ключом мимо выдачи). Ключ хоста — только из
// ответа панели; пароль и проброс выключены.
func sshArgs(t *directTarget, dir string, remote []string) []string {
	args := []string{
		"-F", "none",
		"-o", "IdentityAgent=SSH_AUTH_SOCK",
		"-o", "IdentitiesOnly=yes",
		"-o", "IdentityFile=" + filepath.Join(dir, pubName),
		"-o", "CertificateFile=" + filepath.Join(dir, certName),
		"-o", "UserKnownHostsFile=" + filepath.Join(dir, knownHostsName),
		"-o", "GlobalKnownHostsFile=/dev/null",
		"-o", "StrictHostKeyChecking=yes",
		"-o", "UpdateHostKeys=no",
		"-o", "CheckHostIP=no",
		"-o", "VerifyHostKeyDNS=no",
		"-o", "PreferredAuthentications=publickey",
		"-o", "PasswordAuthentication=no",
		"-o", "KbdInteractiveAuthentication=no",
		"-o", "ForwardAgent=no",
		"-o", "ForwardX11=no",
		"-o", "ClearAllForwardings=yes",
		"-o", "ControlMaster=no",
		"-o", "ControlPath=none",
		"-o", "PermitLocalCommand=no",
		"-p", strconv.Itoa(t.port),
		"-l", t.user,
		"--", t.host,
	}
	return append(args, remote...)
}

// readOnlyAgent — агент ssh только с нашим ключом и сертификатом: добавить, убрать или запереть ключ через сокет
// нельзя.
type readOnlyAgent struct{ agent.Agent }

var errReadOnly = errors.New("agent is read-only")

func (readOnlyAgent) Add(agent.AddedKey) error   { return errReadOnly }
func (readOnlyAgent) Remove(ssh.PublicKey) error { return errReadOnly }
func (readOnlyAgent) RemoveAll() error           { return errReadOnly }
func (readOnlyAgent) Lock([]byte) error          { return errReadOnly }
func (readOnlyAgent) Unlock([]byte) error        { return errReadOnly }

// serveAgent — сокет агента в каталоге 0700; закрывается с ctx.
func serveAgent(ctx context.Context, path string, ag agent.Agent) (func(), error) {
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		l.Close()
		return nil, err
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer conn.Close()
				_ = agent.ServeAgent(ag, conn)
			}()
		}
	}()
	stop := context.AfterFunc(ctx, func() { l.Close() })
	return func() {
		stop()
		l.Close()
		wg.Wait()
	}, nil
}

// Direct — trassa ssh --direct: временная пара Ed25519 в памяти, сертификат на 10 минут, системный ssh напрямую.
func (a *App) Direct(ctx context.Context, c *client, ws string, srv myServer, unixUser string, remote []string) (int, error) {
	if a.GOOS == "windows" {
		return 1, userError{a.t("err.direct_windows")}
	}
	sshPath, err := a.LookPath("ssh")
	if err != nil {
		return 1, userError{a.t("err.no_ssh")}
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return 1, err
	}
	defer clear(priv)
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return 1, err
	}
	body := map[string]string{
		"serverId":  srv.ServerID,
		"unixUser":  unixUser,
		"publicKey": strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))),
	}
	var r certReply
	if err := c.do(ctx, http.MethodPost, wsPath(ws, "certificates"), body, &r); err != nil {
		return 1, err
	}
	t, err := checkCert(&r, sshPub, a.now())
	switch {
	case errors.Is(err, errNoAddress):
		return 1, userError{a.t("err.no_address")}
	case errors.Is(err, errNoHostKeys):
		return 1, userError{a.t("err.no_host_keys")}
	case errors.Is(err, errCertMismatch):
		return 1, userError{a.t("err.cert_bad")}
	case err != nil:
		return 1, err
	}

	dir, err := os.MkdirTemp("", "trassa-ssh-")
	if err != nil {
		return 1, err
	}
	defer os.RemoveAll(dir)
	if !safePathRe.MatchString(dir) {
		return 1, userError{a.t("err.tmp_path", dir)}
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return 1, err
	}
	for name, data := range map[string][]byte{
		knownHostsName: knownHosts(t),
		pubName:        ssh.MarshalAuthorizedKey(sshPub),
		certName:       ssh.MarshalAuthorizedKey(t.cert),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			return 1, err
		}
	}
	kr := agent.NewKeyring()
	life := uint32(max(time.Until(time.Unix(int64(t.cert.ValidBefore), 0)).Seconds(), 1))
	// Ключ и сертификат: ssh подписывает либо ключом сертификата, либо самим ключом (по версии OpenSSH).
	for _, k := range []agent.AddedKey{
		{PrivateKey: priv, Certificate: t.cert, LifetimeSecs: life, Comment: "trassa " + r.KeyID},
		{PrivateKey: priv, LifetimeSecs: life, Comment: "trassa " + r.KeyID},
	} {
		if err := kr.Add(k); err != nil {
			return 1, err
		}
	}
	defer kr.RemoveAll()
	actx, cancel := context.WithCancel(ctx)
	defer cancel()
	sock := filepath.Join(dir, "agent.sock")
	stop, err := serveAgent(actx, sock, readOnlyAgent{kr})
	if err != nil {
		return 1, err
	}
	defer stop()

	fmt.Fprint(a.Stderr, a.t("ssh.direct", clean(srv.Name), time.Unix(int64(t.cert.ValidBefore), 0).Local().Format("15:04"), t.user, t.host))
	env := withEnv(os.Environ(), "SSH_AUTH_SOCK", sock)
	return a.RunSSH(ctx, sshPath, sshArgs(t, dir, remote), env)
}

// withEnv — окружение с заменой переменной.
func withEnv(env []string, k, v string) []string {
	out := make([]string, 0, len(env)+1)
	for _, e := range env {
		if !strings.HasPrefix(e, k+"=") {
			out = append(out, e)
		}
	}
	return append(out, k+"="+v)
}

// RunSSH — запуск ssh с терминалом человека; код выхода ssh — код выхода trassa.
func RunSSH(ctx context.Context, path string, args, env []string) (int, error) {
	cmd := exec.Command(path, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Env = env
	err := cmd.Run()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), nil
	}
	if err != nil {
		return 1, err
	}
	return 0, nil
}
