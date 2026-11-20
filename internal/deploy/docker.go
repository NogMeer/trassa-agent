// SPDX-License-Identifier: AGPL-3.0-only

package deploy

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/dockerapi"
	"github.com/NogMeer/trassa-agent/internal/fsutil"
)

// DockerKeyFingerprint — ключ репозитория Docker (decisions E17, 4.1): первичный ключ v4.
const DockerKeyFingerprint = "9DC858229FC7DD38854AE2D88D81803C0EBFCD88"

// supportedDocker — версии docker-ce, которые ставит docker.ensure (пакеты есть для всех четырёх ОС).
var supportedDocker = map[string]bool{"29.9.3": true}

// MinDocker — ниже 28.0.0 порты на 127.0.0.1 видны соседям по сети хостера (decisions E17, развилка 2).
const MinDocker = "28.0.0"

// Ошибки docker.ensure.
var (
	ErrDockerTooOld   = errors.New("DOCKER_TOO_OLD")
	ErrDockerKey      = errors.New("DOCKER_KEY_MISMATCH")
	ErrOSUnsupported  = errors.New("DEPLOY_OS_UNSUPPORTED")
	ErrDockerNotReady = errors.New("DOCKER_UNAVAILABLE")
)

// Пути docker.ensure.
const (
	aptKeyFile    = "/etc/apt/keyrings/docker.asc"
	aptSources    = "/etc/apt/sources.list.d/docker.sources"
	daemonJSON    = "/etc/docker/daemon.json"
	cliPluginsDir = "/usr/local/lib/docker/cli-plugins"
)

// Env — зависимости деплоя в помощнике под корнем Root ("/" на сервере).
type Env struct {
	Root     string
	Docker   *dockerapi.Client
	Run      func(ctx context.Context, name string, args ...string) ([]byte, error)
	Stage    func(op string) string // каталог, куда агент скачал программы операции
	StateDir string                 // /var/lib/trassa/deploy
}

func (e *Env) path(p string) string { return filepath.Join(e.Root, p) }

// osRelease — дистрибутив и выпуск из /etc/os-release: ubuntu 22.04/24.04, debian 12/13.
func (e *Env) osRelease() (distro, version, codename string, err error) {
	raw, err := os.ReadFile(e.path("/etc/os-release"))
	if err != nil {
		return "", "", "", err
	}
	kv := map[string]string{}
	for _, l := range strings.Split(string(raw), "\n") {
		if k, v, ok := strings.Cut(l, "="); ok {
			kv[k] = strings.Trim(v, `"`)
		}
	}
	distro, version, codename = kv["ID"], kv["VERSION_ID"], kv["VERSION_CODENAME"]
	ok := map[string]string{"ubuntu/22.04": "jammy", "ubuntu/24.04": "noble", "debian/12": "bookworm", "debian/13": "trixie"}
	if want, found := ok[distro+"/"+version]; !found || want != codename {
		return "", "", "", fmt.Errorf("%w: %s %s %s", ErrOSUnsupported, distro, version, codename)
	}
	return distro, version, codename, nil
}

// aptVersion — версия пакета docker-ce в репозитории Docker: 5:29.9.3-1~ubuntu.24.04~noble.
func aptVersion(v, distro, version, codename string) string {
	return fmt.Sprintf("5:%s-1~%s.%s~%s", v, distro, version, codename)
}

// keyFingerprint — отпечаток v4 первичного ключа из armored-блока OpenPGP (SHA-1 от 0x99 ‖ длина ‖ тело
// пакета открытого ключа, RFC 4880 §12.2).
func keyFingerprint(armored []byte) (string, error) {
	s := string(armored)
	start := strings.Index(s, "-----BEGIN PGP PUBLIC KEY BLOCK-----")
	end := strings.Index(s, "-----END PGP PUBLIC KEY BLOCK-----")
	if start < 0 || end < start {
		return "", errors.New("не armored-ключ OpenPGP")
	}
	var b64 strings.Builder
	body := strings.SplitN(s[start:end], "\n\n", 2)
	if len(body) != 2 {
		return "", errors.New("armored: нет тела")
	}
	for _, l := range strings.Split(body[1], "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "=") {
			continue // строка CRC
		}
		b64.WriteString(l)
	}
	raw, err := base64.StdEncoding.DecodeString(b64.String())
	if err != nil || len(raw) < 3 {
		return "", errors.New("armored: base64")
	}
	tag, hdr, n := raw[0], 0, 0
	switch {
	case tag&0x80 == 0:
		return "", errors.New("пакет OpenPGP")
	case tag&0x40 != 0: // новый формат
		if (tag & 0x3f) != 6 {
			return "", errors.New("первый пакет не открытый ключ")
		}
		switch l := int(raw[1]); {
		case l < 192:
			hdr, n = 2, l
		case l < 224 && len(raw) > 2:
			hdr, n = 3, ((l-192)<<8)+int(raw[2])+192
		case l == 255 && len(raw) > 5:
			hdr, n = 6, int(raw[2])<<24|int(raw[3])<<16|int(raw[4])<<8|int(raw[5])
		default:
			return "", errors.New("длина пакета")
		}
	default: // старый формат
		if (tag>>2)&0x0f != 6 {
			return "", errors.New("первый пакет не открытый ключ")
		}
		switch tag & 3 {
		case 0:
			hdr, n = 2, int(raw[1])
		case 1:
			hdr, n = 3, int(raw[1])<<8|int(raw[2])
		case 2:
			if len(raw) < 5 {
				return "", errors.New("длина пакета")
			}
			hdr, n = 5, int(raw[1])<<24|int(raw[2])<<16|int(raw[3])<<8|int(raw[4])
		default:
			return "", errors.New("длина пакета")
		}
	}
	if hdr+n > len(raw) || n < 1 || raw[hdr] != 4 {
		return "", errors.New("ключ не v4")
	}
	h := sha1.New()
	h.Write([]byte{0x99, byte(n >> 8), byte(n)})
	h.Write(raw[hdr : hdr+n])
	return strings.ToUpper(hex.EncodeToString(h.Sum(nil))), nil
}

// dockerVersion — версия и API демона (GET /version).
func (e *Env) dockerVersion(ctx context.Context) (string, string, error) {
	if e.Docker == nil {
		return "", "", dockerapi.ErrNoDocker
	}
	resp, err := e.Docker.Get(ctx, "/version")
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("%w: GET /version: HTTP %d", ErrDockerNotReady, resp.StatusCode)
	}
	var v struct {
		Version    string `json:"Version"`
		APIVersion string `json:"ApiVersion"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&v); err != nil {
		return "", "", err
	}
	return v.Version, v.APIVersion, nil
}

// cmpVersion — сравнение «a.b.c» по числам (хвосты вроде -rc отбрасываются).
func cmpVersion(a, b string) int {
	pa, pb := strings.Split(strings.SplitN(a, "-", 2)[0], "."), strings.Split(strings.SplitN(b, "-", 2)[0], ".")
	for i := 0; i < 3; i++ {
		var x, y int
		if i < len(pa) {
			x, _ = strconv.Atoi(pa[i])
		}
		if i < len(pb) {
			y, _ = strconv.Atoi(pb[i])
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

// EnsureDocker — docker.ensure: Docker не ниже MinDocker; нет — docker-ce из репозитория Docker (ключ сверен
// по отпечатку, daemon.json — до установки), плагины compose и buildx — бинарниками из таблицы помощника, git.
// Чужой Docker не переустанавливается.
func (e *Env) EnsureDocker(ctx context.Context, op string, p *agentv1.DockerEnsureParams) (*agentv1.DockerEnsureResult, error) {
	res := &agentv1.DockerEnsureResult{}
	ver, api, err := e.dockerVersion(ctx)
	switch {
	case err == nil:
		if cmpVersion(ver, MinDocker) < 0 {
			return nil, fmt.Errorf("%w: Docker %s, нужен не ниже %s (пакет docker.io заменить на docker-ce)", ErrDockerTooOld, ver, MinDocker)
		}
	case errors.Is(err, dockerapi.ErrNoDocker):
		if err := e.installDocker(ctx, p); err != nil {
			return nil, err
		}
		res.Installed, res.DaemonJsonWritten = true, true
		if ver, api, err = e.dockerVersion(ctx); err != nil {
			return nil, fmt.Errorf("%w: после установки: %v", ErrDockerNotReady, err)
		}
	default:
		return nil, fmt.Errorf("%w: %v", ErrDockerNotReady, err)
	}
	res.DockerVersion, res.ApiVersion = ver, api
	for _, t := range p.GetPlugins() {
		bin, err := installPlugin(ctx, e.Stage(op), t, e.path(cliPluginsDir))
		if err != nil {
			return nil, err
		}
		_ = bin
	}
	if out, err := e.Run(ctx, "docker", "compose", "version", "--short"); err == nil {
		res.ComposeVersion = strings.TrimPrefix(strings.TrimSpace(string(out)), "v")
	} else {
		return nil, fmt.Errorf("docker compose: %v", err)
	}
	if out, err := e.Run(ctx, "docker", "buildx", "version"); err == nil {
		if f := strings.Fields(string(out)); len(f) >= 2 {
			res.BuildxVersion = strings.TrimPrefix(f[1], "v")
		}
	} else {
		return nil, fmt.Errorf("docker buildx: %v", err)
	}
	if out, err := e.Run(ctx, "git", "--version"); err == nil {
		if f := strings.Fields(string(out)); len(f) >= 3 {
			res.GitVersion = f[2]
		}
	} else if _, err := e.Run(ctx, "apt-get", "install", "-y", "-q", "--no-install-recommends", "git"); err != nil {
		return nil, fmt.Errorf("git: %v", err)
	}
	return res, nil
}

func (e *Env) installDocker(ctx context.Context, p *agentv1.DockerEnsureParams) error {
	distro, version, codename, err := e.osRelease()
	if err != nil {
		return err
	}
	fp, err := keyFingerprint(p.GetAptKey())
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDockerKey, err)
	}
	if fp != DockerKeyFingerprint {
		return fmt.Errorf("%w: отпечаток %s", ErrDockerKey, fp)
	}
	if err := e.write(aptKeyFile, p.GetAptKey(), 0o644); err != nil {
		return err
	}
	src := fmt.Sprintf("Types: deb\nURIs: https://download.docker.com/linux/%s\nSuites: %s\nComponents: stable\nSigned-By: %s\n", distro, codename, aptKeyFile)
	if err := e.write(aptSources, []byte(src), 0o644); err != nil {
		return err
	}
	// daemon.json до установки: журналы local с ротацией и live-restore (контейнеры переживают перезапуск dockerd).
	if _, err := os.Stat(e.path(daemonJSON)); errors.Is(err, os.ErrNotExist) {
		dj, _ := json.MarshalIndent(map[string]any{"log-driver": "local", "log-opts": map[string]string{
			"max-size": p.GetLogMaxSize(), "max-file": strconv.Itoa(int(p.GetLogMaxFiles()))}, "live-restore": true}, "", "  ")
		if err := e.write(daemonJSON, dj, 0o644); err != nil {
			return err
		}
	}
	if out, err := e.Run(ctx, "apt-get", "update", "-q"); err != nil {
		return fmt.Errorf("apt-get update: %v %s", err, firstLine(out))
	}
	v := aptVersion(p.GetDockerVersion(), distro, version, codename)
	if out, err := e.Run(ctx, "apt-get", "install", "-y", "-q", "--no-install-recommends",
		"docker-ce="+v, "docker-ce-cli="+v, "containerd.io", "git"); err != nil {
		return fmt.Errorf("apt-get install docker-ce: %v %s", err, firstLine(out))
	}
	return nil
}

func (e *Env) write(p string, data []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(e.path(p)), 0o755); err != nil {
		return err
	}
	if err := os.Chmod(filepath.Dir(e.path(p)), 0o755); err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(e.path(p), data, perm, fsutil.Keep)
}

func firstLine(b []byte) string {
	if i := bytes.IndexByte(b, '\n'); i >= 0 {
		b = b[:i]
	}
	if len(b) > 200 {
		b = b[:200]
	}
	return string(b)
}
