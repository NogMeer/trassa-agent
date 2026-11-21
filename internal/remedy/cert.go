// SPDX-License-Identifier: AGPL-3.0-only

package remedy

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/fsutil"
)

// Каталоги certbot (решение E18 п. 5).
const (
	leDir      = "/etc/letsencrypt"
	leLive     = leDir + "/live"
	leRenewal  = leDir + "/renewal"
	maxCertPEM = 64 << 10
)

// certNameRe — имя сертификата certbot: имя хоста, к нему certbot дописывает -0001 и т. п.
var certNameRe = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)

// ValidateCertRenew — cert.renew.
func ValidateCertRenew(p *agentv1.CertRenewParams) error {
	if d := p.GetDomain(); len(d) > 253 || !certNameRe.MatchString(d) {
		return fmt.Errorf("domain %q: имя сертификата certbot", d)
	}
	return nil
}

// certFiles — ссылки live/<имя>/* certbot.
var certFiles = []string{"cert.pem", "chain.pem", "fullchain.pem", "privkey.pem"}

// notAfter — срок и издатель сертификата live/<имя>/cert.pem. Ссылка обязана вести в archive/<имя>/: иначе
// чтение от root по подставленной ссылке.
func (e *Env) notAfter(name string) (time.Time, string, error) {
	link := e.path(filepath.Join(leLive, name, "cert.pem"))
	target, err := os.Readlink(link)
	if err != nil {
		return time.Time{}, "", fmt.Errorf("%w: %s", ErrCertNotFound, name)
	}
	if err := archiveTarget(name, "cert.pem", target); err != nil {
		return time.Time{}, "", err
	}
	f, err := fsutil.OpenNoFollow(e.path(filepath.Join(leDir, "archive", name, filepath.Base(target))), os.O_RDONLY)
	if err != nil {
		return time.Time{}, "", fmt.Errorf("%w: %v", ErrCertNotFound, err)
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxCertPEM))
	if err != nil {
		return time.Time{}, "", err
	}
	b, _ := pem.Decode(raw)
	if b == nil || b.Type != "CERTIFICATE" {
		return time.Time{}, "", fmt.Errorf("%w: %s не PEM", ErrCertNotFound, name)
	}
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return time.Time{}, "", fmt.Errorf("%w: %v", ErrCertNotFound, err)
	}
	return c.NotAfter, c.Issuer.CommonName, nil
}

// archiveTarget — цель ссылки live/<имя>/<файл>: ../../archive/<имя>/<файл без .pem>N.pem.
func archiveTarget(name, file, target string) error {
	base := strings.TrimSuffix(file, ".pem")
	re := regexp.MustCompile(`^\.\./\.\./archive/` + regexp.QuoteMeta(name) + `/` + base + `[0-9]{1,6}\.pem$`)
	if !re.MatchString(target) {
		return fmt.Errorf("%w: %s/%s ведёт не в archive certbot (%q)", ErrCertUnsupport, name, file, target)
	}
	return nil
}

func (e *Env) proxyManaged(name string) bool {
	if e.ProxyHosts == nil {
		return false
	}
	for _, h := range e.ProxyHosts() {
		if h == name || (strings.HasPrefix(h, "*.") && strings.HasSuffix(name, h[1:])) {
			return true
		}
	}
	return false
}

// CertLineage — проверки до точки отката: сертификат certbot (renewal/<имя>.conf — обычный файл), не прокси
// Trassa. Возвращает файл настроек и команды восстановления прежних ссылок live/<имя>/* (для отката CONFIG).
func (e *Env) CertLineage(name string) (string, [][]string, error) {
	if e.proxyManaged(name) {
		return "", nil, fmt.Errorf("%w: %s выпускает Caddy Trassa", ErrCertProxy, name)
	}
	if st, err := os.Lstat(e.path(leDir)); err != nil || !st.IsDir() {
		return "", nil, fmt.Errorf("%w: certbot на сервере нет", ErrCertUnsupport)
	}
	conf := e.path(filepath.Join(leRenewal, name+".conf"))
	st, err := os.Lstat(conf)
	if errors.Is(err, os.ErrNotExist) {
		if _, lerr := os.Lstat(e.path(filepath.Join(leLive, name))); lerr == nil {
			return "", nil, fmt.Errorf("%w: %s без настроек продления certbot", ErrCertUnsupport, name)
		}
		return "", nil, fmt.Errorf("%w: %s", ErrCertNotFound, name)
	}
	if err != nil || !st.Mode().IsRegular() {
		return "", nil, fmt.Errorf("%w: %s.conf не обычный файл", ErrCertUnsupport, name)
	}
	var cmds [][]string
	for _, f := range certFiles {
		link := filepath.Join(leLive, name, f)
		target, err := os.Readlink(e.path(link))
		if err != nil {
			return "", nil, fmt.Errorf("%w: %s: %v", ErrCertUnsupport, link, err)
		}
		if err := archiveTarget(name, f, target); err != nil {
			return "", nil, err
		}
		cmds = append(cmds, []string{"/bin/ln", "-sfn", target, link})
	}
	return conf, cmds, nil
}

// RenewCert — cert.renew: certbot renew только этого сертификата, без --force-renewal и своих хуков; успех —
// срок стал позже. certbot возвращает 0 и когда продлевать рано — это CERT_NOT_DUE.
func (e *Env) RenewCert(ctx context.Context, name string) (*agentv1.CertRenewResult, error) {
	before, _, err := e.notAfter(name)
	if err != nil {
		return nil, err
	}
	res := &agentv1.CertRenewResult{NotAfterBeforeMs: before.UnixMilli()}
	if out, err := e.Run(ctx, "certbot", "renew", "--cert-name", name, "--non-interactive"); err != nil {
		return res, fmt.Errorf("%w: %v %s", ErrCertFailed, err, tail(out))
	}
	after, issuer, err := e.notAfter(name)
	if err != nil {
		return res, err
	}
	res.NotAfterMs, res.Issuer = after.UnixMilli(), issuer
	if !after.After(before) {
		return res, fmt.Errorf("%w: certbot не продлил %s (срок до %s)", ErrCertNotDue, name, before.UTC().Format(time.DateOnly))
	}
	return res, nil
}

// Certs — сертификаты certbot: имя → срок (для события cert.expiring); сертификаты прокси Trassa пропускаются.
func (e *Env) Certs() map[string]time.Time {
	out := map[string]time.Time{}
	ents, err := os.ReadDir(e.path(leLive))
	if err != nil {
		return out
	}
	for _, d := range ents {
		if !d.IsDir() || !certNameRe.MatchString(d.Name()) || e.proxyManaged(d.Name()) {
			continue
		}
		if t, _, err := e.notAfter(d.Name()); err == nil {
			out[d.Name()] = t
		}
	}
	return out
}
