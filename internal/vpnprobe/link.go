// SPDX-License-Identifier: AGPL-3.0-only

package vpnprobe

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// Link — тестовый доступ, разобранный из ссылки. Поддержаны (решения E25-agent, по #716 и SIP002):
//   - vless://uuid@host:port?type=…&security=tls|reality&…
//   - trojan://password@host:port?… (те же параметры);
//   - ss://base64url(method:password)@host:port или ss://method:password@… (SIP002, без plugin).
//
// Транспорты: raw (tcp), ws, grpc, httpupgrade, xhttp. VMess, kcp, hysteria и плагины SIP003 отклоняются.
type Link struct {
	Protocol string // vless, trojan, shadowsocks
	Host     string // имя или IP входа из ссылки
	Port     int

	ID, Flow, Encryption string // vless
	Password             string // trojan, shadowsocks
	Method               string // shadowsocks

	Network                string // raw, ws, grpc, httpupgrade, xhttp
	Security               string // none, tls, reality
	SNI                    string
	ALPN                   []string
	FP                     string
	PBK, SID, SPX          string // reality
	Path, HostHeader       string
	ServiceName, Authority string
	GRPCMulti              bool
	Mode                   string // xhttp
}

var (
	uuidRe   = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	pbkRe    = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	sidRe    = regexp.MustCompile(`^[0-9a-fA-F]{0,16}$`)
	fpRe     = regexp.MustCompile(`^[a-z0-9_]{1,32}$`)
	alpnRe   = regexp.MustCompile(`^[a-z0-9./-]{1,32}$`)
	flowRe   = regexp.MustCompile(`^(|xtls-rprx-vision|xtls-rprx-vision-udp443)$`)
	pathRe   = regexp.MustCompile(`^/[\x21-\x7e]{0,255}$`)
	svcRe    = regexp.MustCompile(`^[A-Za-z0-9._/-]{0,128}$`)
	ssMethod = map[string]bool{
		"aes-128-gcm": true, "aes-256-gcm": true, "chacha20-poly1305": true, "chacha20-ietf-poly1305": true,
		"xchacha20-poly1305": true, "xchacha20-ietf-poly1305": true, "2022-blake3-aes-128-gcm": true,
		"2022-blake3-aes-256-gcm": true, "2022-blake3-chacha20-poly1305": true,
	}
	xhttpModes = map[string]bool{"": true, "auto": true, "packet-up": true, "stream-up": true, "stream-one": true}
	networks   = map[string]string{"": "raw", "tcp": "raw", "raw": "raw", "ws": "ws", "grpc": "grpc",
		"httpupgrade": "httpupgrade", "xhttp": "xhttp", "splithttp": "xhttp"}
)

// invalid — отказ разбора. Значения из ссылки в текст не попадают: он уходит в итог операции, а в ссылке секреты.
func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrConfigInvalid}, a...)...)
}

// ParseLink — ссылка доступа. Неизвестная схема, параметр с недопустимым значением или лишняя строка — отказ:
// значения уходят в конфигурацию движка, поэтому каждое проверяется по своему формату.
func ParseLink(text string) (*Link, error) {
	s := strings.TrimSpace(text)
	if s == "" || len(s) > MaxConfigBytes || strings.ContainsAny(s, "\r\n\t ") {
		return nil, invalid("ждали одну ссылку vless://, trojan:// или ss://")
	}
	u, err := url.Parse(s)
	if err != nil || u.Opaque != "" || u.Host == "" {
		return nil, invalid("ссылка не разбирается")
	}
	l := &Link{}
	host, portS := u.Hostname(), u.Port()
	port, err := strconv.Atoi(portS)
	if err != nil || port < 1 || port > 65535 {
		return nil, invalid("порт")
	}
	if net.ParseIP(host) == nil && !hostRe.MatchString(host) {
		return nil, invalid("адрес входа")
	}
	l.Host, l.Port = strings.ToLower(host), port
	q := u.Query()
	switch strings.ToLower(u.Scheme) {
	case "vless":
		l.Protocol = "vless"
		if u.User == nil || !uuidRe.MatchString(u.User.Username()) {
			return nil, invalid("vless: id")
		}
		if _, hasPw := u.User.Password(); hasPw {
			return nil, invalid("vless: id")
		}
		l.ID = strings.ToLower(u.User.Username())
		l.Encryption = q.Get("encryption")
		if l.Encryption == "" {
			l.Encryption = "none"
		}
		if l.Encryption != "none" {
			return nil, invalid("vless: encryption не поддерживается")
		}
		l.Flow = q.Get("flow")
		if !flowRe.MatchString(l.Flow) {
			return nil, invalid("vless: flow")
		}
		if err := l.stream(q); err != nil {
			return nil, err
		}
	case "trojan":
		l.Protocol = "trojan"
		if u.User == nil {
			return nil, invalid("trojan: пароль")
		}
		l.Password = u.User.Username()
		if _, hasPw := u.User.Password(); hasPw || l.Password == "" || len(l.Password) > 256 || !printable(l.Password) {
			return nil, invalid("trojan: пароль")
		}
		if q.Get("flow") != "" {
			return nil, invalid("trojan: flow")
		}
		if q.Get("security") == "" {
			q.Set("security", "tls") // trojan без TLS не бывает
		}
		if err := l.stream(q); err != nil {
			return nil, err
		}
	case "ss":
		l.Protocol = "shadowsocks"
		if err := l.shadowsocks(u); err != nil {
			return nil, err
		}
		if len(q) != 0 {
			return nil, invalid("ss: параметры (plugin) не поддерживаются")
		}
		l.Network, l.Security = "raw", "none"
	default:
		return nil, invalid("схема ссылки не поддерживается")
	}
	return l, nil
}

func (l *Link) shadowsocks(u *url.URL) error {
	if u.User == nil {
		return invalid("ss: метод и пароль")
	}
	var method, pw string
	if p, ok := u.User.Password(); ok {
		method, pw = u.User.Username(), p
	} else {
		raw := u.User.Username()
		dec, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(raw, "="))
		if err != nil {
			dec, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(raw, "="))
		}
		if err != nil {
			return invalid("ss: userinfo не base64")
		}
		m, p, ok := strings.Cut(string(dec), ":")
		if !ok {
			return invalid("ss: метод и пароль")
		}
		method, pw = m, p
		if strings.HasPrefix(method, "2022-") {
			return invalid("ss: для 2022-blake3 userinfo не кодируется base64 (SIP002)")
		}
	}
	if !ssMethod[method] {
		return invalid("ss: метод не поддерживается")
	}
	if pw == "" || len(pw) > 256 || !printable(pw) {
		return invalid("ss: пароль")
	}
	l.Method, l.Password = method, pw
	return nil
}

// stream — параметры транспорта и защиты (#716).
func (l *Link) stream(q url.Values) error {
	n, ok := networks[q.Get("type")]
	if !ok {
		return invalid("type не поддерживается")
	}
	l.Network = n
	l.Security = q.Get("security")
	switch l.Security {
	case "tls", "reality":
	case "", "none":
		// Xray сам не пустит vless и trojan без защиты на публичный адрес; точка замера не ослабляет это.
		return invalid("security: нужен tls или reality")
	default:
		return invalid("security не поддерживается")
	}
	l.SNI = q.Get("sni")
	if l.SNI != "" && !hostRe.MatchString(l.SNI) {
		return invalid("sni")
	}
	if l.SNI == "" && net.ParseIP(l.Host) == nil {
		l.SNI = l.Host
	}
	l.FP = q.Get("fp")
	if l.FP == "" {
		l.FP = "chrome"
	}
	if !fpRe.MatchString(l.FP) || l.FP == "unsafe" || l.FP == "hellogolang" {
		return invalid("fp")
	}
	if a := q.Get("alpn"); a != "" {
		for _, p := range strings.Split(a, ",") {
			if !alpnRe.MatchString(p) {
				return invalid("alpn")
			}
			l.ALPN = append(l.ALPN, p)
		}
	}
	if l.Security == "reality" {
		l.PBK, l.SID, l.SPX = q.Get("pbk"), q.Get("sid"), q.Get("spx")
		if !pbkRe.MatchString(l.PBK) || !sidRe.MatchString(l.SID) || l.SNI == "" {
			return invalid("reality: pbk, sid или sni")
		}
		if l.SPX == "" {
			l.SPX = "/"
		}
		if !pathRe.MatchString(l.SPX) {
			return invalid("reality: spx")
		}
	}
	switch l.Network {
	case "ws", "httpupgrade", "xhttp":
		l.Path = q.Get("path")
		if l.Path == "" {
			l.Path = "/"
		}
		if !pathRe.MatchString(l.Path) {
			return invalid("path")
		}
		l.HostHeader = q.Get("host")
		if l.HostHeader != "" && !hostRe.MatchString(l.HostHeader) {
			return invalid("host")
		}
		if l.Network == "xhttp" {
			l.Mode = q.Get("mode")
			if !xhttpModes[l.Mode] {
				return invalid("mode")
			}
			if q.Get("extra") != "" {
				return invalid("xhttp: extra не поддерживается")
			}
		}
	case "grpc":
		l.ServiceName, l.Authority = q.Get("serviceName"), q.Get("authority")
		if !svcRe.MatchString(l.ServiceName) || (l.Authority != "" && !hostRe.MatchString(l.Authority)) {
			return invalid("grpc: serviceName или authority")
		}
		switch q.Get("mode") {
		case "", "gun":
		case "multi":
			l.GRPCMulti = true
		default:
			return invalid("grpc: mode")
		}
	}
	return nil
}

func printable(s string) bool {
	for _, r := range s {
		if r < 0x21 || r == 0x7f {
			return false
		}
	}
	return true
}
