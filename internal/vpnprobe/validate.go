// SPDX-License-Identifier: AGPL-3.0-only

// Package vpnprobe — точка замера VPN-пакета (E25, раздел 6): установка движка (vpn.probe.ensure) и замер цепочки
// по тестовому доступу (vpn.probe.run). Движок — клиентское ядро из зашитой таблицы (internal/tools), запускается
// помощником от пользователя trassa в песочнице systemd: слушает только 127.0.0.1, исходящие — только на адрес
// входа цепочки из allowed_endpoints. Конфигурацию движка строит помощник сам из ссылки доступа: произвольный
// JSON движка не принимается (иначе в нём были бы свои выходы, DNS и маршруты — агент стал бы сканером).
package vpnprobe

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/config"
)

// Коды отказа (e25-agent-scope.md).
var (
	ErrEngineUnknown      = errors.New("VPN_PROBE_ENGINE_UNKNOWN")
	ErrEngineMissing      = errors.New("VPN_PROBE_ENGINE_MISSING")
	ErrConfigInvalid      = errors.New("VPN_PROBE_CONFIG_INVALID")
	ErrEndpointForbid     = errors.New("VPN_PROBE_ENDPOINT_FORBIDDEN")
	ErrTimeout            = errors.New("VPN_CHECK_TIMEOUT")
	ErrBusy               = errors.New("VPN_PROBE_BUSY")
	ErrSHA256             = errors.New("SHA256_MISMATCH")
	ErrEngineFailed       = errors.New("VPN_PROBE_ENGINE_FAILED")
	ErrSandboxUnavailable = errors.New("VPN_PROBE_SANDBOX_UNAVAILABLE")
)

// Codes — все коды пакета для итога операции.
var Codes = []error{ErrEngineUnknown, ErrEngineMissing, ErrConfigInvalid, ErrEndpointForbid, ErrTimeout, ErrBusy,
	ErrSHA256, ErrEngineFailed, ErrSandboxUnavailable}

// Пределы (e25-agent-scope.md, п. 6).
const (
	MinHold        = 30
	MaxHold        = 300
	MaxTimeout     = 600
	MinHops        = 2
	MaxHops        = 12
	MaxEndpoints   = 100
	MaxParallel    = 4
	MaxConfigBytes = 16 << 10
	EngineXray     = "xray"
)

var (
	semverRe = regexp.MustCompile(`^\d{1,4}\.\d{1,4}\.\d{1,4}$`)
	sha256Re = regexp.MustCompile(`^[0-9a-f]{64}$`)
	hostRe   = regexp.MustCompile(`^(?i:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?i:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))+$`)
	noteRe   = regexp.MustCompile(`^[A-Z_]{1,40}$`)
	engines  = map[string]bool{EngineXray: true}
)

// ValidateEnsure — vpn.probe.ensure: движок из таблицы помощника, версия, sha256 и https-источник.
func ValidateEnsure(p *agentv1.VpnProbeEnsureParams) error {
	if !engines[p.GetEngine()] {
		return fmt.Errorf("%w: движок %q", ErrEngineUnknown, p.GetEngine())
	}
	if !semverRe.MatchString(p.GetVersion()) {
		return errors.New("version: ждали x.y.z")
	}
	if !sha256Re.MatchString(p.GetSha256()) {
		return errors.New("sha256: 64 знака hex")
	}
	u, err := url.Parse(p.GetUrl())
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || len(p.GetUrl()) > 2048 {
		return errors.New("url: ждали https без учётных данных")
	}
	return nil
}

// ValidateRun — vpn.probe.run: пределы времени, звеньев и адресов; dry_run не бывает (замер — не изменение).
func ValidateRun(b *agentv1.OperationBody) error {
	if b.GetDryRun() {
		return errors.New("dry_run: замер без предпросмотра")
	}
	p := b.GetParams().GetVpnProbeRun()
	if !config.IsUUID(p.GetCheckId()) || !config.IsUUID(p.GetRouteId()) {
		return errors.New("check_id, route_id: ждали uuid")
	}
	if !engines[p.GetEngine()] {
		return fmt.Errorf("%w: движок %q", ErrEngineUnknown, p.GetEngine())
	}
	if p.GetHoldSeconds() < MinHold || p.GetHoldSeconds() > MaxHold {
		return fmt.Errorf("hold_seconds: %d–%d", MinHold, MaxHold)
	}
	if p.GetTimeoutSeconds() > MaxTimeout || p.GetTimeoutSeconds() <= p.GetHoldSeconds() {
		return fmt.Errorf("timeout_seconds: больше hold_seconds и не больше %d", MaxTimeout)
	}
	if p.GetHopCount() < MinHops || p.GetHopCount() > MaxHops {
		return fmt.Errorf("hop_count: %d–%d", MinHops, MaxHops)
	}
	if _, _, err := TargetURL(p.GetTargetUrl()); err != nil {
		return err
	}
	if p.GetConfig().GetKid() == "" || len(p.GetConfig().GetEncCt()) == 0 {
		return errors.New("config: нет тестового доступа")
	}
	if len(p.GetConfig().GetEncCt()) > MaxConfigBytes+1024 {
		return errors.New("config: больше 16 КБ")
	}
	if _, err := Endpoints(p.GetAllowedEndpoints()); err != nil {
		return err
	}
	return nil
}

// TargetURL — адрес запроса через цепочку: http или https, имя хоста (не IP-литерал), порт 80 или 443, без
// учётных данных. Хост уходит в туннель именем и разрешается на выходе цепочки, не на точке замера.
func TargetURL(raw string) (*url.URL, string, error) {
	u, err := url.Parse(raw)
	if err != nil || len(raw) > 2048 || u.User != nil || u.Opaque != "" || u.Fragment != "" {
		return nil, "", errors.New("target_url: ждали http(s)://имя/путь")
	}
	port := u.Port()
	switch u.Scheme {
	case "https":
		if port == "" {
			port = "443"
		}
	case "http":
		if port == "" {
			port = "80"
		}
	default:
		return nil, "", errors.New("target_url: только http и https")
	}
	if port != "80" && port != "443" {
		return nil, "", errors.New("target_url: порт 80 или 443")
	}
	h := u.Hostname()
	if net.ParseIP(h) != nil || !hostRe.MatchString(h) || len(h) > 253 {
		return nil, "", errors.New("target_url: имя хоста, не адрес")
	}
	return u, net.JoinHostPort(strings.ToLower(h), port), nil
}

// Endpoints — разрешённые адреса: 1–100 IP-литералов, без служебных (петля, частные, link-local, multicast,
// неуказанный). Вход цепочки — публичный сервер; локальный адрес здесь — попытка ходить по своей сети.
func Endpoints(list []string) (map[string]net.IP, error) {
	if len(list) == 0 || len(list) > MaxEndpoints {
		return nil, fmt.Errorf("allowed_endpoints: 1–%d адресов", MaxEndpoints)
	}
	out := make(map[string]net.IP, len(list))
	for _, s := range list {
		ip := net.ParseIP(s)
		if ip == nil {
			return nil, fmt.Errorf("allowed_endpoints: %q — не IP", s)
		}
		if !public(ip) {
			return nil, fmt.Errorf("%w: %s — не публичный адрес", ErrEndpointForbid, s)
		}
		out[ip.String()] = ip
	}
	return out, nil
}

func public(ip net.IP) bool {
	return !(ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() || ip.IsInterfaceLocalMulticast()) && !cgnat.Contains(ip)
}

// cgnat — 100.64.0.0/10 (RFC 6598): адреса оператора, не публичные.
var cgnat = &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}

// ValidNote — код заметки звена.
func ValidNote(s string) bool { return s == "" || noteRe.MatchString(s) }
