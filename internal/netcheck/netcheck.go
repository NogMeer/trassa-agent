// SPDX-License-Identifier: AGPL-3.0-only

// Package netcheck — net.check (E07, раздел 6): одно TCP-соединение без передачи данных, исполняет агент без
// прав. Цель вычисляет панель; здесь — только схема и само соединение.
package netcheck

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"regexp"
	"syscall"
	"time"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
)

// Пределы.
const (
	MaxHost        = 253
	MaxTimeout     = 5000 * time.Millisecond
	DefaultTimeout = 3000 * time.Millisecond
)

// Причины недоступности (NetCheckResult.error).
const (
	ErrTimeout     = "TIMEOUT"
	ErrRefused     = "REFUSED"
	ErrUnresolved  = "UNRESOLVED"
	ErrUnreachable = "UNREACHABLE"
	ErrOther       = "ERROR"
	// ErrForbidden — цель (или одно из её разрешённых имён) — loopback, link-local (в том числе метаданные облака
	// 169.254.169.254), unspecified или multicast. Частные диапазоны разрешены: на них держится PRIVATE_NET.
	ErrForbidden = "FORBIDDEN_TARGET"
)

// Forbidden — адрес, к которому проверка связи не подключается.
func Forbidden(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || a.IsInterfaceLocalMulticast() ||
		a.IsMulticast() || a.IsUnspecified()
}

// resolve — адреса цели: IP как есть, имя — через резолвер. Запрещён хотя бы один адрес — отказ целиком: имя,
// которое разрешается и в чужой, и в запрещённый адрес, не проверяется.
func resolve(ctx context.Context, host string) ([]netip.Addr, string) {
	if a, err := netip.ParseAddr(host); err == nil {
		if Forbidden(a) {
			return nil, ErrForbidden
		}
		return []netip.Addr{a.Unmap()}, ""
	}
	addrs, err := lookup(ctx, host)
	if err != nil {
		return nil, reason(err)
	}
	if len(addrs) == 0 {
		return nil, ErrUnresolved
	}
	for i, a := range addrs {
		if Forbidden(a) {
			return nil, ErrForbidden
		}
		addrs[i] = a.Unmap()
	}
	return addrs, ""
}

// lookup — резолвер (переменная: тест подменяет его, чтобы проверить ответ DNS с запрещённым адресом).
var lookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// Имя хоста по RFC 1123: метки из букв, цифр и дефиса, не с дефиса и не на дефис, до 63 символов.
var hostRe = regexp.MustCompile(`^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.?$`)

// Validate — схема параметров. Лишние поля (неизвестные номера) — отказ: подписанное тело не должно нести то,
// чего агент не понимает.
func Validate(p *agentv1.NetCheckParams) error {
	if len(p.ProtoReflect().GetUnknown()) > 0 {
		return errors.New("лишние поля в параметрах")
	}
	h := p.GetHost()
	if h == "" || len(h) > MaxHost {
		return errors.New("host: от 1 до 253 символов")
	}
	if _, err := netip.ParseAddr(h); err != nil && !hostRe.MatchString(h) {
		return errors.New("host: IP-адрес или имя")
	}
	if p.GetPort() < 1 || p.GetPort() > 65535 {
		return errors.New("port: от 1 до 65535")
	}
	if time.Duration(p.GetTimeoutMs())*time.Millisecond > MaxTimeout {
		return errors.New("timeout_ms: до 5000")
	}
	return nil
}

// Run — соединение и сразу закрытие. Данные не передаются.
func Run(ctx context.Context, p *agentv1.NetCheckParams) *agentv1.NetCheckResult {
	timeout := time.Duration(p.GetTimeoutMs()) * time.Millisecond
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	start := time.Now()
	addrs, why := resolve(ctx, p.GetHost())
	if why != "" {
		return &agentv1.NetCheckResult{LatencyMs: uint32(time.Since(start) / time.Millisecond), Error: why}
	}
	// Соединение — с уже проверенным адресом, а не с именем: повторного разрешения (подмены DNS) нет.
	var d net.Dialer
	var err error
	for _, a := range addrs {
		var conn net.Conn
		conn, err = d.DialContext(ctx, "tcp", netip.AddrPortFrom(a, uint16(p.GetPort())).String())
		if err == nil {
			_ = conn.Close()
			return &agentv1.NetCheckResult{Reachable: true, LatencyMs: uint32(time.Since(start) / time.Millisecond)}
		}
		if ctx.Err() != nil {
			break
		}
	}
	return &agentv1.NetCheckResult{LatencyMs: uint32(time.Since(start) / time.Millisecond), Error: reason(err)}
}

func reason(err error) string {
	var dns *net.DNSError
	switch {
	case errors.As(err, &dns) && !dns.IsTimeout:
		return ErrUnresolved
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, syscall.ETIMEDOUT):
		return ErrTimeout
	case errors.Is(err, syscall.ECONNREFUSED):
		return ErrRefused
	case errors.Is(err, syscall.ENETUNREACH), errors.Is(err, syscall.EHOSTUNREACH):
		return ErrUnreachable
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return ErrTimeout
	}
	return ErrOther
}
