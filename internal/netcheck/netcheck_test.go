// SPDX-License-Identifier: AGPL-3.0-only

package netcheck

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
)

// hostIP — адрес интерфейса машины, не loopback (loopback проверка связи не трогает).
func hostIP(t *testing.T) netip.Addr {
	t.Helper()
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if p, err := netip.ParsePrefix(a.String()); err == nil && p.Addr().Is4() && !Forbidden(p.Addr()) {
			return p.Addr()
		}
	}
	t.Skip("нет адреса IPv4 кроме loopback")
	return netip.Addr{}
}

func listen(t *testing.T, ip netip.Addr) (net.Listener, uint32) {
	t.Helper()
	l, err := net.Listen("tcp", netip.AddrPortFrom(ip, 0).String())
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	return l, uint32(l.Addr().(*net.TCPAddr).Port)
}

func TestRun(t *testing.T) {
	ip := hostIP(t)
	l, port := listen(t, ip)
	if r := Run(context.Background(), &agentv1.NetCheckParams{Host: ip.String(), Port: port, TimeoutMs: 1000}); !r.GetReachable() || r.GetError() != "" {
		t.Fatalf("успех: %+v", r)
	}
	l.Close()
	if r := Run(context.Background(), &agentv1.NetCheckParams{Host: ip.String(), Port: port, TimeoutMs: 1000}); r.GetReachable() || r.GetError() != ErrRefused {
		t.Fatalf("отказ: %+v", r)
	}
	// 192.0.2.0/24 (TEST-NET-1) не маршрутизируется: тайм-аут или «недоступна сеть», если маршрута нет совсем.
	r := Run(context.Background(), &agentv1.NetCheckParams{Host: "192.0.2.1", Port: 9, TimeoutMs: 200})
	if r.GetReachable() && os.Getenv("CI") == "true" {
		t.Fatalf("тайм-аут в CI: %+v", r)
	} else if r.GetReachable() {
		t.Log("сеть этой машины принимает соединения на TEST-NET (прозрачный прокси или VPN): тайм-аут проверяется в CI")
	} else if r.GetError() != ErrTimeout && r.GetError() != ErrUnreachable {
		t.Fatalf("тайм-аут: %+v", r)
	}
	if r := Run(context.Background(), &agentv1.NetCheckParams{Host: "nonexistent.invalid", Port: 80, TimeoutMs: 2000}); r.GetError() != ErrUnresolved && r.GetError() != ErrTimeout {
		t.Fatalf("имя: %+v", r)
	}
}

// Запрещённые диапазоны — FORBIDDEN_TARGET без соединения; частные — разрешены.
func TestForbiddenTargets(t *testing.T) {
	forbidden := []string{
		"127.0.0.1", "127.255.0.9", "::1", // loopback
		"169.254.169.254", "169.254.1.1", "fe80::1", // link-local, метаданные облака
		"0.0.0.0", "::", // unspecified
		"224.0.0.1", "239.255.255.250", "ff02::1", "ff05::2", // multicast
		"::ffff:127.0.0.1", "::ffff:169.254.169.254", // IPv4 внутри IPv6
	}
	for _, h := range forbidden {
		if r := Run(context.Background(), &agentv1.NetCheckParams{Host: h, Port: 22, TimeoutMs: 500}); r.GetReachable() || r.GetError() != ErrForbidden {
			t.Errorf("%s: %+v", h, r)
		}
	}
	for _, h := range []string{"10.1.2.3", "172.16.0.1", "172.31.255.254", "192.168.1.1", "fd00::1", "fc00::1", "100.64.0.1", "8.8.8.8"} {
		if Forbidden(netip.MustParseAddr(h)) {
			t.Errorf("%s запрещён, а не должен", h)
		}
	}
}

// Имя разрешается — каждый адрес проверяется; соединение идёт к проверенному адресу, без второго разрешения.
func TestResolveAndPin(t *testing.T) {
	ip := hostIP(t)
	l, port := listen(t, ip)
	defer l.Close()
	old := lookup
	t.Cleanup(func() { lookup = old })
	calls := 0
	lookup = func(_ context.Context, host string) ([]netip.Addr, error) {
		calls++
		switch host {
		case "svc.example":
			return []netip.Addr{ip}, nil
		case "rebind.example":
			return []netip.Addr{netip.MustParseAddr("203.0.113.5"), netip.MustParseAddr("169.254.169.254")}, nil
		case "mapped.example":
			return []netip.Addr{netip.MustParseAddr("::ffff:127.0.0.1")}, nil
		}
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	// svc.example системный резолвер не знает: успех значит, что соединение шло к адресу из проверки.
	if r := Run(context.Background(), &agentv1.NetCheckParams{Host: "svc.example", Port: port, TimeoutMs: 1000}); !r.GetReachable() || calls != 1 {
		t.Fatalf("закреплённый адрес: %+v, разрешений %d", r, calls)
	}
	for _, h := range []string{"rebind.example", "mapped.example"} {
		if r := Run(context.Background(), &agentv1.NetCheckParams{Host: h, Port: port, TimeoutMs: 500}); r.GetError() != ErrForbidden {
			t.Errorf("%s: %+v", h, r)
		}
	}
	if r := Run(context.Background(), &agentv1.NetCheckParams{Host: "missing.example", Port: port, TimeoutMs: 500}); r.GetError() != ErrUnresolved {
		t.Errorf("нет имени: %+v", r)
	}
	lookup = func(context.Context, string) ([]netip.Addr, error) {
		return nil, errors.New("сбой резолвера")
	}
	if r := Run(context.Background(), &agentv1.NetCheckParams{Host: "svc.example", Port: port, TimeoutMs: 500}); r.GetError() != ErrOther {
		t.Errorf("сбой резолвера: %+v", r)
	}
}

func TestValidate(t *testing.T) {
	ok := []*agentv1.NetCheckParams{
		{Host: "10.0.0.5", Port: 5432}, {Host: "db.internal", Port: 1, TimeoutMs: 5000}, {Host: "2001:db8::1", Port: 65535},
	}
	for _, p := range ok {
		if err := Validate(p); err != nil {
			t.Errorf("%v: %v", p, err)
		}
	}
	long := ""
	for len(long) < 254 {
		long += "a."
	}
	bad := []*agentv1.NetCheckParams{
		{Port: 80}, {Host: "a b", Port: 80}, {Host: "-x.com", Port: 80}, {Host: "x.com", Port: 0}, {Host: "x.com", Port: 70000},
		{Host: "x.com", Port: 80, TimeoutMs: 5001}, {Host: long, Port: 80}, {Host: "x.com:22", Port: 80}, {Host: "http://x", Port: 80},
	}
	for _, p := range bad {
		if Validate(p) == nil {
			t.Errorf("принято: %v", p)
		}
	}
	// Лишнее поле (номер 9, которого нет в схеме) — отказ.
	raw, _ := proto.Marshal(&agentv1.NetCheckParams{Host: "x.com", Port: 80})
	raw = protowire.AppendTag(raw, 9, protowire.VarintType)
	raw = protowire.AppendVarint(raw, 1)
	var p agentv1.NetCheckParams
	if err := proto.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	if Validate(&p) == nil {
		t.Fatal("лишнее поле принято")
	}
}
