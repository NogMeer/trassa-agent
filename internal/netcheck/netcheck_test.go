// SPDX-License-Identifier: AGPL-3.0-only

package netcheck

import (
	"context"
	"net"
	"os"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
)

func TestRun(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := uint32(l.Addr().(*net.TCPAddr).Port)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	if r := Run(context.Background(), &agentv1.NetCheckParams{Host: "127.0.0.1", Port: port, TimeoutMs: 1000}); !r.GetReachable() || r.GetError() != "" {
		t.Fatalf("успех: %+v", r)
	}
	l.Close()
	if r := Run(context.Background(), &agentv1.NetCheckParams{Host: "127.0.0.1", Port: port, TimeoutMs: 1000}); r.GetReachable() || r.GetError() != ErrRefused {
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
