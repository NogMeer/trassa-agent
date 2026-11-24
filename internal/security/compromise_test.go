// SPDX-License-Identifier: AGPL-3.0-only

package security

import "testing"

func TestCompromiseInstant(t *testing.T) {
	sys := build(t, tree{
		"proc/10/exe": "->/usr/sbin/sshd", "proc/10/comm": "sshd\n",
		"proc/20/exe": "->/tmp/.x/kworker", "proc/20/comm": "kworker\n",
		"proc/30/exe": "->/usr/bin/python3.12 (deleted)", "proc/30/comm": "python3\n",
		"proc/2/comm":       "kthreadd\n",
		"etc/ld.so.preload": "# comment\n/usr/lib/libhide.so\n",
		// 10.0.0.5:51000 → 203.0.113.9:3333 (ESTABLISHED) и обычное к 443.
		"proc/net/tcp": "  sl  local_address rem_address   st\n" +
			"   0: 0500000A:C738 097100CB:0D05 01 00000000:00000000 00:00000000 00000000 0 0 1 1\n" +
			"   1: 0500000A:C739 097100CB:01BB 01 00000000:00000000 00:00000000 00000000 0 0 2 1\n",
	})
	r := scan(t, sys, "COMPROMISE_TMP_EXEC", "COMPROMISE_LD_PRELOAD", "COMPROMISE_OUTBOUND")
	if got := states(r["COMPROMISE_TMP_EXEC"]); got != "FAIL:/tmp/.x/kworker,FAIL:/usr/bin/python3.12" {
		t.Errorf("%s", got)
	}
	if got := states(r["COMPROMISE_LD_PRELOAD"]); got != "FAIL:/etc/ld.so.preload" {
		t.Errorf("%s", got)
	}
	if got := states(r["COMPROMISE_OUTBOUND"]); got != "FAIL:203.0.113.9:3333 (пул майнинга)" {
		t.Errorf("%s", got)
	}
	clean := build(t, tree{"proc/1/exe": "->/usr/lib/systemd/systemd", "etc/ld.so.preload": "\n", "proc/net/tcp": "  sl\n"})
	r = scan(t, clean, "COMPROMISE_TMP_EXEC", "COMPROMISE_LD_PRELOAD", "COMPROMISE_OUTBOUND")
	for code, rs := range r {
		if states(rs) != "PASS:" {
			t.Errorf("%s на чистой системе: %s", code, states(rs))
		}
	}
}

// Прод, MeerGuard: входящие подключения клиентов VPN с исходным портом 3333/5555/6667 считались «связью с пулом».
// Соединение, чей локальный порт прослушивается (на том же адресе или на 0.0.0.0 и ::), — входящее.
func TestOutboundSkipsIncoming(t *testing.T) {
	const hdr = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	const zero6 = "00000000000000000000000000000000"
	const a6 = "B80D0120000000000000000001000000" // 2001:db8::1
	const b6 = "B80D0120000000000000000002000000" // 2001:db8::2
	sys := build(t, tree{
		"proc/net/tcp": hdr +
			// LISTEN 0.0.0.0:443 и 10.0.0.5:1194.
			"   0: 00000000:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 100 1\n" +
			"   1: 0500000A:04AA 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 101 1\n" +
			// Входящие: клиент 91.78.1.2:5555 → :443, 178.177.0.9:3333 → 10.0.0.5:1194.
			"   2: 0500000A:01BB 02014E5B:15B3 01 00000000:00000000 00:00000000 00000000 0 0 102 1\n" +
			"   3: 0500000A:04AA 0900B1B2:0D05 01 00000000:00000000 00:00000000 00000000 0 0 103 1\n" +
			// Входящее на :8443, слушаемый только в tcp6 на :: (двойной стек), с удалённым 6667.
			"   4: 0500000A:20FB 0900B1B2:1A0B 01 00000000:00000000 00:00000000 00000000 0 0 104 1\n" +
			// Настоящее исходящее: эфемерный 51000 → 203.0.113.9:3333.
			"   5: 0500000A:C738 097100CB:0D05 01 00000000:00000000 00:00000000 00000000 0 0 4242 1\n",
		"proc/net/tcp6": hdr +
			"   0: " + zero6 + ":20FB " + zero6 + ":0000 0A 00000000:00000000 00:00000000 00000000 0 0 200 1\n" +
			"   1: " + zero6 + ":01BB " + zero6 + ":0000 0A 00000000:00000000 00:00000000 00000000 0 0 201 1\n" +
			// IPv6 входящее: [2001:db8::2]:6667 → [2001:db8::1]:443.
			"   2: " + a6 + ":01BB " + b6 + ":1A0B 01 00000000:00000000 00:00000000 00000000 0 0 202 1\n" +
			// IPv6 исходящее: эфемерный 40000 → [2001:db8::2]:6667.
			"   3: " + a6 + ":9C40 " + b6 + ":1A0B 01 00000000:00000000 00:00000000 00000000 0 0 4243 1\n",
		"proc/77/comm": "xmrig\n", "proc/77/fd/3": "->socket:[4242]",
		"proc/88/comm": "irc\n", "proc/88/fd/5": "->socket:[4243]", "proc/88/fd/6": "->/dev/null",
	})
	conns, err := outbound(sys)
	if err != nil {
		t.Fatal(err)
	}
	if len(conns) != 2 {
		t.Fatalf("%+v", conns)
	}
	if conns[0].Subject != "203.0.113.9:3333 (пул майнинга)" || conns[0].Process != "xmrig, pid 77" ||
		conns[1].Subject != "[2001:db8::2]:6667 (IRC)" || conns[1].Process != "irc, pid 88" {
		t.Fatalf("%+v", conns)
	}
	r := scan(t, sys, "COMPROMISE_OUTBOUND")
	if got := r["COMPROMISE_OUTBOUND"]; len(got) != 2 || got[0].Evidence != "исходящее соединение на 203.0.113.9:3333 (пул майнинга) — процесс xmrig, pid 77" {
		t.Fatalf("%+v", got)
	}
}
