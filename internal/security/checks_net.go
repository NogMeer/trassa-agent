// SPDX-License-Identifier: AGPL-3.0-only

package security

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"time"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/metrics"
)

func init() {
	register(Check{Code: "OPEN_PORTS", Run: checkOpenPorts})
	register(Check{Code: "DB_PORT_PUBLIC", Run: checkDBPorts})
	register(Check{Code: "DOCKER_API_EXPOSED", Run: checkDockerAPI})
	register(Check{Code: "DOCKER_PRIVILEGED", Run: checkDockerPrivileged})
	register(Check{Code: "CERT_EXPIRING", Run: func(ctx context.Context, s *Scan) []Finding { return checkCerts(ctx, s, false) }})
	register(Check{Code: "CERT_EXPIRED", Run: func(ctx context.Context, s *Scan) []Finding { return checkCerts(ctx, s, true) }})
}

func diskMounts(sys *System) ([]string, error) {
	c := &metrics.Collector{Proc: sys.path("/proc")}
	if sys.Root == "/" {
		c.IsDir = metrics.New().IsDir
	}
	return c.Mounts()
}

func listenersOr(ctx context.Context, s *Scan) ([]*agentv1.Listener, []Finding) {
	l, err := s.Listeners(ctx)
	if err != nil {
		return nil, []Finding{failed(ErrReadFailed, err)}
	}
	return l, nil
}

func portSubject(l *agentv1.Listener) string {
	return l.GetProtocol() + "/" + strconv.Itoa(int(l.GetPort()))
}

// OPEN_PORTS — порт слушает адрес, который может быть виден снаружи. Доступен ли он снаружи на самом деле и
// ожидаемый ли он, решает панель (внешняя проверка T19 и отметки «Так и нужно»).
func checkOpenPorts(ctx context.Context, s *Scan) []Finding {
	ls, f := listenersOr(ctx, s)
	if f != nil {
		return f
	}
	seen := map[string]bool{}
	var out []Finding
	for _, l := range ls {
		sub := portSubject(l)
		if !l.GetPublic() || seen[sub] {
			continue
		}
		seen[sub] = true
		out = append(out, fail(sub, describe(l)))
	}
	return out
}

func describe(l *agentv1.Listener) string {
	ev := fmt.Sprintf("%s слушает %s", portSubject(l), net.JoinHostPort(l.GetAddress(), strconv.Itoa(int(l.GetPort()))))
	if l.GetProcess() != "" {
		ev += ", процесс " + l.GetProcess()
	}
	if l.GetContainer() != "" {
		ev += ", контейнер " + l.GetContainer()
	}
	return ev
}

// Порты и процессы баз данных и кэшей.
var (
	dbPorts = map[uint32]string{
		5432: "PostgreSQL", 3306: "MySQL/MariaDB", 6379: "Redis", 27017: "MongoDB", 9200: "Elasticsearch",
		11211: "Memcached", 5984: "CouchDB", 9042: "Cassandra", 8086: "InfluxDB", 26257: "CockroachDB",
	}
	dbProcs = map[string]string{
		"postgres": "PostgreSQL", "mysqld": "MySQL", "mariadbd": "MariaDB", "redis-server": "Redis", "mongod": "MongoDB",
		"memcached": "Memcached", "clickhouse-serv": "ClickHouse",
	}
)

func checkDBPorts(ctx context.Context, s *Scan) []Finding {
	ls, f := listenersOr(ctx, s)
	if f != nil {
		return f
	}
	var out []Finding
	seen := map[string]bool{}
	for _, l := range ls {
		what, ok := dbProcs[l.GetProcess()]
		if !ok {
			what, ok = dbPorts[l.GetPort()]
		}
		if !ok || !l.GetPublic() || seen[portSubject(l)] {
			continue
		}
		seen[portSubject(l)] = true
		out = append(out, fail(portSubject(l), what+": "+describe(l)))
	}
	return out
}

func checkDockerAPI(ctx context.Context, s *Scan) []Finding {
	ls, f := listenersOr(ctx, s)
	if f != nil {
		return f
	}
	var out []Finding
	for _, l := range ls {
		if l.GetProtocol() == "tcp" && l.GetProcess() == "dockerd" && l.GetContainer() == "" && !isLoopback(l.GetAddress()) {
			out = append(out, fail(portSubject(l), "управление Docker доступно по сети: "+describe(l)))
		}
	}
	return out
}

func isLoopback(a string) bool {
	ip, err := netip.ParseAddr(a)
	return err == nil && ip.IsLoopback()
}

func checkDockerPrivileged(ctx context.Context, s *Scan) []Finding {
	cs, err := s.Containers(ctx)
	if err != nil {
		return []Finding{failed(ErrReadFailed, err)}
	}
	if cs == nil {
		return []Finding{na("Docker не установлен или контейнеров нет")}
	}
	var out []Finding
	for _, c := range cs {
		switch {
		case c.privileged:
			out = append(out, fail(c.name, "контейнер "+c.name+" запущен с полными правами (privileged)"))
		case c.dockerSock:
			out = append(out, fail(c.name, "контейнеру "+c.name+" доступен сокет Docker"))
		}
	}
	return out
}

// Пределы проверки сертификатов: столько портов и столько времени на каждый.
const (
	maxCertPorts    = 20
	certDialTimeout = 3 * time.Second
	certWarnDays    = 14
)

// checkCerts — сертификат, который отдаёт TLS-порт сервера по локальному адресу (без SNI — сертификат по
// умолчанию). Цепочка не проверяется: нужна только дата окончания.
func checkCerts(ctx context.Context, s *Scan, expired bool) []Finding {
	ls, f := listenersOr(ctx, s)
	if f != nil {
		return f
	}
	now := s.sys.Now()
	var out []Finding
	n := 0
	seen := map[uint32]bool{}
	for _, l := range ls {
		if l.GetProtocol() != "tcp" || !l.GetPublic() || seen[l.GetPort()] || n >= maxCertPorts {
			continue
		}
		seen[l.GetPort()] = true
		n++
		host := "127.0.0.1"
		if a, err := netip.ParseAddr(l.GetAddress()); err == nil && !a.IsUnspecified() {
			host = a.String()
		} else if err == nil && a.Is6() {
			host = "::1"
		}
		d := &net.Dialer{Timeout: certDialTimeout}
		dctx, cancel := context.WithTimeout(ctx, certDialTimeout)
		conn, err := (&tls.Dialer{NetDialer: d, Config: &tls.Config{InsecureSkipVerify: true}}).DialContext(dctx, "tcp", net.JoinHostPort(host, strconv.Itoa(int(l.GetPort()))))
		cancel()
		if err != nil {
			continue // не TLS
		}
		st := conn.(*tls.Conn).ConnectionState()
		conn.Close()
		if len(st.PeerCertificates) == 0 {
			continue
		}
		c := st.PeerCertificates[0]
		sub := portSubject(l)
		left := c.NotAfter.Sub(now)
		name := c.Subject.CommonName
		if len(c.DNSNames) > 0 {
			name = c.DNSNames[0]
		}
		ev := fmt.Sprintf("%s: сертификат %s действует до %s", sub, name, c.NotAfter.UTC().Format("2006-01-02"))
		switch {
		case expired && left <= 0:
			out = append(out, fail(sub, ev))
		case !expired && left > 0 && left < certWarnDays*24*time.Hour:
			out = append(out, fail(sub, ev+fmt.Sprintf(" (осталось %d дн.)", int(left.Hours()/24))))
		case left > 0 || expired:
			out = append(out, pass(sub, ev))
		}
	}
	return out
}
