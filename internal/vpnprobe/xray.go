// SPDX-License-Identifier: AGPL-3.0-only

package vpnprobe

import (
	"encoding/json"
	"net"
)

// XrayConfig — конфигурация клиента Xray (поля по исходникам v26.10.31, решения E25-agent): вход socks только на
// 127.0.0.1 без UDP, один выход на закреплённый IP входа цепочки. Секций routing, dns, api, metrics нет: весь
// трафик идёт в единственный выход, других выходов и слушателей нет, имя target_url разрешается на выходе цепочки.
func XrayConfig(l *Link, entry net.IP, socksPort int) ([]byte, error) {
	out := map[string]any{"protocol": l.Protocol, "tag": "chain"}
	addr := entry.String()
	switch l.Protocol {
	case "vless":
		user := map[string]any{"id": l.ID, "encryption": l.Encryption}
		if l.Flow != "" {
			user["flow"] = l.Flow
		}
		out["settings"] = map[string]any{"vnext": []any{map[string]any{"address": addr, "port": l.Port, "users": []any{user}}}}
	case "trojan":
		out["settings"] = map[string]any{"servers": []any{map[string]any{"address": addr, "port": l.Port, "password": l.Password}}}
	case "shadowsocks":
		out["settings"] = map[string]any{"servers": []any{map[string]any{"address": addr, "port": l.Port,
			"method": l.Method, "password": l.Password}}}
	default:
		return nil, invalid("протокол %q", l.Protocol)
	}
	ss := map[string]any{"network": l.Network, "security": l.Security}
	switch l.Security {
	case "tls":
		t := map[string]any{"fingerprint": l.FP}
		if l.SNI != "" {
			t["serverName"] = l.SNI
		}
		if len(l.ALPN) > 0 {
			t["alpn"] = l.ALPN
		}
		ss["tlsSettings"] = t
	case "reality":
		ss["realitySettings"] = map[string]any{"serverName": l.SNI, "fingerprint": l.FP, "password": l.PBK,
			"shortId": l.SID, "spiderX": l.SPX}
	}
	pathHost := func() map[string]any {
		m := map[string]any{"path": l.Path}
		if l.HostHeader != "" {
			m["host"] = l.HostHeader
		}
		return m
	}
	switch l.Network {
	case "ws":
		ss["wsSettings"] = pathHost()
	case "httpupgrade":
		ss["httpupgradeSettings"] = pathHost()
	case "xhttp":
		m := pathHost()
		if l.Mode != "" {
			m["mode"] = l.Mode
		}
		ss["xhttpSettings"] = m
	case "grpc":
		g := map[string]any{"serviceName": l.ServiceName, "multiMode": l.GRPCMulti}
		if l.Authority != "" {
			g["authority"] = l.Authority
		}
		ss["grpcSettings"] = g
	}
	out["streamSettings"] = ss
	cfg := map[string]any{
		"log": map[string]any{"loglevel": "error"},
		"inbounds": []any{map[string]any{
			"listen": "127.0.0.1", "port": socksPort, "protocol": "socks", "tag": "probe",
			"settings": map[string]any{"auth": "noauth", "udp": false},
		}},
		"outbounds": []any{out},
	}
	return json.MarshalIndent(cfg, "", "  ")
}
