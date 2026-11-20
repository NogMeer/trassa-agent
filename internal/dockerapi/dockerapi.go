// SPDX-License-Identifier: AGPL-3.0-only

// Package dockerapi — клиент Docker Engine API по Unix-сокету для помощника (root): инвентарь и журналы
// контейнеров (E05, E08-T15). Только GET, свой клиент на net/http, без SDK Docker.
package dockerapi

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
)

// DefaultSocket — сокет Docker по умолчанию.
const DefaultSocket = "/var/run/docker.sock"

// MaxAPI — версия API клиента; с демоном договариваемся на min(своя, его).
const MaxAPI = "1.44"

// ErrNoDocker — сокета нет: Docker не установлен.
var ErrNoDocker = errors.New("docker не установлен")

// Client ходит в Docker API. Socket пуст — DefaultSocket.
type Client struct {
	Socket string
}

func (c *Client) socket() string {
	if c.Socket == "" {
		return DefaultSocket
	}
	return c.Socket
}

// Get выполняет GET path (без префикса версии) с договорённой версией API. Тело закрывает вызывающий.
// Сроки задаёт ctx.
func (c *Client) Get(ctx context.Context, path string) (*http.Response, error) {
	sock := c.socket()
	if _, err := os.Stat(sock); errors.Is(err, os.ErrNotExist) {
		return nil, ErrNoDocker
	}
	hc := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", sock)
		},
		DisableKeepAlives: true,
	}}
	get := func(p string) (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker"+p, nil)
		if err != nil {
			return nil, err
		}
		return hc.Do(req)
	}
	resp, err := get("/_ping")
	if err != nil {
		return nil, err
	}
	resp.Body.Close()
	return get("/v" + Version(resp.Header.Get("Api-Version")) + path)
}

// Version — min(MaxAPI, версия демона); пустой или кривой заголовок — MaxAPI.
func Version(daemon string) string {
	if cmpVersion(daemon, MaxAPI) < 0 {
		return daemon
	}
	return MaxAPI
}

func cmpVersion(a, b string) int {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	if len(pa) != 2 || len(pb) != 2 {
		return 1
	}
	for i := 0; i < 2; i++ {
		x, e1 := strconv.Atoi(pa[i])
		y, e2 := strconv.Atoi(pb[i])
		if e1 != nil || e2 != nil {
			return 1
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

// Потоки мультиплексного вывода.
const (
	StreamStdout = 1
	StreamStderr = 2
)

// MaxFrame — предел кадра журнала: длиннее — поток считается испорченным.
const MaxFrame = 1 << 20

// ReadFrame читает кадр мультиплексного потока контейнера без TTY: заголовок 8 байт
// {тип, 0, 0, 0, длина big-endian}, затем данные. io.EOF — поток кончился между кадрами.
func ReadFrame(r io.Reader) (stream byte, payload []byte, err error) {
	var hdr [8]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return 0, nil, fmt.Errorf("docker: оборванный заголовок кадра")
		}
		return 0, nil, err
	}
	if hdr[0] > StreamStderr || hdr[1] != 0 || hdr[2] != 0 || hdr[3] != 0 {
		return 0, nil, fmt.Errorf("docker: неверный заголовок кадра %x", hdr)
	}
	n := binary.BigEndian.Uint32(hdr[4:])
	if n > MaxFrame {
		return 0, nil, fmt.Errorf("docker: кадр %d байт больше предела", n)
	}
	payload = make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, fmt.Errorf("docker: оборванный кадр: %w", err)
	}
	return hdr[0], payload, nil
}
