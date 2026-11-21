// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// Config — настройки CLI в <UserConfigDir>/trassa/config.json: адрес панели и пространство по умолчанию.
// Токена здесь нет (он в системном хранилище или в credentials.json).
type Config struct {
	URL       string `json:"url,omitempty"`
	Workspace string `json:"workspace,omitempty"`
}

const configName = "config.json"

func loadConfig(dir string) (*Config, error) {
	b, err := os.ReadFile(filepath.Join(dir, configName))
	if errors.Is(err, fs.ErrNotExist) {
		return &Config{}, nil
	}
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("%s: %w", filepath.Join(dir, configName), err)
	}
	return &c, nil
}

func saveConfig(dir string, c *Config) error {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return writePrivate(dir, configName, append(b, '\n'))
}

// writePrivate — файл 0600 в каталоге 0700 через временный файл и rename: недописанный файл не остаётся.
func writePrivate(dir, name string, data []byte) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, "."+name+".*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, name))
}

var errBadURL = errors.New("bad panel url")

// normalizeBase — адрес панели как origin: https, без пути, запроса и учётных данных; http — только для
// localhost и адресов петли (разработка). Токен не уходит по открытому каналу на чужой хост.
func normalizeBase(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errBadURL
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" ||
		(u.Path != "" && u.Path != "/") || u.Opaque != "" {
		return nil, errBadURL
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Host)
	switch scheme {
	case "https":
	case "http":
		if !loopback(u.Hostname()) {
			return nil, errBadURL
		}
	default:
		return nil, errBadURL
	}
	return &url.URL{Scheme: scheme, Host: host}, nil
}

func loopback(h string) bool {
	if strings.EqualFold(h, "localhost") || strings.HasSuffix(strings.ToLower(h), ".localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}
