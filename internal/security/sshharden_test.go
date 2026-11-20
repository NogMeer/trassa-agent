// SPDX-License-Identifier: AGPL-3.0-only

package security

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
)

func ptr(b bool) *bool { return &b }

// fakeSSHD — sshd -T отдаёт действующие значения: базовые плюс файл Trassa, если он есть.
func fakeSSHD(sys *System, base string) func(context.Context, string, ...string) ([]byte, error) {
	return func(_ context.Context, name string, args ...string) ([]byte, error) {
		switch name {
		case "sshd":
			if len(args) > 0 && args[0] == "-t" {
				return nil, nil
			}
			out := base
			if b, err := os.ReadFile(filepath.Join(sys.Root, SSHConfigFile)); err == nil {
				for _, l := range strings.Split(string(b), "\n") {
					if k, v, ok := strings.Cut(l, " "); ok && !strings.HasPrefix(l, "#") {
						out = strings.ToLower(k) + " " + v + "\n" + out // первое значение побеждает
					}
				}
			}
			// Как sshd -T: по ключу одна строка (кроме port) — первая.
			seen := map[string]bool{}
			var res []string
			for _, l := range strings.Split(out, "\n") {
				k, _, _ := strings.Cut(l, " ")
				if k == "" || (seen[k] && k != "port") {
					continue
				}
				seen[k] = true
				res = append(res, l)
			}
			return []byte(strings.Join(res, "\n") + "\n"), nil
		case "systemctl":
			return []byte("disabled\n"), errors.New("1")
		}
		return nil, errors.New("нет")
	}
}

func sshSystem(t *testing.T, keys bool) *System {
	files := tree{"etc/passwd": passwd, "etc/shadow": shadow, "etc/group": "sudo:x:27:alice\n", "proc/net/tcp": procTCP, "proc/net/udp": "  sl\n",
		"proc/10/fd/3": "->socket:[1001]", "proc/10/comm": "sshd\n"}
	if keys {
		files["home/alice/.ssh/authorized_keys"] = "ssh-ed25519 " + sshBlob("ssh-ed25519", make([]byte, 32)) + " alice\n"
	}
	sys := build(t, files)
	sys.Run = fakeSSHD(sys, "port 22\npasswordauthentication yes\npermitrootlogin yes\nmaxauthtries 6\nkbdinteractiveauthentication no\n")
	return sys
}

func TestSSHHardenValidate(t *testing.T) {
	for name, p := range map[string]*agentv1.SshHardenParams{
		"пусто":            {},
		"включить пароль":  {PasswordAuth: ptr(true)},
		"пустые пароли":    {EmptyPasswords: ptr(true)},
		"порт":             {Port: 70000},
		"попыток слишком":  {MaxAuthTries: 11},
		"неизвестный root": {RootLogin: 9},
	} {
		if ValidateSSHHarden(p) == nil {
			t.Errorf("%s: принято", name)
		}
	}
	if err := ValidateSSHHarden(&agentv1.SshHardenParams{PasswordAuth: ptr(false), CryptoPreset: agentv1.CryptoPreset_CRYPTO_PRESET_STRICT}); err != nil {
		t.Fatal(err)
	}
}

func TestSSHHardenPlan(t *testing.T) {
	sys := sshSystem(t, true)
	p, err := PlanSSHHarden(context.Background(), sys, &agentv1.SshHardenParams{
		PasswordAuth: ptr(false), RootLogin: agentv1.RootLogin_ROOT_LOGIN_KEY_ONLY, MaxAuthTries: 3, CryptoPreset: agentv1.CryptoPreset_CRYPTO_PRESET_STRICT,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Services) != 1 || p.Services[0] != "ssh.service" || !p.State.Empty() {
		t.Fatalf("%v %+v", p.Services, p.State)
	}
	if err := p.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(sys.Root, SSHConfigFile))
	for _, want := range []string{"PasswordAuthentication no", "KbdInteractiveAuthentication no", "PermitRootLogin prohibit-password", "MaxAuthTries 3", "MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com"} {
		if !strings.Contains(string(b), want+"\n") {
			t.Errorf("нет %q в\n%s", want, b)
		}
	}
	if err := p.Verify(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Второй запуск сохраняет прежние значения файла.
	p2, err := PlanSSHHarden(context.Background(), sys, &agentv1.SshHardenParams{EmptyPasswords: ptr(false)})
	if err != nil {
		t.Fatal(err)
	}
	_ = p2.Apply(context.Background())
	b, _ = os.ReadFile(filepath.Join(sys.Root, SSHConfigFile))
	if !strings.Contains(string(b), "MaxAuthTries 3") || !strings.Contains(string(b), "PermitEmptyPasswords no") {
		t.Fatalf("%s", b)
	}
	// Действующее значение не совпало (пользовательский Match или sshd не перечитал) — проверка падает.
	sys.Run = fakeSSHD(sys, "passwordauthentication yes\n")
	if err := os.WriteFile(filepath.Join(sys.Root, SSHConfigFile), []byte("# пусто\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := p.Verify(context.Background()); err == nil {
		t.Fatal("проверка не заметила расхождения")
	}
}

func TestSSHHardenPreconditions(t *testing.T) {
	// Нет ключа у пользователя с sudo — пароль выключать нельзя.
	sys := sshSystem(t, false)
	if _, err := PlanSSHHarden(context.Background(), sys, &agentv1.SshHardenParams{PasswordAuth: ptr(false)}); !errors.Is(err, ErrPrecondition) {
		t.Fatalf("без ключа: %v", err)
	}
	// Нет пользователя с sudo — root запрещать нельзя.
	sys = sshSystem(t, true)
	if err := os.WriteFile(filepath.Join(sys.Root, "etc/group"), []byte("sudo:x:27:\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := PlanSSHHarden(context.Background(), sys, &agentv1.SshHardenParams{RootLogin: agentv1.RootLogin_ROOT_LOGIN_NO}); !errors.Is(err, ErrPrecondition) {
		t.Fatalf("без sudo: %v", err)
	}
	// Порт занят другим процессом (6379 — redis в образце /proc/net/tcp).
	sys = sshSystem(t, true)
	files := map[string]string{"proc/20/fd/5": "socket:[1003]", "proc/20/comm": "redis-server\n"}
	for p, v := range files {
		full := filepath.Join(sys.Root, p)
		_ = os.MkdirAll(filepath.Dir(full), 0o755)
		if strings.HasPrefix(v, "socket:") {
			_ = os.Symlink(v, full)
		} else {
			_ = os.WriteFile(full, []byte(v), 0o644)
		}
	}
	if _, err := PlanSSHHarden(context.Background(), sys, &agentv1.SshHardenParams{Port: 6379}); !errors.Is(err, ErrPrecondition) {
		t.Fatalf("занятый порт: %v", err)
	}
}

// Пароль уже выключен раньше: запрет root без ключа у пользователя с sudo — отказ, с ключом — можно.
func TestSSHHardenRootNoWithPasswordAlreadyOff(t *testing.T) {
	base := "port 22\npasswordauthentication no\npermitrootlogin yes\nkbdinteractiveauthentication no\n"
	sys := sshSystem(t, false)
	sys.Run = fakeSSHD(sys, base)
	if _, err := PlanSSHHarden(context.Background(), sys, &agentv1.SshHardenParams{RootLogin: agentv1.RootLogin_ROOT_LOGIN_NO}); !errors.Is(err, ErrPrecondition) {
		t.Fatalf("без ключа: %v", err)
	}
	sys = sshSystem(t, true)
	sys.Run = fakeSSHD(sys, base)
	if _, err := PlanSSHHarden(context.Background(), sys, &agentv1.SshHardenParams{RootLogin: agentv1.RootLogin_ROOT_LOGIN_NO}); err != nil {
		t.Fatalf("с ключом: %v", err)
	}
}

// Межсетевой экран Trassa загружен: новый порт SSH должен быть в нём открыт.
func TestSSHHardenPortVsTrassaFirewall(t *testing.T) {
	table := "table inet trassa {\n\tchain input {\n\t\ttcp dport 22 accept\n\t\tip saddr { 10.0.0.0/8 } tcp dport 2000-2100 accept comment \"vpn\"\n\t}\n" +
		"\tchain forward {\n\t\tmeta l4proto tcp ct original proto-dst 3333 accept\n\t\ttcp dport 4444 accept\n\t}\n}\n"
	for port, ok := range map[uint32]bool{2022: true, 3333: false, 4444: false, 2222: false} {
		sys := sshSystem(t, true)
		sshd := fakeSSHD(sys, "port 22\npasswordauthentication yes\npermitrootlogin yes\nkbdinteractiveauthentication no\n")
		sys.Run = func(ctx context.Context, name string, args ...string) ([]byte, error) {
			if name == "nft" {
				return []byte(table), nil
			}
			return sshd(ctx, name, args...)
		}
		_, err := PlanSSHHarden(context.Background(), sys, &agentv1.SshHardenParams{Port: port})
		if ok && err != nil || !ok && !errors.Is(err, ErrPrecondition) {
			t.Errorf("порт %d: %v", port, err)
		}
	}
	// Таблицы Trassa нет — проверка не мешает (остаётся заметка про чужой firewall).
	sys := sshSystem(t, true)
	if _, err := PlanSSHHarden(context.Background(), sys, &agentv1.SshHardenParams{Port: 2222}); err != nil {
		t.Fatal(err)
	}
}
