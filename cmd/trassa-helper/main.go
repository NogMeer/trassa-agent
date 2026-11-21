// SPDX-License-Identifier: AGPL-3.0-only

// trassa-helper — root-помощник агента Trassa (E05-T12). Слушает /run/trassa/helper.sock, выполняет только
// подписанные панелью операции из зашитого списка.
//
//	trassa-helper [serve]                  служба
//	trassa-helper rollback <operation_id>  автооткат по таймеру (запускает systemd-run)
//	trassa-helper update-rollback <op>     то же для сторожа обновления
//	trassa-helper uninstall [--purge-rollback]
//	trassa-helper version
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/access"
	"github.com/NogMeer/trassa-agent/internal/autorollback"
	"github.com/NogMeer/trassa-agent/internal/backup"
	"github.com/NogMeer/trassa-agent/internal/config"
	"github.com/NogMeer/trassa-agent/internal/deploy"
	"github.com/NogMeer/trassa-agent/internal/dockerapi"
	"github.com/NogMeer/trassa-agent/internal/fsinspect"
	"github.com/NogMeer/trassa-agent/internal/helper"
	"github.com/NogMeer/trassa-agent/internal/helper/execrun"
	"github.com/NogMeer/trassa-agent/internal/helperrpc"
	"github.com/NogMeer/trassa-agent/internal/logsrc"
	"github.com/NogMeer/trassa-agent/internal/metrics"
	"github.com/NogMeer/trassa-agent/internal/nonce"
	"github.com/NogMeer/trassa-agent/internal/ops"
	"github.com/NogMeer/trassa-agent/internal/remedy"
	"github.com/NogMeer/trassa-agent/internal/rollback"
	"github.com/NogMeer/trassa-agent/internal/sealed"
	"github.com/NogMeer/trassa-agent/internal/security"
	"github.com/NogMeer/trassa-agent/internal/sysinfo"
	"github.com/NogMeer/trassa-agent/internal/sysinfo/sdunits"
	"github.com/NogMeer/trassa-agent/internal/terminal"
	"github.com/NogMeer/trassa-agent/internal/uninstall"
	"github.com/NogMeer/trassa-agent/internal/update"
	"github.com/NogMeer/trassa-agent/internal/vpnprobe"
	"github.com/NogMeer/trassa-agent/internal/wireguard"
)

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(log)
	args := os.Args[1:]
	cmd := "serve"
	if len(args) > 0 {
		cmd, args = args[0], args[1:]
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	var err error
	switch cmd {
	case "version":
		fmt.Println(config.Version)
		return
	case "serve":
		err = serve(ctx, log)
	case "rollback", "update-rollback":
		if len(args) != 1 || !config.IsUUID(args[0]) {
			err = errors.New("нужен operation_id")
			break
		}
		err = rollbackCmd(ctx, log, args[0])
	case "wireguard-sync":
		// После отката: ядро и блок имён по возвращённым файлам (rollback.State.Commands).
		if len(args) != 1 || wireguard.ValidIface(args[0]) != nil {
			err = errors.New("использование: trassa-helper wireguard-sync <iface>")
			break
		}
		e := wgEnv(config.Default())
		err = errors.Join(e.SyncHosts(args[0]), e.Sync(ctx, args[0]))
	case "proxy-sync":
		// После отката маршрутов: документ Caddy по возвращённому состоянию (rollback.State.Commands).
		if err = requireRoot(); err == nil {
			err = deployEnv(config.Default()).SyncProxy(ctx)
		}
	case "wireguard-purge":
		// При удалении агента: интерфейсы, правила DOCKER-USER, блоки имён и пересылка Trassa снимаются.
		if err = requireRoot(); err == nil {
			err = wgEnv(config.Default()).Purge(ctx)
		}
	case "uninstall":
		purge := len(args) == 1 && args[0] == "--purge-rollback"
		if len(args) > 1 || (len(args) == 1 && !purge) {
			err = errors.New("использование: trassa-helper uninstall [--purge-rollback]")
			break
		}
		err = requireRoot()
		if err == nil {
			err = uninstall.Run(ctx, config.Default(), purge, uninstall.Exec)
		}
	default:
		err = fmt.Errorf("неизвестная команда %q", cmd)
	}
	if err != nil {
		log.Error("trassa-helper", "cmd", cmd, "err", err)
		os.Exit(1)
	}
}

func requireRoot() error {
	if os.Geteuid() != 0 {
		return errors.New("нужны права root")
	}
	return nil
}

// agentUser — uid и gid пользователя trassa. Нет пользователя — помощник не стартует.
func agentUser() (int, int, error) {
	u, err := user.Lookup(config.UserName)
	if err != nil {
		return -1, -1, fmt.Errorf("пользователь %s: %w", config.UserName, err)
	}
	uid, err1 := strconv.Atoi(u.Uid)
	gid, err2 := strconv.Atoi(u.Gid)
	if err1 != nil || err2 != nil || uid == 0 {
		return -1, -1, fmt.Errorf("пользователь %s: uid %s gid %s", config.UserName, u.Uid, u.Gid)
	}
	return uid, gid, nil
}

// executor собирает исполнитель. Пустой список ключей панели или типов — отказ (R1).
func executor(log *slog.Logger) (*helper.Executor, func(), error) {
	if err := requireRoot(); err != nil {
		return nil, nil, err
	}
	p := config.Default()
	en, keys, err := config.LoadEnrollment(p.Enrollment)
	if err != nil {
		return nil, nil, fmt.Errorf("запись о регистрации: %w", err)
	}
	for _, d := range []string{p.HelperDir, p.OpsDir, p.AutoRollbackDir, p.RollbackDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, nil, err
		}
		if err := os.Chmod(d, 0o700); err != nil {
			return nil, nil, err
		}
	}
	n, err := nonce.Open(p.Nonces, nil)
	if err != nil {
		return nil, nil, err
	}
	var updater helper.Updater
	if v, err := update.NewVerifier(update.ReleaseKeys); err != nil {
		log.Warn("обновления агента отключены: в сборке нет ключей выпуска", "err", err)
	} else {
		updater.Verifier = v
	}
	host := sysinfo.Real()
	inv := &sysinfo.Inventory{Host: host, Units: sdunits.List}
	// Ключ секретов (E13, HPKE): создаётся при первом запуске, хранится только у помощника.
	secrets, err := sealed.LoadOrCreate(filepath.Join(p.HelperDir, "encryption.key"))
	if err != nil {
		n.Close()
		return nil, nil, fmt.Errorf("ключ секретов: %w", err)
	}
	sec := security.Real()
	sec.Detector = &security.Detector{Sys: sec, Path: filepath.Join(p.HelperDir, "baseline.json"), Log: log}
	dep := deployEnv(p)
	ex := &helper.Executor{
		Checker:   &helper.Checker{Keys: keys, ServerID: en.ServerID, Catalog: ops.Builtin(), Nonces: n},
		States:    helper.States{Dir: p.OpsDir},
		Nonces:    n,
		Rollback:  &rollback.Store{Dir: p.RollbackDir, Exec: execNoShell},
		Auto:      autorollback.Store{Dir: p.AutoRollbackDir},
		Timer:     autorollback.DefaultSystemd(),
		Lock:      helper.FileLock{Path: p.HelperLock},
		Log:       log,
		Version:   config.Version,
		System:    system{host: host, inv: inv},
		Services:  helper.DefaultSystemdServices(),
		Updater:   &updater,
		Paths:     p,
		Logs:      logsrc.New(),
		Security:  sec,
		WireGuard: wgEnv(p),
		Secrets:   secrets,
		Backup: &backup.Env{
			Store: backup.Store{Dir: p.BackupDir}, BinDir: p.HelperBin, CacheDir: filepath.Join(p.CacheDir, "restic"),
			WorkDir: p.BackupWorkDir, StatusPath: filepath.Join(p.BackupWorkDir, "status.json"),
			Docker: &dockerapi.Client{}, Run: backup.RunCommand, Look: backup.LookPath,
		},
		Access:   &access.Env{Root: "/", Run: backup.RunCommand},
		Deploy:   dep,
		AppStats: &deploy.AppStats{Env: dep},
		Remedy:   remedyEnv(p, sec),
		VpnProbe: vpnProbeEnv(p),
		Inspect:  &fsinspect.Env{Root: "/"},
		Exec:     execrun.Systemd{SystemdRun: "/usr/bin/systemd-run", Systemctl: "/usr/bin/systemctl"},
		Terminals: &helper.Terminals{Units: terminal.Systemd{}, OpenPTY: terminal.OpenPTY, Locales: func(ctx context.Context) []string {
			out, _ := backup.RunCommand(ctx, "locale", "-a")
			return strings.Fields(string(out))
		}},
		BackupTarget: &backup.Target{Root: "/", BinDir: p.TargetBin, Run: backup.RunCommand,
			StageDir: func(op string) string { return helper.StageDir(p, op) }},
	}
	if err := ex.CheckHandlers(); err != nil {
		n.Close()
		return nil, nil, err
	}
	return ex, func() { n.Close() }, nil
}

type system struct {
	host *sysinfo.Host
	inv  *sysinfo.Inventory
}

func (s system) Info(context.Context) (*agentv1.SystemInfoResult, []string) {
	return s.host.Info(config.Version)
}

func (s system) Inventory(ctx context.Context, kinds []agentv1.InventoryKind) (*agentv1.SystemInventoryResult, []string) {
	return s.inv.Collect(ctx, kinds)
}

func serve(ctx context.Context, log *slog.Logger) error {
	uid, gid, err := agentUser()
	if err != nil {
		return err
	}
	ex, closeFn, err := executor(log)
	if err != nil {
		return err
	}
	defer closeFn()
	if err := ex.Recover(ctx); err != nil {
		return fmt.Errorf("восстановление: %w", err)
	}
	// Терминалы прошлого запуска без таймеров продления жить не должны (decisions E16, 9.3).
	ex.StopOrphanTerminals(ctx)
	// Каталоги замеров прошлого запуска (в них тестовый доступ) не остаются на диске.
	if ex.VpnProbe != nil {
		if err := ex.VpnProbe.Cleanup(); err != nil {
			log.Error("trassa-helper: каталоги замеров не удалены", "err", err)
		}
	}
	// Бэкап в режиме STOP прервался (падение помощника) — контейнеры с томом не остаются остановленными.
	if ex.Backup != nil {
		if err := ex.Backup.RestartStopped(ctx); err != nil {
			log.Error("trassa-helper: контейнеры после прерванного бэкапа не запущены", "err", err)
			ex.PushEvent(&agentv1.Event{Kind: backup.EventContainerNotRestarted, Severity: agentv1.EventSeverity_EVENT_SEVERITY_CRIT,
				AtMs: time.Now().UnixMilli(), Message: "контейнеры не запустились после прерванного бэкапа",
				Attributes: map[string]string{"state": "firing", "subject": "restart-after-crash"}})
		}
	}
	p := config.Default()
	// /run/trassa создаёт systemd (RuntimeDirectory, root:root 0750); агенту нужна группа, чтобы дойти до сокета.
	if err := os.MkdirAll(p.RunDir, 0o750); err != nil {
		return err
	}
	if err := os.Chown(p.RunDir, 0, gid); err != nil {
		return err
	}
	if err := os.Chmod(p.RunDir, 0o750); err != nil {
		return err
	}
	l, err := helperrpc.Listen(p.Socket, gid)
	if err != nil {
		return err
	}
	go func() {
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				ex.PruneBackupWork()
				ex.ExpireRescue(ctx)
			}
		}
	}()
	// Приватная сеть после перезагрузки и перерисовки /etc/hosts cloud-init — по файлам состояния (E14).
	if ex.WireGuard != nil {
		if err := ex.WireGuard.SyncAll(ctx); err != nil {
			log.Warn("приватная сеть: синхронизация при старте", "err", err)
		}
	}
	// Падение контейнеров и срок сертификатов certbot (E18): события — агенту через опрос событий.
	if ex.Remedy != nil {
		w := &remedy.Watcher{Env: ex.Remedy}
		go w.Run(ctx, time.Minute, 6*time.Hour, ex.PushEvent)
	}
	// Детектор (E10-T7) наблюдает, пока работает помощник.
	if ex.Security != nil && ex.Security.Detector != nil {
		go ex.Security.Detector.Run(ctx)
	}
	log.Info("помощник слушает", "socket", p.Socket, "types", ex.Checker.Catalog.Types(), "version", config.Version)
	return (&helperrpc.Server{AllowedUID: uid, Handler: ex, Log: log}).Serve(ctx, l)
}

func rollbackCmd(ctx context.Context, log *slog.Logger, op string) error {
	ex, closeFn, err := executor(log)
	if err != nil {
		return err
	}
	defer closeFn()
	return ex.AutoRollback(ctx, op)
}

// execNoShell — systemctl и apt-get для отката состояния (rollback.State): без оболочки, ограниченное окружение,
// вывод в журнал помощника не идёт, код возврата — ошибка.
func execNoShell(name string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = []string{"LANG=C", "LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin", "DEBIAN_FRONTEND=noninteractive"}
	out, err := cmd.CombinedOutput()
	if err != nil {
		s := strings.TrimSpace(string(out))
		if len(s) > 500 {
			s = s[len(s)-500:]
		}
		return fmt.Errorf("%w: %s", err, s)
	}
	return nil
}

// wgEnv — приватная сеть на настоящей системе: файлы в /etc/trassa/wireguard, ядро через netlink и wgctrl.
func wgEnv(p config.Paths) *wireguard.Env {
	sock := "/var/run/docker.sock"
	return &wireguard.Env{
		System: &wireguard.System{
			Store: wireguard.Store{Dir: filepath.Join(p.EtcDir, "wireguard")}, Kernel: wireguard.NetlinkKernel{},
			Run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
				return exec.CommandContext(ctx, name, args...).CombinedOutput()
			},
			Hosts: "/etc/hosts", ProcSys: "/proc/sys",
			DockerPresent: func() bool { _, err := os.Stat(sock); return err == nil },
		},
		Root: "/", HelperPath: filepath.Join(p.BinDir, "trassa-helper"), Docker: &dockerapi.Client{},
		Addrs: func() ([]netip.Prefix, []string, error) {
			ifs, err := net.Interfaces()
			if err != nil {
				return nil, nil, err
			}
			var ps []netip.Prefix
			var names []string
			for _, i := range ifs {
				as, _ := i.Addrs()
				for _, a := range as {
					if pr, err := netip.ParsePrefix(a.String()); err == nil {
						ps = append(ps, pr)
						names = append(names, i.Name)
					}
				}
			}
			return ps, names, nil
		},
	}
}

// deployEnv — деплой (E17): Docker, прокси Caddy; программы скачивает агент в каталог операции.
func deployEnv(p config.Paths) *deploy.Env {
	return &deploy.Env{Root: "/", Docker: &dockerapi.Client{}, Run: backup.RunCommand,
		Stage: func(op string) string { return helper.StageDir(p, op) }, StateDir: filepath.Join(p.StateDir, "deploy"),
		AppsDir: filepath.Join(p.StateDir, "apps"), BuildDir: filepath.Join(p.StateDir, "build")}
}

// remedyEnv — исправления E18: прокси и образы релизов Trassa берутся из состояния деплоя.
// vpnProbeEnv — точка замера (E25): движки в /var/lib/trassa/vpn-probe, доступ замера — в /run/trassa-vpnprobe.
// Движку скрыты каталоги Trassa (ключ агента, сокет помощника, секреты бэкапов) и соседние замеры.
func vpnProbeEnv(p config.Paths) *vpnprobe.Env {
	dir := filepath.Join(p.StateDir, "vpn-probe")
	run := "/run/trassa-vpnprobe"
	var d net.Dialer
	return &vpnprobe.Env{
		Dir: dir, RunDir: run,
		Sandbox: vpnprobe.Systemd{SystemdRun: "/usr/bin/systemd-run", Systemctl: "/usr/bin/systemctl", User: config.ProbeUserName,
			Hidden: []string{p.StateDir, p.EtcDir, p.RunDir, p.CacheDir, run}, EngineDir: dir},
		Owner:      probeUser,
		EnsureUser: ensureProbeUser,
		LookupIP: func(ctx context.Context, h string) ([]net.IP, error) {
			return net.DefaultResolver.LookupIP(ctx, "ip", h)
		},
		DialEntry: func(ctx context.Context, addr string) (net.Conn, error) { return d.DialContext(ctx, "tcp", addr) },
	}
}

// probeUser — uid и gid пользователя движка; совпадение с root или trassa — отказ (иначе скрытие не действует).
func probeUser() (int, int, error) {
	u, err := user.Lookup(config.ProbeUserName)
	if err != nil {
		return -1, -1, fmt.Errorf("пользователь %s: %w", config.ProbeUserName, err)
	}
	uid, err1 := strconv.Atoi(u.Uid)
	gid, err2 := strconv.Atoi(u.Gid)
	auid, agid, aerr := agentUser()
	if err1 != nil || err2 != nil || aerr != nil || uid == 0 || gid == 0 || uid == auid || gid == agid {
		return -1, -1, fmt.Errorf("пользователь %s: uid %s gid %s совпадает с root или %s", config.ProbeUserName, u.Uid, u.Gid, config.UserName)
	}
	return uid, gid, nil
}

// ensureProbeUser — системный пользователь движка без дома и оболочки, как trassa в установщике.
func ensureProbeUser(ctx context.Context) error {
	if _, err := user.Lookup(config.ProbeUserName); err == nil {
		_, _, err := probeUser()
		return err
	}
	out, err := backup.RunCommand(ctx, "/usr/sbin/useradd", "--system", "--user-group", "--no-create-home",
		"--home-dir", "/nonexistent", "--shell", "/usr/sbin/nologin", config.ProbeUserName)
	if err != nil {
		return fmt.Errorf("useradd: %v %s", err, strings.TrimSpace(string(out)))
	}
	_, _, err = probeUser()
	return err
}

func remedyEnv(p config.Paths, sec *security.System) *remedy.Env {
	d := deployEnv(p)
	return &remedy.Env{Root: "/", Run: backup.RunCommand, Docker: &dockerapi.Client{},
		ProxyHosts: d.ProxyHosts, TrassaImages: d.ReleaseImages,
		Free: func(path string) (uint64, uint64, error) {
			fs, err := metrics.New().Statfs(path)
			if err != nil {
				return 0, 0, err
			}
			return fs.Bavail * uint64(fs.Bsize), fs.Blocks * uint64(fs.Bsize), nil
		},
		Served: remedy.ServedTLS,
		PackagesBusy: func(context.Context) string {
			h, err := security.PackageManagerBusy(sec)
			if err != nil {
				return "блокировка не проверена: " + err.Error()
			}
			if h != nil {
				return h.String()
			}
			return ""
		},
	}
}
