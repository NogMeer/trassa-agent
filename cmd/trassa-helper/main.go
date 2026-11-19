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
	"net/http"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"syscall"
	"time"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/autorollback"
	"github.com/NogMeer/trassa-agent/internal/config"
	"github.com/NogMeer/trassa-agent/internal/helper"
	"github.com/NogMeer/trassa-agent/internal/helperrpc"
	"github.com/NogMeer/trassa-agent/internal/nonce"
	"github.com/NogMeer/trassa-agent/internal/ops"
	"github.com/NogMeer/trassa-agent/internal/rollback"
	"github.com/NogMeer/trassa-agent/internal/sysinfo"
	"github.com/NogMeer/trassa-agent/internal/sysinfo/sdunits"
	"github.com/NogMeer/trassa-agent/internal/uninstall"
	"github.com/NogMeer/trassa-agent/internal/update"
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
	updater.Client = &http.Client{Timeout: 5 * time.Minute}
	host := sysinfo.Real()
	inv := &sysinfo.Inventory{Host: host, Units: sdunits.List}
	ex := &helper.Executor{
		Checker:  &helper.Checker{Keys: keys, ServerID: en.ServerID, Catalog: ops.Builtin(), Nonces: n},
		States:   helper.States{Dir: p.OpsDir},
		Nonces:   n,
		Rollback: &rollback.Store{Dir: p.RollbackDir},
		Auto:     autorollback.Store{Dir: p.AutoRollbackDir},
		Timer:    autorollback.DefaultSystemd(),
		Lock:     helper.FileLock{Path: p.HelperLock},
		Log:      log,
		Version:  config.Version,
		System:   system{host: host, inv: inv},
		Services: helper.DefaultSystemdServices(),
		Updater:  &updater,
		Paths:    p,
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
