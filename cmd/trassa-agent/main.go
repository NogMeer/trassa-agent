// SPDX-License-Identifier: AGPL-3.0-only

// trassa-agent — сетевой процесс агента Trassa (E05-T11). Работает от пользователя trassa без прав, держит WSS
// со шлюзом и передаёт подписанные операции помощнику.
//
//	trassa-agent [run]                       служба
//	trassa-agent enroll --url https://agents.<домен>   регистрация (root; токен в TRASSA_ENROLL_TOKEN)
//	trassa-agent status
//	trassa-agent uninstall [--purge-rollback] [--yes]
//	trassa-agent version
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/NogMeer/trassa-agent/internal/channel"
	"github.com/NogMeer/trassa-agent/internal/config"
	"github.com/NogMeer/trassa-agent/internal/enroll"
	"github.com/NogMeer/trassa-agent/internal/fsutil"
	"github.com/NogMeer/trassa-agent/internal/helperrpc"
	"github.com/NogMeer/trassa-agent/internal/identity"
	"github.com/NogMeer/trassa-agent/internal/sysinfo"
	"github.com/NogMeer/trassa-agent/internal/uninstall"
)

// Коды выхода. ExitRevoked прописан в RestartPreventExitStatus службы: отозванный агент не перезапускается.
const (
	exitError        = 1
	exitTokenInvalid = 2
	exitRevoked      = 3
	exitUnsupported  = 4
)

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(log)
	args := os.Args[1:]
	cmd := "run"
	if len(args) > 0 {
		cmd, args = args[0], args[1:]
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	switch cmd {
	case "version":
		fmt.Println(config.Version)
	case "run":
		os.Exit(run(ctx, log))
	case "enroll":
		os.Exit(enrollCmd(ctx, args))
	case "status":
		os.Exit(status(ctx))
	case "uninstall":
		os.Exit(uninstallCmd(ctx, args))
	default:
		fmt.Fprintf(os.Stderr, "неизвестная команда %q\n", cmd)
		os.Exit(exitError)
	}
}

func run(ctx context.Context, log *slog.Logger) int {
	p := config.Default()
	en, keys, err := config.LoadEnrollment(p.Enrollment)
	if err != nil {
		log.Error("агент не зарегистрирован", "err", err)
		return exitError
	}
	id, err := identity.Load(p.AgentKey)
	if err != nil {
		log.Error("ключ агента", "err", err)
		return exitError
	}
	osID, osVer, _ := sysinfo.Real().OSRelease()
	a := channel.New(channel.Config{
		GatewayURL: en.GatewayURL, ServerID: en.ServerID, Identity: id, PanelKeys: keys,
		Helper:  &helperrpc.Client{Path: p.Socket, Timeout: 30 * time.Second},
		Version: config.Version, OS: osID, OSVersion: osVer, Arch: runtime.GOARCH,
		HTTPClient: &http.Client{}, Log: log, UpdateDir: p.UpdateDir,
	})
	if err := a.Run(ctx); errors.Is(err, channel.ErrRevoked) {
		return exitRevoked
	} else if err != nil {
		log.Error("канал", "err", err)
		return exitError
	}
	return 0
}

func requireRoot() bool {
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "Нужны права root: запустите через sudo")
		return false
	}
	return true
}

func enrollCmd(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("enroll", flag.ContinueOnError)
	panelURL := fs.String("url", "", "адрес панели, https://agents.<домен>")
	if err := fs.Parse(args); err != nil || *panelURL == "" {
		fmt.Fprintln(os.Stderr, "использование: TRASSA_ENROLL_TOKEN=trs_enr_… trassa-agent enroll --url https://agents.<домен>")
		return exitError
	}
	if !requireRoot() {
		return exitError
	}
	// Токен — из окружения, а не из аргументов: аргументы видны всем в списке процессов.
	token := strings.TrimSpace(os.Getenv("TRASSA_ENROLL_TOKEN"))
	p := config.Default()
	if _, err := os.Stat(p.Enrollment); err == nil {
		fmt.Fprintln(os.Stderr, "Агент уже зарегистрирован. Состояние: trassa-agent status. Удалить: trassa-agent uninstall")
		return exitError
	}
	u, err := user.Lookup(config.UserName)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Нет пользователя trassa: запустите установку заново")
		return exitError
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	for _, d := range []struct {
		path  string
		mode  os.FileMode
		owner fsutil.Owner
	}{{p.EtcDir, 0o750, fsutil.Owner{UID: 0, GID: gid}}, {p.StateDir, 0o755, fsutil.Owner{UID: 0, GID: 0}}, {p.AgentDir, 0o700, fsutil.Owner{UID: uid, GID: gid}}} {
		if err := os.MkdirAll(d.path, d.mode); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return exitError
		}
		if err := os.Chown(d.path, d.owner.UID, d.owner.GID); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return exitError
		}
		_ = os.Chmod(d.path, d.mode)
	}
	// Ключ от прошлой неудачной попытки не переиспользуется: панель его не знает.
	_ = os.Remove(p.AgentKey)
	id, err := identity.Generate(p.AgentKey, fsutil.Owner{UID: uid, GID: gid})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitError
	}
	host := sysinfo.Real()
	osID, osVer, _ := host.OSRelease()
	hostname, _ := os.Hostname()
	rctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	en, err := enroll.Do(rctx, &http.Client{Timeout: 30 * time.Second}, *panelURL, enroll.Request{
		Token: token, PublicKey: enroll.PublicKeyString(id.PublicKey()), Hostname: sysinfo.Clean(hostname),
		OS: osID, OSVersion: osVer, Arch: runtime.GOARCH, AgentVersion: config.Version,
		ProtocolVersions: []int{config.ProtocolVersion},
	})
	if err != nil {
		_ = os.Remove(p.AgentKey)
		fmt.Fprintln(os.Stderr, enroll.UserMessage(err))
		var e *enroll.Error
		if errors.As(err, &e) && e.Code == enroll.CodeTokenInvalid {
			return exitTokenInvalid
		}
		if errors.As(err, &e) && (e.Code == enroll.CodeOSUnsupported || e.Code == enroll.CodeProtocolUnsupported) {
			return exitUnsupported
		}
		return exitError
	}
	if err := config.SaveEnrollment(p.Enrollment, en, fsutil.Owner{UID: 0, GID: gid}); err != nil {
		_ = os.Remove(p.AgentKey)
		fmt.Fprintln(os.Stderr, err)
		return exitError
	}
	fmt.Println("Сервер зарегистрирован:", en.ServerID)
	return 0
}

func status(ctx context.Context) int {
	p := config.Default()
	en, _, err := config.LoadEnrollment(p.Enrollment)
	if err != nil {
		fmt.Println("Регистрация: нет или не читается (" + err.Error() + ")")
	} else {
		fmt.Println("Сервер:", en.ServerID)
		fmt.Println("Шлюз:", en.GatewayURL)
	}
	fmt.Println("Версия:", config.Version)
	code := 0
	// Помощник отвечает только пользователю trassa; от root и других пользователей — отказ, это нормально.
	hv, caps, err := (&helperrpc.Client{Path: p.Socket, Timeout: 5 * time.Second}).Hello(ctx)
	if err != nil {
		fmt.Println("Помощник: нет ответа (" + err.Error() + ")")
		code = exitError
	} else {
		fmt.Printf("Помощник: %s, типы операций: %s\n", hv, strings.Join(caps, ", "))
	}
	for _, u := range uninstall.Units {
		out, err := exec.CommandContext(ctx, "/usr/bin/systemctl", "is-active", u).Output()
		state := strings.TrimSpace(string(out))
		if state == "" {
			state = "неизвестно"
		}
		if err != nil {
			code = exitError
		}
		fmt.Printf("%s: %s\n", u, state)
	}
	return code
}

func uninstallCmd(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("uninstall", flag.ContinueOnError)
	purge := fs.Bool("purge-rollback", false, "удалить и точки отката")
	yes := fs.Bool("yes", false, "не спрашивать подтверждение")
	if err := fs.Parse(args); err != nil {
		return exitError
	}
	if !requireRoot() {
		return exitError
	}
	plan := uninstall.Plan(config.Default(), *purge)
	fmt.Println("Будут остановлены службы:", strings.Join(plan.Units, ", "))
	fmt.Println("Будут удалены:", strings.Join(plan.Paths, ", "))
	fmt.Println("Будет удалён пользователь:", plan.User)
	if !*yes {
		fmt.Print("Удалить агент Trassa? Введите yes: ")
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		if strings.TrimSpace(line) != "yes" {
			fmt.Println("Отменено")
			return exitError
		}
	}
	if err := uninstall.Run(ctx, config.Default(), *purge, uninstall.Exec); err != nil {
		fmt.Fprintln(os.Stderr, "Удалено не всё:", err)
		return exitError
	}
	fmt.Println("Агент Trassa удалён. Сервер в панели останется без связи")
	return 0
}
