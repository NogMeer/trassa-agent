// SPDX-License-Identifier: AGPL-3.0-only

// trassa — вход на свои серверы через Trassa со своего компьютера (E16 S4, T19, T20).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"

	"github.com/NogMeer/trassa-agent/internal/cli"
)

// version задаётся при сборке: -ldflags "-X main.version=1.2.3".
var version = "0.0.0-dev"

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	dir, err := os.UserConfigDir()
	lang := cli.DetectLang(os.Getenv)
	app := &cli.App{
		Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr,
		Env:       os.Getenv,
		ConfigDir: filepath.Join(dir, "trassa"),
		Keyring:   cli.SystemKeyring{},
		HTTP:      cli.NewHTTPClient(),
		Version:   version,
		Lang:      lang,
		Hostname:  os.Hostname,
		LookPath:  exec.LookPath,
		RunSSH:    cli.RunSSH,
		GOOS:      runtime.GOOS,
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "trassa:", err)
		return 1
	}
	code, err := dispatch(app, args)
	if err != nil {
		var ue usageError
		if errors.As(err, &ue) {
			fmt.Fprintln(os.Stderr, app.Explain(err))
			return 2
		}
		fmt.Fprintln(os.Stderr, "trassa: "+app.Explain(err))
		if code == 0 {
			code = 1
		}
	}
	return code
}

type usageError struct{ msg string }

func (e usageError) Error() string { return e.msg }

func dispatch(app *cli.App, args []string) (int, error) {
	usage := func() error { return usageError{cli.Usage(app.Lang)} }
	if len(args) == 0 {
		fmt.Fprint(app.Stderr, cli.Help(app.Lang))
		return 2, nil
	}
	cmd, rest := args[0], args[1:]
	// Ctrl-C в login и servers прерывает ожидание; в ssh его получает удалённая оболочка или ssh.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	switch cmd {
	case "help", "-h", "--help":
		fmt.Fprint(app.Stdout, cli.Help(app.Lang))
		return 0, nil
	case "version", "--version":
		fmt.Fprintf(app.Stdout, "trassa %s\n", app.Version)
		return 0, nil
	case "login":
		fs := newFlags("login")
		u := fs.String("url", "", "")
		name := fs.String("name", "", "")
		pos, _, err := parse(fs, rest)
		if err != nil || len(pos) != 0 {
			return 2, usage()
		}
		return 0, app.Login(ctx, *u, *name)
	case "logout":
		if len(rest) != 0 {
			return 2, usage()
		}
		return 0, app.Logout(ctx)
	case "whoami":
		if len(rest) != 0 {
			return 2, usage()
		}
		return 0, app.Whoami(ctx)
	case "use":
		if len(rest) != 1 {
			return 2, usage()
		}
		return 0, app.Use(ctx, rest[0])
	case "servers", "ls":
		fs := newFlags("servers")
		ws := workspaceFlag(fs)
		pos, _, err := parse(fs, rest)
		if err != nil || len(pos) != 0 {
			return 2, usage()
		}
		return 0, app.Servers(ctx, *ws)
	case "ssh":
		fs := newFlags("ssh")
		ws := workspaceFlag(fs)
		login := fs.String("l", "", "")
		direct := fs.Bool("direct", false, "")
		pos, remote, err := parse(fs, rest)
		if err != nil || len(pos) != 1 {
			return 2, usage()
		}
		// Сигналы терминала идут удалённой оболочке (сырой режим) или ssh; trassa их не перехватывает насмерть.
		stop()
		sctx, sstop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGHUP)
		defer sstop()
		ignoreInterrupt()
		return app.SSH(sctx, cli.SSHOptions{Workspace: *ws, Login: *login, Direct: *direct, Server: pos[0], Remote: remote},
			cli.NewTerminal(os.Stdin, os.Stdout))
	}
	return 2, usage()
}

// ignoreInterrupt — Ctrl-C во время ssh получает ssh (та же группа процессов), а не trassa. Через Notify, не
// signal.Ignore: игнорирование наследуется при exec, и ssh тоже перестал бы реагировать на Ctrl-C.
func ignoreInterrupt() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt)
	go func() {
		for range ch {
		}
	}()
}

func newFlags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

func workspaceFlag(fs *flag.FlagSet) *string {
	ws := fs.String("workspace", "", "")
	fs.StringVar(ws, "w", "", "")
	return ws
}

// parse — флаги вперемешку с позиционными аргументами; всё после «--» — команда для сервера.
func parse(fs *flag.FlagSet, args []string) (pos, remote []string, err error) {
	for i, a := range args {
		if a == "--" {
			args, remote = args[:i], args[i+1:]
			break
		}
	}
	for {
		if err := fs.Parse(args); err != nil {
			return nil, nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			return pos, remote, nil
		}
		// Parse остановился на позиционном аргументе: он в pos, флаги после него разбираются дальше.
		pos = append(pos, args[0])
		args = args[1:]
	}
}
