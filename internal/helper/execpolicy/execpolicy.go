// SPDX-License-Identifier: AGPL-3.0-only

// Package execpolicy — запреты диспетчера для exec.run (E20, R28), второй слой после запуска без оболочки.
//
// Первый слой — сама форма: exec.run получает argv и запускает программу напрямую (execve), без sh -c, поэтому
// конвейеров, подстановок, перенаправлений и шаблонов нет. Здесь — правила над argv (та же функция живёт в панели,
// apps/api/src/modules/ai/operator/policy/exec-policy.ts, общий набор — proto/testdata/exec-policy.json):
//   - форма слов: 1–64, вместе до 2000 знаков UTF-16, без знаков Cc и Cf (C1, смена направления, невидимые),
//     U+2028, U+2029 и «$» (systemd подставляет $VAR
//     и ${VAR} в ExecStart, до 254 это не выключить); программа — абсолютный путь или имя без «/» и шаблонов;
//   - программы, которые сами выполняют чужой код или команду (оболочки, интерпретаторы, обёртки вроде sudo, env,
//     nice, xargs, find -exec, менеджеры пакетов языков, git, make…), — EXEC_RUNS_COMMANDS;
//   - запреты по смыслу (ключи SSH и sudo, firewall, журналы, секреты, Trassa, пользователи, диски, ядро,
//     перезагрузка, обратные оболочки) — по каждому слову в нескольких видах: как написано, значение после «=»,
//     после path.Clean и от каталога запуска.
//
// Агент дополнительно (Options.Resolve) проверяет пути после ссылок: у панели нет файловой системы сервера.
// Запреты не делают exec.run безопасной: это один слой из пяти.
package execpolicy

import (
	"path"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

// Коды запрета (как ExecDenyCode панели).
const (
	Unparseable      = "EXEC_UNPARSEABLE"
	RunsCommands     = "EXEC_RUNS_COMMANDS"
	SSHKeysOrSudo    = "EXEC_SSH_KEYS_OR_SUDO"
	FirewallOff      = "EXEC_FIREWALL_OFF"
	LogsOrAudit      = "EXEC_LOGS_OR_AUDIT"
	SecretsRead      = "EXEC_SECRETS_READ"
	TrassaAgent      = "EXEC_TRASSA_AGENT"
	UsersOrPasswords = "EXEC_USERS_OR_PASSWORDS"
	DiskDestroy      = "EXEC_DISK_DESTROY"
	ReverseShell     = "EXEC_REVERSE_SHELL"
	KernelModule     = "EXEC_KERNEL_MODULE"
	Reboot           = "EXEC_REBOOT"
	PackageDB        = "EXEC_PACKAGE_DB"
)

// Пределы формы.
const (
	MaxCommand = 2000
	MaxWords   = 64
)

// Verdict — итог проверки.
type Verdict struct {
	Allowed bool
	Code    string
	Detail  string
}

// Options — проверки, которые может сделать только агент.
type Options struct {
	// Resolve — путь после ссылок для абсолютного пути; ok = false — пути нет.
	Resolve func(p string) (string, bool)
	// Comm — имя процесса по PID (/proc/<pid>/comm); "" — нет процесса.
	Comm func(pid string) string
}

func utf16Len(s string) int {
	n := 0
	for _, r := range s {
		n += utf16.RuneLen(r)
	}
	return n
}

var progNameRe = regexp.MustCompile(`^[A-Za-z0-9._+-]+$`)

// CheckShape — форма argv (до смысла).
func CheckShape(argv []string) Verdict {
	if len(argv) == 0 || len(argv) > MaxWords {
		return deny(Unparseable, "argv: 1–64 words")
	}
	total := 0
	for _, w := range argv {
		total += utf16Len(w) + 1
		if !utf8.ValidString(w) {
			return deny(Unparseable, "argv is not UTF-8")
		}
		for _, r := range w {
			// Как панель: управляющие (Cc, включая C1), невидимые и меняющие направление текста (Cf) и разделители
			// строк — человек при подтверждении должен видеть ровно то, что запустится.
			if r == '$' || unicode.Is(unicode.Cc, r) || unicode.Is(unicode.Cf, r) || r == 0x2028 || r == 0x2029 {
				return deny(Unparseable, "control, invisible or bidi character or $ in argv")
			}
		}
	}
	if total-1 > MaxCommand {
		return deny(Unparseable, "argv longer than 2000")
	}
	prog := argv[0]
	switch {
	case strings.HasPrefix(prog, "/"):
		if path.Clean(prog) != prog || globRe.MatchString(prog) {
			return deny(Unparseable, "program path")
		}
	case !progNameRe.MatchString(prog) || prog == "." || prog == "..":
		return deny(Unparseable, "program must be an absolute path or a plain name")
	}
	return Verdict{Allowed: true}
}

func base(p string) string { return p[strings.LastIndexByte(p, '/')+1:] }

func set(words ...string) map[string]bool {
	m := make(map[string]bool, len(words))
	for _, w := range words {
		m[w] = true
	}
	return m
}

var (
	globRe = regexp.MustCompile(`[*?\[\]]`)
	// Оболочки, обёртки и программы, которые сами запускают команду или чужой код.
	runners = set(
		// оболочки
		"sh", "bash", "dash", "zsh", "ksh", "mksh", "csh", "tcsh", "fish", "ash", "busybox", "rbash",
		// обёртки и запуск от имени
		"env", "sudo", "su", "doas", "pkexec", "runuser", "nice", "nohup", "ionice", "timeout", "stdbuf", "chroot",
		"setsid", "nsenter", "unshare", "flock", "setpriv", "capsh", "chrt", "taskset", "prlimit", "strace", "ltrace",
		"cgexec", "firejail", "numactl", "unbuffer", "watch", "script", "time", "xargs", "parallel", "systemd-run",
		"start-stop-daemon", "sg", "newgrp", "sshpass", "gdb", "valgrind", "perf",
		"systemd-cat", "systemd-inhibit", "systemd-nspawn", "machinectl", "setarch", "linux32", "linux64", "i386",
		"x86_64", "logsave", "ssh-agent", "dbus-run-session", "dbus-launch", "dbus-send", "busctl", "gdbus",
		"run-parts", "chpst", "sudoedit", "pkill", "killall", "pgrep", "fakeroot", "faketime", "catchsegv",
		"eatmydata", "torsocks", "proxychains", "proxychains4", "rlwrap", "chronic", "ifne", "vipe",
		"lckdo", "daemonize", "cpulimit", "trickle", "openvt",
		// запуск по расписанию и удалённо
		"at", "batch", "crontab", "ssh", "scp", "sftp", "rsync", "tmux", "screen",
		// редакторы с командами и сборка
		"vi", "vim", "nvim", "vim.basic", "vim.tiny", "emacs", "ed", "ex", "make", "git",
		// менеджеры пакетов языков (выполняют скрипты установки)
		"pip", "pip3", "pipx", "npm", "npx", "yarn", "pnpm", "gem", "bundle", "cargo", "go", "composer",
	)
	// Интерпретаторы: только «--version».
	interpreterRe = regexp.MustCompile(`^(python[0-9.]*|perl[0-9.]*|ruby[0-9.]*|node|nodejs|php[0-9.]*|php-cgi|lua[0-9.]*|luajit|tclsh[0-9.]*|wish|rscript|r|julia|deno|bun|jshell|java|irb|pwsh|expect|awk|gawk|mawk|nawk)$`)
	ldSoRe        = regexp.MustCompile(`^ld(-linux[-_.a-z0-9]*)?\.so(\.\d+)?$`)
	versionArgs   = set("--version", "-V", "-v", "version")
	tarExec       = regexp.MustCompile(`^(--to-command|--checkpoint-action|--use-compress-program|--info-script|--new-volume-script|--rsh-command|-I|-F)`)
	aptOpts       = regexp.MustCompile(`^(-o|--option|-c|--config-file)`)
	dpkgInstall   = set("-i", "--install", "--unpack", "-R", "--recursive")
	dockerAllowed = set("ps", "logs", "restart", "start", "stop", "inspect", "stats", "top", "images", "info", "version",
		"system", "volume", "network", "compose", "container", "image")
	dockerSubDeny = set("run", "exec", "create", "cp", "build", "buildx", "commit", "load", "import", "plugin", "attach",
		"debug", "up", "rm", "rmi", "update", "kill", "pause", "unpause", "prune")
	systemctlDeny = set("edit", "set-environment", "import-environment", "link", "revert", "set-property",
		"daemon-reexec", "switch-root", "isolate")
	powerUnit = regexp.MustCompile(`^(reboot|poweroff|halt|kexec|rescue|emergency|ctrl-alt-del|soft-reboot|exit)(\.target|\.service)?$`)
	dpkgDB    = regexp.MustCompile(`^/var/lib/dpkg(/|$)`)
	findExec  = set("-exec", "-execdir", "-ok", "-okdir")

	firewalls   = set("ufw", "nft", "iptables", "ip6tables", "iptables-restore", "ip6tables-restore", "firewall-cmd", "iptables-nft", "iptables-legacy")
	logUnits    = regexp.MustCompile(`^(systemd-journald|journald|rsyslog|syslog-ng|auditd|ufw|nftables|firewalld|netfilter-persistent|iptables)(\.service|\.socket)?$`)
	svcDown     = set("stop", "disable", "mask", "kill")
	userTools   = set("useradd", "adduser", "usermod", "userdel", "deluser", "passwd", "chpasswd", "chage", "groupadd", "groupmod", "groupdel", "gpasswd", "visudo", "newusers", "vipw", "vigr", "chsh", "chfn")
	diskTools   = regexp.MustCompile(`^(mkfs(\..+)?|mke2fs|mkswap|wipefs|fdisk|sfdisk|cfdisk|parted|sgdisk|gdisk|shred|blkdiscard|dd|losetup|cryptsetup|pvremove|vgremove|lvremove|mdadm)$`)
	kernelTools = set("insmod", "modprobe", "rmmod", "kexec", "depmod")
	powerTools  = set("reboot", "shutdown", "poweroff", "halt", "init", "telinit")
	reverse     = set("nc", "ncat", "netcat", "socat", "telnet")
	readers     = set("cat", "grep", "less", "head", "tail", "stat", "ls", "sshd", "wc", "diff")
	logRmTools  = set("rm", "truncate", "shred", "unlink", "find", "mv")
	devWriters  = set("cp", "cat", "tee", "mv", "install", "ln")
	fwOff       = set("disable", "reset", "stop", "flush", "-F", "--flush", "-X", "--delete-chain", "delete", "--panic-off")

	trassaRe    = regexp.MustCompile(`(?i)(^|/)(trassa[-_.\w]*)|/etc/trassa|/var/lib/trassa|/opt/trassa|/run/trassa|/usr/local/lib/trassa`)
	secretPaths = regexp.MustCompile(`(?i)(^/etc/shadow|^/etc/gshadow|\.ssh/|(^|/)id_(rsa|ed25519|ecdsa|dsa)|\.pem$|\.key$|\.p12$|\.pfx$|/etc/ssl/private|/etc/letsencrypt/(live|archive)/|(^|/)\.env($|\.)|/proc/(\d+|self|thread-self)/(environ|mem|maps)|\.bash_history|\.zsh_history|(^|/)\.?htpasswd|/etc/ssh/ssh_host_.*_key)`)
	sshSudo     = regexp.MustCompile(`(?i)(authorized_keys|sshd_config|sudoers)`)
	devices     = regexp.MustCompile(`^/dev/(sd|nvme|vd|xvd|hd|mmcblk|md|dm-|loop|mapper/|disk/)`)
	devTCP      = regexp.MustCompile(`^/dev/(tcp|udp)/`)
	reverseArg  = regexp.MustCompile(`(?i)^exec:|^system:`)
	logRm       = regexp.MustCompile(`^/var/log(/|$)|\.bash_history|/var/log/audit`)
	journalOff  = regexp.MustCompile(`^--(vacuum|rotate|flush)`)
	rmRecursive = regexp.MustCompile(`^(-[a-zA-Z]*[rR]|--recursive)`)
	rmRootArg   = regexp.MustCompile(`^/(\*|bin|boot|etc|lib|lib32|lib64|libx32|opt|root|sbin|srv|usr|var|home)?/?$`)
	sysctlKern  = regexp.MustCompile(`kernel\.modules_disabled|kexec`)
	powerVerb   = regexp.MustCompile(`^(reboot|poweroff|halt|kexec|rescue|emergency|soft-reboot)$`)
	fwUnits     = regexp.MustCompile(`ufw|nft|firewalld|iptables|netfilter`)
)

// Variants — слово как написано, значение после «=», после path.Clean и от каталога запуска.
func Variants(a, cwd string) []string {
	words := []string{a}
	if i := strings.IndexByte(a, '='); i >= 0 && i+1 < len(a) {
		words = append(words, a[i+1:])
	}
	out := make([]string, 0, 4)
	for _, w := range words {
		out = append(out, w)
		if strings.Contains(w, "/") {
			if c := path.Clean(w); c != w {
				out = append(out, c)
			}
		}
		if cwd != "" && w != "" && !strings.HasPrefix(w, "/") && !strings.HasPrefix(w, "-") {
			out = append(out, path.Join(cwd, w))
		}
	}
	return out
}

type checker struct {
	cwd     string
	resolve func(string) (string, bool)
	comm    func(string) string
}

// forms — все виды слова, с путями после ссылок (агент).
func (c checker) forms(a string) []string {
	out := Variants(a, c.cwd)
	if c.resolve != nil {
		for _, v := range out {
			if strings.HasPrefix(v, "/") {
				if r, ok := c.resolve(v); ok && r != v {
					out = append(out, r)
				}
			}
		}
	}
	return out
}

func (c checker) any(words []string, f func(string) bool) bool {
	for _, w := range words {
		for _, v := range c.forms(w) {
			if f(v) {
				return true
			}
		}
	}
	return false
}

func anyWord(words []string, f func(string) bool) bool {
	for _, w := range words {
		if f(w) {
			return true
		}
	}
	return false
}

// Check — argv в каталоге запуска cwd (абсолютный; "" — «/»). Программа проверяется по имени как написано и, у
// агента, по имени файла после ссылок (/usr/bin/vi → vim.basic).
func Check(argv []string, cwd string, o Options) Verdict {
	if v := CheckShape(argv); !v.Allowed {
		return v
	}
	if cwd == "" {
		cwd = "/"
	}
	c := checker{cwd: cwd, resolve: o.Resolve, comm: o.Comm}
	names := []string{strings.ToLower(base(argv[0]))}
	if c.resolve != nil && strings.HasPrefix(argv[0], "/") {
		if r, ok := c.resolve(argv[0]); ok && !strings.EqualFold(base(r), base(argv[0])) {
			names = append(names, strings.ToLower(base(r)))
		}
	}
	for _, p := range names {
		if v := c.program(p, argv, argv[1:]); !v.Allowed {
			return v
		}
	}
	return Verdict{Allowed: true}
}

func (c checker) program(p string, argv, args []string) Verdict {
	if c.any(argv, trassaRe.MatchString) {
		return deny(TrassaAgent, "Trassa agent files and services are off limits")
	}
	if p == "kill" {
		// kill -1 — все процессы, включая Trassa; PID процесса Trassa (только агент знает имена процессов).
		for _, a := range args {
			if a == "-1" {
				return deny(TrassaAgent, "kill -1 stops every process")
			}
			if pid := strings.TrimPrefix(a, "-"); c.comm != nil && pid != "" && strings.Trim(pid, "0123456789") == "" {
				if strings.HasPrefix(c.comm(pid), "trassa") {
					return deny(TrassaAgent, "Trassa process")
				}
			}
		}
	}
	if runners[p] || ldSoRe.MatchString(p) {
		return deny(RunsCommands, p+" runs other commands")
	}
	if interpreterRe.MatchString(p) {
		if len(args) == 1 && versionArgs[args[0]] {
			return Verdict{Allowed: true}
		}
		return deny(RunsCommands, p+" runs code")
	}
	if v := c.runsViaOptions(p, args); !v.Allowed {
		return v
	}
	if reverse[p] && anyWord(args, func(a string) bool { return a == "-e" || a == "-c" || reverseArg.MatchString(a) }) {
		return deny(ReverseShell, p)
	}
	if c.any(argv, devTCP.MatchString) {
		return deny(ReverseShell, "/dev/tcp")
	}
	if c.any(argv, sshSudo.MatchString) && !readers[p] {
		return deny(SSHKeysOrSudo, "authorized_keys, sshd_config and sudoers are changed only by typed operations")
	}
	if logRmTools[p] && c.any(args, logRm.MatchString) {
		return deny(LogsOrAudit, "log removal")
	}
	if c.any(args, dpkgDB.MatchString) {
		return deny(PackageDB, "the package database is changed only by apt and dpkg")
	}
	if c.any(args, secretPaths.MatchString) {
		return deny(SecretsRead, "secrets, keys and env files")
	}
	if firewalls[p] {
		policyAccept := false
		for j, a := range args {
			if (a == "-P" || a == "--policy") && j+2 < len(args) && args[j+2] == "ACCEPT" {
				policyAccept = true
			}
		}
		if anyWord(args, func(a string) bool { return fwOff[a] }) || policyAccept {
			return deny(FirewallOff, strings.TrimSpace(p+" "+strings.Join(args, " ")))
		}
	}
	if v := checkService(p, args); !v.Allowed {
		return v
	}
	if p == "journalctl" && anyWord(args, journalOff.MatchString) {
		return deny(LogsOrAudit, "journalctl vacuum")
	}
	if p == "auditctl" && anyWord(args, func(a string) bool { return a == "-D" || a == "-e" }) {
		return deny(LogsOrAudit, p)
	}
	if userTools[p] {
		return deny(UsersOrPasswords, p)
	}
	ddOut := func() bool {
		for _, a := range args {
			if strings.HasPrefix(a, "of=") && c.any([]string{a[3:]}, func(v string) bool { return strings.HasPrefix(v, "/dev/") }) {
				return true
			}
		}
		return false
	}
	if diskTools.MatchString(p) && (p != "dd" || ddOut()) {
		return deny(DiskDestroy, p)
	}
	if devWriters[p] && c.any(args, devices.MatchString) {
		return deny(DiskDestroy, "write to a block device")
	}
	if p == "rm" && anyWord(args, rmRecursive.MatchString) &&
		(anyWord(args, func(a string) bool { return a == "--no-preserve-root" }) || c.any(args, rmRootArg.MatchString)) {
		return deny(DiskDestroy, "rm -r of a system root")
	}
	if (p == "chmod" || p == "chown" || p == "chgrp") && c.any(args, func(a string) bool { return a == "/" }) {
		return deny(DiskDestroy, p+" /")
	}
	if kernelTools[p] {
		return deny(KernelModule, p)
	}
	if p == "sysctl" && anyWord(args, sysctlKern.MatchString) {
		return deny(KernelModule, "sysctl")
	}
	if powerTools[p] || (p == "systemctl" && anyWord(args, powerVerb.MatchString)) {
		return deny(Reboot, "use the typed operation system.reboot")
	}
	return Verdict{Allowed: true}
}

// runsViaOptions — программы, которые запускают чужую команду через опции.
func (c checker) runsViaOptions(p string, args []string) Verdict {
	switch p {
	case "find":
		if anyWord(args, func(a string) bool { return findExec[a] }) {
			return deny(RunsCommands, "find -exec")
		}
	case "tar":
		if anyWord(args, tarExec.MatchString) {
			return deny(RunsCommands, "tar runs a program")
		}
	case "zip":
		if anyWord(args, func(a string) bool { return a == "-TT" || strings.HasPrefix(a, "--unzip-command") }) {
			return deny(RunsCommands, "zip runs a program")
		}
	case "sed":
		// GNU sed выполняет команды оболочки (e, s///e); --sandbox их выключает.
		if !anyWord(args, func(a string) bool { return a == "--sandbox" }) {
			return deny(RunsCommands, "sed only with --sandbox")
		}
	case "apt", "apt-get", "aptitude", "apt-cache":
		if anyWord(args, aptOpts.MatchString) || anyWord(args, func(a string) bool { return strings.HasSuffix(a, ".deb") }) {
			return deny(RunsCommands, p+": options and local packages run scripts")
		}
	case "dpkg":
		if anyWord(args, func(a string) bool { return dpkgInstall[a] || strings.HasSuffix(a, ".deb") }) {
			return deny(RunsCommands, "dpkg install runs package scripts")
		}
	case "docker":
		return checkDocker(args)
	case "systemctl":
		if anyWord(args, func(a string) bool { return systemctlDeny[a] }) {
			return deny(RunsCommands, "systemctl "+strings.Join(args, " "))
		}
	case "ip":
		// ip netns exec, ip vrf exec — запуск команды.
		if anyWord(args, func(a string) bool { return a == "exec" }) {
			return deny(RunsCommands, "ip … exec")
		}
	case "man":
		if anyWord(args, func(a string) bool {
			return strings.HasPrefix(a, "-P") || strings.HasPrefix(a, "--pager") || strings.HasPrefix(a, "-H") || strings.HasPrefix(a, "--html")
		}) {
			return deny(RunsCommands, "man pager")
		}
	}
	return Verdict{Allowed: true}
}

func checkService(p string, args []string) Verdict {
	if p != "systemctl" && p != "service" {
		return Verdict{Allowed: true}
	}
	var verb string
	var units []string
	if p == "service" {
		units, verb = []string{at(args, 0)}, at(args, 1)
	} else {
		for _, a := range args {
			if strings.HasPrefix(a, "-") {
				continue
			}
			if verb == "" {
				verb = a
			} else {
				units = append(units, a)
			}
		}
	}
	if anyWord(units, globRe.MatchString) {
		return deny(Unparseable, "unit name pattern")
	}
	if anyWord(units, trassaRe.MatchString) {
		return deny(TrassaAgent, "Trassa units")
	}
	if p == "systemctl" && anyWord(units, powerUnit.MatchString) {
		return deny(Reboot, "use the typed operation system.reboot")
	}
	if verb != "" && svcDown[verb] && anyWord(units, logUnits.MatchString) {
		code := LogsOrAudit
		if fwUnits.MatchString(strings.Join(units, " ")) {
			code = FirewallOff
		}
		return deny(code, p+" "+verb)
	}
	return Verdict{Allowed: true}
}

// checkDocker — только просмотр и управление существующими контейнерами: run, exec, cp, build и чужой демон
// (-H, --host, --context, --config) дают root на сервере.
func checkDocker(args []string) Verdict {
	var subs []string
	for _, a := range args {
		if a == "-H" || a == "-c" || strings.HasPrefix(a, "--host") || strings.HasPrefix(a, "--context") ||
			strings.HasPrefix(a, "--config") {
			return deny(RunsCommands, "docker: another daemon or config")
		}
		if !strings.HasPrefix(a, "-") {
			subs = append(subs, a)
		}
	}
	if len(subs) == 0 {
		return Verdict{Allowed: true}
	}
	if !dockerAllowed[subs[0]] || anyWord(subs, func(s string) bool { return dockerSubDeny[s] }) {
		return deny(RunsCommands, "docker "+strings.Join(subs, " "))
	}
	return Verdict{Allowed: true}
}

func at(a []string, i int) string {
	if i < len(a) {
		return a[i]
	}
	return ""
}

func deny(code, detail string) Verdict { return Verdict{Code: code, Detail: detail} }
