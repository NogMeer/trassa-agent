// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"fmt"
	"strings"
	"unicode"
)

// Lang — язык сообщений CLI: русский или английский по LC_ALL, LC_MESSAGES, LANG (как у gettext).
type Lang int

const (
	LangEN Lang = iota
	LangRU
)

// DetectLang — первая непустая переменная из LC_ALL, LC_MESSAGES, LANG; «ru…» — русский, иначе английский.
func DetectLang(env func(string) string) Lang {
	for _, k := range []string{"LC_ALL", "LC_MESSAGES", "LANG"} {
		if v := env(k); v != "" {
			if strings.HasPrefix(strings.ToLower(v), "ru") {
				return LangRU
			}
			return LangEN
		}
	}
	return LangEN
}

// locale — значение lang для POST /access/sessions (оболочка на сервере).
func (l Lang) locale() string {
	if l == LangRU {
		return "ru_RU.UTF-8"
	}
	return "en_US.UTF-8"
}

// messages — строки интерфейса CLI: ключ → {RU, EN}.
var messages = map[string][2]string{
	"err.prefix":          {"trassa: %s", "trassa: %s"},
	"err.url_bad":         {"адрес панели должен быть https://… без пути (http — только localhost)", "the panel address must be https://… without a path (http only for localhost)"},
	"err.no_url":          {"не задан адрес панели: trassa login --url https://app.example.com", "no panel address: trassa login --url https://app.example.com"},
	"err.not_logged_in":   {"вход не выполнен: trassa login", "not signed in: trassa login"},
	"err.relogin":         {"вход CLI отозван или истёк: выполните trassa login", "the CLI sign-in was revoked or has expired: run trassa login"},
	"err.network":         {"панель недоступна: %v", "the panel is unreachable: %v"},
	"err.api":             {"панель ответила %d %s: %s", "the panel answered %d %s: %s"},
	"err.denied":          {"вход отклонён в панели", "the sign-in was denied in the panel"},
	"err.code_expired":    {"код истёк, запустите trassa login снова", "the code has expired, run trassa login again"},
	"err.bad_response":    {"панель прислала неожиданный ответ: %s", "the panel sent an unexpected response: %s"},
	"err.no_grant":        {"У вас нет доступа к этому серверу. Попросите администратора", "You have no access to this server. Ask an administrator"},
	"err.ambiguous":       {"под «%s» подходит несколько серверов, укажите id: %s", "several servers match “%s”, give the id: %s"},
	"err.pick_login":      {"на сервере несколько логинов, выберите: -l %s", "the server has several logins, pick one: -l %s"},
	"err.login_unknown":   {"логина %s на этом сервере у вас нет; есть: %s", "you have no login %s on this server; available: %s"},
	"err.ws_pick":         {"вы участник нескольких пространств, укажите --workspace: %s", "you are a member of several workspaces, pass --workspace: %s"},
	"err.ws_unknown":      {"пространство %s не найдено среди ваших: %s", "workspace %s is not among yours: %s"},
	"err.ws_none":         {"у аккаунта нет пространств", "the account has no workspaces"},
	"err.direct_disabled": {"в пространстве включена обязательная запись: прямой вход выключен, используйте trassa ssh без --direct", "recording is required in this workspace: direct sign-in is off, use trassa ssh without --direct"},
	"err.mfa":             {"для доступа к серверам нужен второй фактор: включите его в панели", "server access needs a second factor: turn it on in the panel"},
	"err.step_up":         {"для логина с правами администратора подтвердите вход вторым фактором: выполните trassa login снова", "admin logins need a recent second-factor check: run trassa login again"},
	"err.not_ready":       {"доступ на сервере ещё настраивается, попробуйте через минуту", "access on this server is still being set up, try again in a minute"},
	"err.offline":         {"сервер не на связи с Trassa", "the server is not connected to Trassa"},
	"err.plan":            {"доступ по SSH не входит в тариф пространства", "SSH access is not included in the workspace plan"},
	"err.direct_windows":  {"на Windows доступен только вход через Trassa: trassa ssh без --direct", "on Windows only the Trassa mode is available: trassa ssh without --direct"},
	"err.no_ssh":          {"не найдена программа ssh (OpenSSH)", "the ssh program (OpenSSH) was not found"},
	"err.no_address":      {"у сервера нет публичного адреса для прямого входа: используйте trassa ssh без --direct", "the server has no public address for direct sign-in: use trassa ssh without --direct"},
	"err.no_host_keys":    {"ключи сервера ещё неизвестны панели: прямой вход без проверки ключа не выполняется", "the panel does not know the server keys yet: direct sign-in without a host key check is refused"},
	"err.cert_bad":        {"панель прислала сертификат не для этого ключа", "the panel sent a certificate for another key"},
	"err.tmp_path":        {"временный каталог %s содержит недопустимые символы, задайте TMPDIR", "the temporary directory %s has unsupported characters, set TMPDIR"},
	"err.session_closed":  {"сессия закрыта: %s", "the session was closed: %s"},
	"err.revoked":         {"доступ отозван администратором", "access was revoked by an administrator"},
	"err.idle":            {"сессия закрыта по простою", "the session was closed for inactivity"},
	"err.replaced":        {"сессия открыта в другом окне", "the session was opened in another window"},
	"err.lost_for_good":   {"связь с сервером не вернулась", "the connection to the server did not come back"},
	"err.pass_expired":    {"срок доступа закончился", "the access period has ended"},
	"err.unavailable":     {"панель временно не может открыть терминал, попробуйте позже", "the panel cannot open the terminal right now, try later"},
	"err.remote_relay":    {"команда после -- выполняется только с --direct; через Trassa открывается терминал", "a command after -- runs only with --direct; the Trassa mode opens a terminal"},
	"err.usage":           {"неверные аргументы. trassa help — список команд", "bad arguments. trassa help lists the commands"},

	"login.started":   {"Откройте в браузере, где вы вошли в панель:\n  %s\nи сверьте код: %s\n", "Open in the browser where you are signed in to the panel:\n  %s\nand check the code: %s\n"},
	"login.waiting":   {"Ждём подтверждения (до %s)…\n", "Waiting for approval (until %s)…\n"},
	"login.done":      {"Вход выполнен: %s (%s). Токен сохранён: %s.\n", "Signed in: %s (%s). The token is stored in: %s.\n"},
	"login.ws":        {"Пространство по умолчанию: %s\n", "Default workspace: %s\n"},
	"login.ws_many":   {"Пространств несколько, выберите: trassa use <пространство>\n", "You have several workspaces, choose one: trassa use <workspace>\n"},
	"login.old":       {"прежний вход CLI не отозван: %v", "the previous CLI sign-in was not revoked: %v"},
	"store.keyring":   {"системное хранилище ключей", "the system keyring"},
	"store.file":      {"файл %s (системное хранилище недоступно: %v)", "file %s (the system keyring is unavailable: %v)"},
	"logout.done":     {"Вход CLI отозван, токен удалён.\n", "The CLI sign-in is revoked and the token is removed.\n"},
	"logout.local":    {"Токен удалён с этого компьютера, но панель недоступна: отзовите вход в «Доступ и SSH» → «Со своего компьютера» (%v)\n", "The token is removed from this computer, but the panel is unreachable: revoke the sign-in in “Access and SSH” → “From your computer” (%v)\n"},
	"logout.none":     {"Вход не выполнен.\n", "Not signed in.\n"},
	"whoami.user":     {"%s <%s>\n", "%s <%s>\n"},
	"whoami.session":  {"Вход CLI: %s, действует до %s\n", "CLI sign-in: %s, valid until %s\n"},
	"whoami.panel":    {"Панель: %s\n", "Panel: %s\n"},
	"whoami.ws_head":  {"Пространства:\n", "Workspaces:\n"},
	"use.done":        {"Пространство по умолчанию: %s\n", "Default workspace: %s\n"},
	"servers.head":    {"СЕРВЕР\tСВЯЗЬ\tЛОГИНЫ\tID\n", "SERVER\tSTATUS\tLOGINS\tID\n"},
	"servers.online":  {"на связи", "online"},
	"servers.offline": {"нет связи", "offline"},
	"servers.empty":   {"Доступных серверов нет. Попросите администратора выдать доступ.\n", "No servers are available. Ask an administrator for access.\n"},
	"servers.pending": {"настраивается", "setting up"},
	"servers.until":   {"до %s", "until %s"},

	"ssh.relay":       {"Подключение к %s как %s через Trassa.\r\n", "Connecting to %s as %s through Trassa.\r\n"},
	"ssh.recording":   {"Сессия записывается.\r\n", "The session is recorded.\r\n"},
	"ssh.rec_off":     {"Запись сейчас недоступна, сессия не записывается.\r\n", "Recording is unavailable right now, the session is not recorded.\r\n"},
	"ssh.lost":        {"\r\nСвязь с сервером потеряна. Пробуем снова…\r\n", "\r\nThe connection to the server was lost. Retrying…\r\n"},
	"ssh.back":        {"Связь вернулась.\r\n", "The connection is back.\r\n"},
	"ssh.direct":      {"Сертификат для %s выдан до %s. Запускаем ssh %s@%s.\n", "The certificate for %s is valid until %s. Starting ssh %s@%s.\n"},
	"ssh.sudo":        {"с правами администратора", "with admin rights"},
	"help":            {helpRU, helpEN},
	"version":         {"trassa %s\n", "trassa %s\n"},
	"keyring.warn":    {"внимание: %s\n", "warning: %s\n"},
	"keyring.fileuse": {"токен хранится в файле %s с правами 0600", "the token is stored in %s with mode 0600"},
}

const helpRU = `trassa — вход на свои серверы через Trassa.

  trassa login [--url https://app.example.com] [--name имя]   войти: код подтверждается в панели
  trassa logout                                                отозвать вход и удалить токен
  trassa whoami                                                кто вошёл и какие пространства
  trassa use <пространство>                                    пространство по умолчанию
  trassa servers [-w пространство]                             доступные вам серверы и логины
  trassa ssh [-w пространство] [-l логин] [--direct] <сервер> [-- команда]
        без --direct — через Trassa (открытый порт SSH не нужен, сессия записывается, если включено);
        --direct — сертификат на 10 минут и системный ssh напрямую к серверу (macOS, Linux)
  trassa version
`

const helpEN = `trassa — sign in to your servers through Trassa.

  trassa login [--url https://app.example.com] [--name name]   sign in: approve the code in the panel
  trassa logout                                                revoke the sign-in and remove the token
  trassa whoami                                                who is signed in and which workspaces
  trassa use <workspace>                                       default workspace
  trassa servers [-w workspace]                                servers and logins available to you
  trassa ssh [-w workspace] [-l login] [--direct] <server> [-- command]
        without --direct — through Trassa (no open SSH port needed, recorded when turned on);
        --direct — a 10-minute certificate and the system ssh straight to the server (macOS, Linux)
  trassa version
`

func (l Lang) t(key string, args ...any) string {
	m, ok := messages[key]
	if !ok {
		return key
	}
	s := m[1]
	if l == LangRU {
		s = m[0]
	}
	if len(args) == 0 {
		return s
	}
	return fmt.Sprintf(s, args...)
}

// clean — строка от панели перед выводом в терминал: без управляющих символов и символов формата (escape-
// последовательности и смена направления текста подменили бы то, что видит человек).
func clean(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, s)
}

// Help — справка по командам.
func Help(l Lang) string { return l.t("help") }

// Usage — ошибка разбора аргументов.
func Usage(l Lang) string { return l.t("err.usage") }
