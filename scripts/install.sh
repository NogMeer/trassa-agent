#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
#
# Установка агента Trassa (E05-T21). Запуск от root:
#
#   curl -fsSL --proto '=https' https://agents.<домен>/install.sh | sudo TRASSA_ENROLL_TOKEN=trs_enr_… sh -s -- --url https://agents.<домен>
#
# Или сначала скачать и проверить: sha256 этого файла опубликован в README агента.
#
# Что делает: проверяет систему до любых изменений; скачивает выпуск; проверяет подпись minisign файла SHA256SUMS
# средствами openssl (decisions п. 9) и контрольные суммы бинарников; создаёт пользователя trassa, каталоги и две
# службы; регистрирует сервер одноразовым токеном. Повторный запуск безопасен: зарегистрированный агент не
# трогается, недоустановленный доустанавливается.
#
# Коды выхода: 0 — готово; 1 — ошибка; 2 — токен недействителен; 3 — подпись или сумма выпуска не сошлась
# (скачанное удалено, ничего не установлено); 4 — система не поддерживается.

set -eu

# Открытые ключи minisign выпусков через пробел (те же, что internal/update.ReleaseKeys). Два ключа — для ротации
# (R12). Пустой список — установка невозможна: без ключа подпись не «пропускается».
# Ключ 1 — trassa-release-1, key_id 9889674CCEE25046 (создан 2026-11-23 на машине разработчика, до первых клиентов —
# ротация на офлайн-ключ). Второе место — под будущий офлайн-ключ trassa-release-2: дописывается через пробел.
TRASSA_RELEASE_KEYS="RWRGUOLOTGeJmFfIFOk0UF9AXhgfoh1qZK2h8eRTZNCa23uNDmvfNCSp"

BIN_DIR=/usr/local/bin
UNIT_DIR=/etc/systemd/system
STATE_DIR=/var/lib/trassa
ETC_DIR=/etc/trassa
SUPPORTED="Ubuntu 22.04, Ubuntu 24.04, Debian 12, Debian 13; amd64, arm64"

say() { printf '%s\n' "$*"; }
die() {
	code=$1
	shift
	printf 'Ошибка: %s\n' "$*" >&2
	exit "$code"
}

# ---------- Проверка подписи minisign через openssl ----------

# b64file <base64> <файл> — раскодировать строку в файл.
b64file() { printf '%s' "$1" | base64 -d >"$2" 2>/dev/null; }

# bytes <файл> <смещение> <длина> — вырезать байты.
bytes() { dd if="$1" bs=1 skip="$2" count="$3" 2>/dev/null; }

hex() { od -An -v -tx1 | tr -d ' \n'; }

# key_pem <ключ minisign> <файл.pem> — ключ «Ed || key_id(8) || pk(32)» в PEM SPKI Ed25519; печатает key_id.
key_pem() {
	kd=$(mktemp -d)
	if ! b64file "$1" "$kd/k" || [ "$(wc -c <"$kd/k" | tr -d ' ')" -ne 42 ] || [ "$(bytes "$kd/k" 0 2 | hex)" != "4564" ]; then
		rm -rf "$kd"
		return 1
	fi
	{
		# Префикс DER SubjectPublicKeyInfo для Ed25519: 30 2a 30 05 06 03 2b 65 70 03 21 00.
		printf '\060\052\060\005\006\003\053\145\160\003\041\000'
		bytes "$kd/k" 10 32
	} >"$kd/der"
	if [ "$(wc -c <"$kd/der" | tr -d ' ')" -ne 44 ]; then
		rm -rf "$kd"
		return 1
	fi
	{
		say "-----BEGIN PUBLIC KEY-----"
		base64 <"$kd/der" | tr -d '\n'
		say ""
		say "-----END PUBLIC KEY-----"
	} >"$2"
	bytes "$kd/k" 2 8 | hex
	rm -rf "$kd"
}

# verify_minisig <файл> <файл.minisig> <версия> — подпись файла (алгоритм ED: Ed25519 над BLAKE2b-512) и
# глобальная подпись доверенного комментария «trassa-agent <версия>». Ноль — подпись верна.
# Каждый шаг проверяется явно: внутри условия (if, ||) «set -e» в sh не действует.
verify_minisig() {
	[ -n "$TRASSA_RELEASE_KEYS" ] || return 1
	vd=$(mktemp -d) || return 1
	if verify_in "$vd" "$1" "$2" "trassa-agent $3"; then
		rm -rf "$vd"
		return 0
	fi
	rm -rf "$vd"
	return 1
}

verify_in() {
	vd=$1
	file=$2
	sigf=$3
	want=$4
	[ "$(wc -l <"$sigf" | tr -d ' ')" -ge 4 ] || return 1
	line2=$(sed -n 2p "$sigf")
	line3=$(sed -n 3p "$sigf")
	line4=$(sed -n 4p "$sigf")
	b64file "$line2" "$vd/sig" || return 1
	[ "$(wc -c <"$vd/sig" | tr -d ' ')" -eq 74 ] || return 1
	# Только «ED» (с предварительным хэшем); «Ed» без хэша отклоняется.
	[ "$(bytes "$vd/sig" 0 2 | hex)" = "4544" ] || return 1
	kid=$(bytes "$vd/sig" 2 8 | hex)
	bytes "$vd/sig" 10 64 >"$vd/s" || return 1
	case "$line3" in
	"trusted comment: "*) comment=${line3#trusted comment: } ;;
	*) return 1 ;;
	esac
	[ "$comment" = "$want" ] || return 1
	b64file "$line4" "$vd/g" || return 1
	[ "$(wc -c <"$vd/g" | tr -d ' ')" -eq 64 ] || return 1
	found=0
	for k in $TRASSA_RELEASE_KEYS; do
		pkid=$(key_pem "$k" "$vd/key.pem") || continue
		if [ "$pkid" = "$kid" ]; then
			found=1
			break
		fi
	done
	[ "$found" = 1 ] || return 1
	openssl dgst -blake2b512 -binary "$file" >"$vd/h" || return 1
	[ "$(wc -c <"$vd/h" | tr -d ' ')" -eq 64 ] || return 1
	openssl pkeyutl -verify -pubin -inkey "$vd/key.pem" -rawin -in "$vd/h" -sigfile "$vd/s" >/dev/null 2>&1 || return 1
	{
		cat "$vd/s"
		printf '%s' "$comment"
	} >"$vd/global" || return 1
	openssl pkeyutl -verify -pubin -inkey "$vd/key.pem" -rawin -in "$vd/global" -sigfile "$vd/g" >/dev/null 2>&1 || return 1
	return 0
}

# check_sum <SHA256SUMS> <имя> <файл> — сумма файла равна строке SHA256SUMS для имени.
check_sum() {
	want=$(awk -v n="$2" '($2 == n || $2 == "*" n) && length($1) == 64 { print $1 }' "$1")
	[ -n "$want" ] || return 1
	[ "$(printf '%s\n' "$want" | wc -l | tr -d ' ')" -eq 1 ] || return 1
	got=$(sha256sum "$3" | awk '{ print $1 }')
	[ "$got" = "$want" ]
}

# ---------- Проверки системы (до любых изменений) ----------

detect_arch() {
	case $(uname -m) in
	x86_64 | amd64) echo amd64 ;;
	aarch64 | arm64) echo arm64 ;;
	*) return 1 ;;
	esac
}

check_os() {
	[ -r /etc/os-release ] || die 4 "Эта система пока не поддерживается: нет /etc/os-release. Список поддерживаемых: $SUPPORTED"
	# Значения читаются разбором, а не через «.»: файл не исполняется.
	id=$(sed -n 's/^ID=//p' /etc/os-release | tr -d '"' | head -n1)
	ver=$(sed -n 's/^VERSION_ID=//p' /etc/os-release | tr -d '"' | head -n1)
	case "$id:$ver" in
	ubuntu:22.04 | ubuntu:24.04 | debian:12 | debian:13) ;;
	*) die 4 "Эта система пока не поддерживается: $id $ver. Список поддерживаемых: $SUPPORTED" ;;
	esac
	ARCH=$(detect_arch) || die 4 "Эта система пока не поддерживается: архитектура $(uname -m). Список поддерживаемых: $SUPPORTED"
	[ -d /run/systemd/system ] || die 4 "Нужен systemd: эта система загружена без него"
	command -v curl >/dev/null 2>&1 || die 1 "Нет curl: установите его (apt-get install curl) и повторите"
	command -v openssl >/dev/null 2>&1 || die 1 "Нет openssl 3: установите его (apt-get install openssl) и повторите"
	ov=$(openssl version | awk '{ print $2 }')
	case "$ov" in
	[3-9].*) ;;
	*) die 1 "Нужен OpenSSL 3.0 или новее, установлен $ov" ;;
	esac
	for c in sha256sum base64 od dd awk sed systemctl useradd; do
		command -v "$c" >/dev/null 2>&1 || die 1 "Нет команды $c"
	done
}

usage() {
	say "Использование: TRASSA_ENROLL_TOKEN=trs_enr_… sh install.sh --url https://agents.<домен>"
	exit 1
}

fetch() {
	curl -fsSL --proto '=https' --tlsv1.2 --retry 2 --connect-timeout 15 --max-time 300 -o "$2" "$1"
}

main() {
	URL=""
	TOKEN=${TRASSA_ENROLL_TOKEN:-}
	while [ $# -gt 0 ]; do
		case "$1" in
		--url) [ $# -ge 2 ] || usage; URL=$2; shift 2 ;;
		--token) [ $# -ge 2 ] || usage; TOKEN=$2; shift 2 ;;
		*) usage ;;
		esac
	done
	[ "$(id -u)" -eq 0 ] || die 1 "Нужны права root: запустите через sudo"
	case "$URL" in
	https://*) ;;
	*) usage ;;
	esac
	# Только схема и хост с портом: никаких путей, учёток и спецсимволов оболочки.
	printf '%s' "$URL" | grep -Eq '^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?/?$' || die 1 "Адрес панели должен быть вида https://agents.<домен>"
	URL=${URL%/}
	printf '%s' "$TOKEN" | grep -Eq '^trs_enr_[A-Za-z0-9_-]{43}$' || die 2 "Срок действия команды истёк. Получите новую в панели"

	if [ -e "$ETC_DIR/enrollment.json" ]; then
		say "Агент Trassa уже установлен на этом сервере."
		say "Состояние: trassa-agent status. Удалить: trassa-agent uninstall"
		exit 0
	fi
	check_os
	[ -n "$TRASSA_RELEASE_KEYS" ] || die 3 "В этом скрипте нет ключей проверки выпуска: установка невозможна"

	TMP=$(mktemp -d)
	trap 'rm -rf "$TMP"' EXIT INT TERM

	say "Связываюсь с $URL…"
	if ! fetch "$URL/agent/v1/releases/current?os=linux&arch=$ARCH&channel=stable" "$TMP/manifest.json"; then
		die 1 "Не удалось связаться с $URL. Проверьте исходящий доступ на порт 443: часто его закрывает firewall в панели хостера"
	fi
	VERSION=$(tr -d '\n' <"$TMP/manifest.json" | sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
	SIG_URL=$(tr -d '\n' <"$TMP/manifest.json" | sed -n 's/.*"signatureUrl"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
	printf '%s' "$VERSION" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$' || die 1 "Панель вернула непонятную версию выпуска"
	printf '%s' "$SIG_URL" | grep -Eq '^https://[A-Za-z0-9.-]+(:[0-9]+)?/[A-Za-z0-9._~/-]*SHA256SUMS\.minisig$' || die 1 "Панель вернула непонятный адрес подписи"
	BASE=${SIG_URL%/SHA256SUMS.minisig}
	AGENT_BIN="trassa-agent-linux-$ARCH"
	HELPER_BIN="trassa-helper-linux-$ARCH"

	say "Скачиваю выпуск $VERSION…"
	for f in SHA256SUMS SHA256SUMS.minisig "$AGENT_BIN" "$HELPER_BIN"; do
		fetch "$BASE/$f" "$TMP/$f" || die 1 "Не удалось скачать $BASE/$f"
	done
	if ! verify_minisig "$TMP/SHA256SUMS" "$TMP/SHA256SUMS.minisig" "$VERSION"; then
		rm -rf "$TMP"
		die 3 "Подпись выпуска не сошлась. Скачанное удалено, ничего не установлено"
	fi
	for f in "$AGENT_BIN" "$HELPER_BIN"; do
		if ! check_sum "$TMP/SHA256SUMS" "$f" "$TMP/$f"; then
			rm -rf "$TMP"
			die 3 "Контрольная сумма $f не сошлась. Скачанное удалено, ничего не установлено"
		fi
	done

	say "Устанавливаю…"
	if ! id -u trassa >/dev/null 2>&1; then
		useradd --system --user-group --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin trassa
	fi
	install -d -m 0755 -o root -g root "$STATE_DIR"
	install -d -m 0750 -o root -g trassa "$ETC_DIR"
	install -d -m 0700 -o trassa -g trassa "$STATE_DIR/agent"
	# Локальные настройки (E20): exec.run выключена; существующий файл владельца не трогаем.
	if [ ! -e "$ETC_DIR/agent.toml" ]; then
		cat >"$ETC_DIR/.agent.toml.new" <<'TOML'
# Локальные настройки агента Trassa. Панель изменить этот файл не может.
# allow_exec = true разрешает ИИ-оператору произвольные команды (exec.run): каждый запуск всё равно
# подтверждается в панели и проходит запреты. После правки: systemctl restart trassa-helper trassa-agent.
allow_exec = false
TOML
		chown root:root "$ETC_DIR/.agent.toml.new"
		chmod 0644 "$ETC_DIR/.agent.toml.new"
		mv -f "$ETC_DIR/.agent.toml.new" "$ETC_DIR/agent.toml"
	fi
	# Бинарники — через временный файл в том же каталоге и mv: служба не увидит половину файла.
	for pair in "$AGENT_BIN:trassa-agent" "$HELPER_BIN:trassa-helper"; do
		src=${pair%%:*}
		dst=${pair##*:}
		install -m 0755 -o root -g root "$TMP/$src" "$BIN_DIR/.$dst.new"
		mv -f "$BIN_DIR/.$dst.new" "$BIN_DIR/$dst"
	done
	"$BIN_DIR/trassa-agent" version >/dev/null || die 1 "Скачанный агент не запускается на этой системе"
	write_units
	systemctl daemon-reload

	say "Регистрирую сервер…"
	set +e
	TRASSA_ENROLL_TOKEN=$TOKEN "$BIN_DIR/trassa-agent" enroll --url "$URL"
	rc=$?
	set -e
	case $rc in
	0) ;;
	2) exit 2 ;;
	4) exit 4 ;;
	*) die 1 "Регистрация не удалась. Повторите команду; если не поможет — получите новую в панели" ;;
	esac
	systemctl enable --now trassa-helper.service trassa-agent.service
	say "Готово: агент Trassa $VERSION установлен. Сервер появится в панели в течение нескольких секунд"
}

# Юниты — копия packaging/systemd/*.service (тест сверяет совпадение).
write_units() {
	cat >"$UNIT_DIR/.trassa-helper.service.new" <<'UNIT'
# SPDX-License-Identifier: AGPL-3.0-only
# Root-помощник агента Trassa: выполняет только подписанные операции из зашитого списка (E05, decisions п. 7).
# Строгая песочница невозможна — операциям следующих эпиков предстоит менять конфигурацию системы.
[Unit]
Description=Trassa helper
Documentation=https://github.com/NogMeer/trassa-agent
After=local-fs.target

[Service]
Type=simple
ExecStart=/usr/local/bin/trassa-helper serve
User=root
RuntimeDirectory=trassa
RuntimeDirectoryMode=0750
UMask=0077
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectClock=yes
LockPersonality=yes
RestrictRealtime=yes
SystemCallArchitectures=native
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
UNIT
	cat >"$UNIT_DIR/.trassa-agent.service.new" <<'UNIT'
# SPDX-License-Identifier: AGPL-3.0-only
# Сетевой процесс агента Trassa: без прав, пишет только в /var/lib/trassa/agent (E05, decisions п. 7).
[Unit]
Description=Trassa agent
Documentation=https://github.com/NogMeer/trassa-agent
Wants=network-online.target
After=network-online.target trassa-helper.service
Requires=trassa-helper.service

[Service]
Type=simple
ExecStart=/usr/local/bin/trassa-agent run
User=trassa
Group=trassa
UMask=0077
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
ProtectSystem=strict
ReadWritePaths=/var/lib/trassa/agent
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RemoveIPC=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources
SystemCallErrorNumber=EPERM
Restart=always
RestartSec=5
# Код 3 — ключ отозван панелью: перезапуск бесполезен.
RestartPreventExitStatus=3

[Install]
WantedBy=multi-user.target
UNIT
	chmod 0644 "$UNIT_DIR/.trassa-helper.service.new" "$UNIT_DIR/.trassa-agent.service.new"
	mv -f "$UNIT_DIR/.trassa-helper.service.new" "$UNIT_DIR/trassa-helper.service"
	mv -f "$UNIT_DIR/.trassa-agent.service.new" "$UNIT_DIR/trassa-agent.service"
}

# Тесты подключают файл как библиотеку (TRASSA_INSTALL_LIB=1) и проверяют функции, не запуская установку.
if [ "${TRASSA_INSTALL_LIB:-}" != 1 ]; then
	main "$@"
fi
