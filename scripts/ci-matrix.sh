#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Матрица ОС (E05-T28): чистая система в контейнере с systemd (decisions п. 12) → команда установки как в панели
# → регистрация на заглушке → «Сервер на связи», system.info, метрики, журналы, события → повторная установка → удаление.
# Перед этим — установка с испорченной подписью: отказ с кодом 3, на системе ничего не появилось.
# Только для одноразового раннера CI. Запуск: sudo sh scripts/ci-matrix.sh <образ, например ubuntu:24.04> <каталог отчёта>
# Нужны dist/ после «make build» и dist/stubpanel (заглушка панели той же архитектуры).
set -eu
IMAGE=$1
REPORT=$2
VERSION=${VERSION:-0.0.0-dev}
NAME=trassa-matrix
ADDR=127.0.0.1:8443
URL=https://$ADDR
STUB=/root/stub

fail() {
	echo "FAIL ($IMAGE): $*" >&2
	podman exec "$NAME" journalctl -u trassa-helper -u trassa-agent --no-pager -n 80 >&2 || true
	podman exec "$NAME" journalctl -u ci-stubpanel --no-pager -n 40 >&2 || true
	exit 1
}
x() { podman exec "$NAME" "$@"; }

mkdir -p "$REPORT"
ctx=$(mktemp -d)
trap 'podman rm -f "$NAME" >/dev/null 2>&1 || true; rm -rf "$ctx"' EXIT
cat >"$ctx/Containerfile" <<EOF
FROM docker.io/library/$IMAGE
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    systemd systemd-sysv dbus ca-certificates curl openssl && rm -rf /var/lib/apt/lists/*
CMD ["/sbin/init"]
EOF
podman build -q -t trassa-matrix-os "$ctx" >/dev/null
podman run -d --systemd=always --privileged --name "$NAME" -v "$PWD:/src:ro" trassa-matrix-os >/dev/null
# Сразу после старта шины systemd ещё нет и is-system-running отвечает пустотой — ждём до 60 с.
state=""
for _ in $(seq 1 60); do
	state=$(x systemctl is-system-running --wait 2>/dev/null || true)
	case "$state" in
	running | degraded) break ;;
	esac
	sleep 1
done
case "$state" in
running | degraded) ;;
*) fail "systemd в контейнере не поднялся за 60 с: $state" ;;
esac
osid=$(x sh -c '. /etc/os-release; echo "$ID $VERSION_ID"')
echo "== $osid, $(x uname -m)"

# stub [-tamper] — перезапуск заглушки (новые УЦ, ключи и токен) и доверие её УЦ в системе контейнера.
stub() {
	x systemctl stop ci-stubpanel.service 2>/dev/null || true
	x rm -rf "$STUB"
	x systemd-run --quiet --unit=ci-stubpanel --collect /src/dist/stubpanel -addr "$ADDR" -release /src/dist \
		-version "$VERSION" -script /src/scripts/install.sh -out "$STUB" "$@"
	for _ in $(seq 1 50); do x test -s "$STUB/token" && break; sleep 0.2; done
	x test -s "$STUB/token" || fail "заглушка не запустилась"
	x cp "$STUB/ca.pem" /usr/local/share/ca-certificates/ci-stub.crt
	x update-ca-certificates >/dev/null
}
# install — та же команда, что показывает панель (диалог 7.4).
install_cmd() {
	x bash -c "curl -fsSL --proto '=https' $URL/install.sh | bash -s -- --url $URL --token \$(cat $STUB/token)"
}

# 1. Испорченная подпись: код 3, ни бинарников, ни пользователя, ни служб.
stub -tamper
set +e
install_cmd
rc=$?
set -e
[ "$rc" -eq 3 ] || fail "испорченная подпись: код $rc, ждали 3"
x sh -c 'test ! -e /usr/local/bin/trassa-agent && test ! -e /etc/trassa && test ! -e /etc/systemd/system/trassa-agent.service && ! id trassa' ||
	fail "после отказа по подписи на системе остались следы установки"

# 2. Установка и регистрация. Журнал для подписки E08-T15 и ссылка из /var/log наружу — её читать нельзя.
x sh -c 'printf "before subscribe\n" >/var/log/ci-logs.log && ln -sf /etc/shadow /var/log/ci-evil.log'
stub
start=$(date +%s)
install_cmd || fail "установка не удалась"
installed=$(($(date +%s) - start))
for _ in $(seq 1 60); do x test -s "$STUB/result.json" && break; sleep 1; done
online=$(($(date +%s) - start))
x test -s "$STUB/result.json" || fail "агент не вышел на связь за 60 с"
podman cp "$NAME:$STUB/result.json" "$ctx/result.json"
jq -e '.problem == ""' "$ctx/result.json" >/dev/null || fail "операция: $(jq -r .problem "$ctx/result.json")"
jq -e '.result.outcome == "OPERATION_OUTCOME_SUCCEEDED"' "$ctx/result.json" >/dev/null || fail "итог system.info: $(cat "$ctx/result.json")"
want_os=${osid% *}
want_ver=${osid#* }
jq -e --arg os "$want_os" --arg v "$want_ver" '.hello.os == $os and .hello.os_version == $v and .result.system_info.cpu_cores > 0 and (.result.system_info.ram_mb | tonumber) > 0' \
	"$ctx/result.json" >/dev/null || fail "сведения о системе не совпали с $osid: $(cat "$ctx/result.json")"
# Метрики (E08-T5): первая пачка снята агентом в песочнице службы и подтверждена шлюзом.
for m in mem_used_percent mem_used_bytes load1 uptime_seconds procs_total tcp_connections; do
	jq -e --arg m "$m" '.metrics | index($m) != null' "$ctx/result.json" >/dev/null || fail "в пачке метрик нет $m: $(jq -c .metrics "$ctx/result.json")"
done
# Журналы (E08-T15): подписка открыла файл и отказала ссылке наружу; новые строки приходят пачкой без секретов.
for _ in $(seq 1 30); do x test -s "$STUB/subscribe.json" && break; sleep 1; done
podman cp "$NAME:$STUB/subscribe.json" "$ctx/subscribe.json" 2>/dev/null || fail "нет итога logs.subscribe"
jq -e '.outcome == "OPERATION_OUTCOME_SUCCEEDED" and .logs_subscribe.sources[0].opened == true and .logs_subscribe.sources[1].reason == "PATH_FORBIDDEN"' \
	"$ctx/subscribe.json" >/dev/null || fail "logs.subscribe: $(cat "$ctx/subscribe.json")"
x sh -c 'printf "ci line one\nERROR db password=hunter2hunter2\n" >>/var/log/ci-logs.log'
for _ in $(seq 1 30); do x grep -qF "ERROR db" "$STUB/logs.jsonl" 2>/dev/null && break; sleep 1; done
x grep -qF '"message":"ci line one"' "$STUB/logs.jsonl" || fail "строки журнала не пришли: $(x cat "$STUB/logs.jsonl" 2>&1)"
! x grep -qF "before subscribe" "$STUB/logs.jsonl" || fail "ушли строки до подписки"
! x grep -qF "hunter2hunter2" "$STUB/logs.jsonl" || fail "секрет ушёл в журналы"
! x grep -qF "root:" "$STUB/logs.jsonl" || fail "прочитан файл вне /var/log"
x grep -F '"level":"LOG_LEVEL_ERROR"' "$STUB/logs.jsonl" | grep -qF "ERROR db" || fail "уровень строки ERROR"

# Центр безопасности (E10, блок A): скан по всем кодам и список обновлений на настоящей ОС, без TIMEOUT.
for f in security.json packages.json; do
	for _ in $(seq 1 90); do x test -s "$STUB/$f" && break; sleep 1; done
	podman cp "$NAME:$STUB/$f" "$ctx/$f" 2>/dev/null || fail "нет итога $f"
	jq -e '.outcome == "OPERATION_OUTCOME_SUCCEEDED"' "$ctx/$f" >/dev/null || fail "$f: $(cat "$ctx/$f")"
done
jq -e '[.security_scan.checks[] | select(.error == "TIMEOUT")] | length == 0' "$ctx/security.json" >/dev/null ||
	fail "проверки не уложились в срок: $(jq -c '[.security_scan.checks[] | select(.error == "TIMEOUT") | .code]' "$ctx/security.json")"
jq -e '.security_scan.checks | length > 30' "$ctx/security.json" >/dev/null || fail "в скане мало проверок"
# Ошибок чтения на чистой системе быть не должно (кроме того, чего в контейнере нет по построению).
jq -e '[.security_scan.checks[] | select(.state == "CHECK_STATE_ERROR")] | length == 0' "$ctx/security.json" >/dev/null ||
	fail "проверки с ошибкой: $(jq -c '[.security_scan.checks[] | select(.state == "CHECK_STATE_ERROR") | {code, error, evidence}]' "$ctx/security.json")"
jq -r '.security_scan.checks[] | "\(.code) \(.state) \(.subject // "") \(.error // "")"' "$ctx/security.json"
jq -c '{updates: (.packages_list_updates.packages // [] | length), security: ([.packages_list_updates.packages[]? | select(.security)] | length)}' "$ctx/packages.json"

# События (E08-T12): упавшая служба даёт service.down за 30 с, сброс — resolved.
x systemd-run --quiet --unit=ci-broken --property=Type=oneshot /bin/false || true
event_seen() {
	for _ in $(seq 1 45); do
		x sh -c "grep -F '\"subject\":\"ci-broken.service\"' $STUB/events.jsonl 2>/dev/null | grep -qF '\"state\":\"$1\"'" && return 0
		sleep 1
	done
	return 1
}
event_seen firing || fail "нет события service.down по упавшей службе: $(x cat $STUB/events.jsonl 2>&1)"
x systemctl reset-failed ci-broken.service
event_seen resolved || fail "нет снятия service.down: $(x cat $STUB/events.jsonl 2>&1)"
x systemctl is-active --quiet trassa-helper.service trassa-agent.service || fail "службы не активны"
x test "$(x stat -c '%a %U %G' /run/trassa/helper.sock)" = "660 root trassa" || fail "права сокета помощника"

# 3. Повторный запуск команды безопасен: зарегистрированный агент не трогается.
out=$(install_cmd 2>&1) || fail "повторная установка: $out"
echo "$out" | grep -q "уже установлен" || fail "повторная установка: $out"
x systemctl is-active --quiet trassa-agent.service || fail "служба агента остановилась после повторной установки"

# 4. Удаление: ни файлов, ни служб, ни пользователя.
x /usr/local/bin/trassa-agent uninstall --purge-rollback --yes
# /run/systemd/propagate/<служба> — служебный каталог самого systemd (249 в Ubuntu 22.04 не убирает его после
# остановки службы с песочницей); это tmpfs systemd, не файл Trassa.
left=$(x sh -c "find /etc /usr/local/bin /var/lib /run /usr/lib/systemd -name '*trassa*' ! -path '/run/systemd/propagate/*' 2>/dev/null" || true)
[ -z "$left" ] || fail "после удаления осталось: $left"
! x id trassa >/dev/null 2>&1 || fail "пользователь trassa остался"

arch=$(x uname -m)
jq -n --arg image "$IMAGE" --arg os "$osid" --arg arch "$arch" --argjson installed "$installed" --argjson online "$online" \
	--slurpfile run "$ctx/result.json" --slurpfile scan "$ctx/security.json" \
	'{image: $image, os: $os, arch: $arch, install_seconds: $installed, online_seconds: $online,
	  checks: ["bad-signature-rejected", "install", "enroll", "online", "system.info", "metrics", "logs", "security.scan", "packages.list_updates", "events", "reinstall-idempotent", "uninstall-clean"],
	  metrics: $run[0].metrics,
	  security: $scan[0].security_scan.checks,
	  system_info: $run[0].result.system_info}' >"$REPORT/$(echo "$IMAGE" | tr ':' '-')-$arch.json"
echo "OK $osid $arch: установка ${installed} с, на связи через ${online} с"
