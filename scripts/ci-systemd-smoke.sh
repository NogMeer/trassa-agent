#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Проверка служб на настоящем systemd раннера CI (E05-T21, R11). Только для одноразовой машины CI: ставит файлы
# в систему. Запуск: sudo sh scripts/ci-systemd-smoke.sh dist/<arch>
set -eu
DIST=$1
fail() { echo "FAIL: $*" >&2; journalctl -u trassa-helper -u trassa-agent --no-pager -n 50 >&2 || true; exit 1; }

id -u trassa >/dev/null 2>&1 || useradd --system --user-group --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin trassa
install -m 0755 "$DIST"/trassa-agent-linux-* /usr/local/bin/trassa-agent
install -m 0755 "$DIST"/trassa-helper-linux-* /usr/local/bin/trassa-helper
install -m 0644 packaging/systemd/trassa-agent.service packaging/systemd/trassa-helper.service /etc/systemd/system/
systemd-analyze verify /etc/systemd/system/trassa-agent.service /etc/systemd/system/trassa-helper.service
systemd-analyze security --no-pager trassa-agent.service || true

install -d -m 0755 /var/lib/trassa
install -d -m 0700 -o trassa -g trassa /var/lib/trassa/agent
install -d -m 0750 -o root -g trassa /etc/trassa
# Тестовая регистрация: шлюз недоступен, ключ панели — нулевой (подписей в этой проверке нет).
cat >/etc/trassa/enrollment.json <<'JSON'
{"serverId":"01a1f4b6-f327-7a5d-ac23-e95c272c0fe8","gatewayUrl":"wss://127.0.0.1:9/agent/v1/connect","protocolVersion":1,"panelKeys":[{"keyId":"ci","publicKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}]}
JSON
chown root:trassa /etc/trassa/enrollment.json
chmod 0640 /etc/trassa/enrollment.json

systemctl daemon-reload
systemctl start trassa-helper.service
for _ in $(seq 1 50); do [ -S /run/trassa/helper.sock ] && break; sleep 0.2; done
[ -S /run/trassa/helper.sock ] || fail "сокет не создан"
[ "$(stat -c '%a %U %G' /run/trassa/helper.sock)" = "660 root trassa" ] || fail "права сокета: $(stat -c '%a %U %G' /run/trassa/helper.sock)"
[ "$(stat -c '%a %U %G' /run/trassa)" = "750 root trassa" ] || fail "права /run/trassa: $(stat -c '%a %U %G' /run/trassa)"
[ "$(stat -c '%a' /var/lib/trassa/helper)" = "700" ] || fail "права каталога помощника"

# Агент в своей песочнице (те же опции, что у службы) доходит до сокета и получает список типов.
set --
while IFS= read -r line; do
	set -- "$@" -p "$line"
done <<PROPS
$(sed -n '/^\[Service\]/,/^\[Install\]/p' /etc/systemd/system/trassa-agent.service | grep -E '^[A-Za-z]+=' | grep -Ev '^(Type|ExecStart|Restart|RestartSec|RestartPreventExitStatus)=')
PROPS
out=$(systemd-run --wait --pipe --quiet "$@" /usr/local/bin/trassa-agent status 2>&1 || true)
echo "$out"
echo "$out" | grep -q "Помощник: .*system.info" || fail "агент в песочнице не достучался до помощника"

# Чужой пользователь (nobody) помощника вызвать не может (R11).
out=$(setpriv --reuid=nobody --regid=nogroup --clear-groups /usr/local/bin/trassa-agent status 2>&1 || true)
echo "$out"
echo "$out" | grep -q "Помощник: нет ответа" || fail "nobody достучался до помощника"
# root тоже не trassa: помощник отвечает PEER_FORBIDDEN.
out=$(/usr/local/bin/trassa-agent status 2>&1 || true)
echo "$out" | grep -q "PEER_FORBIDDEN" || fail "root получил ответ помощника"

# Служба агента запускается в песочнице и живёт (шлюз недоступен — переподключается, не падает навсегда).
systemctl start trassa-agent.service
sleep 3
systemctl is-active --quiet trassa-agent.service || fail "служба агента не активна"
journalctl -u trassa-agent --no-pager -n 5

# Удаление: ни файлов, ни служб, ни пользователя.
/usr/local/bin/trassa-agent uninstall --purge-rollback --yes
left=$(find /etc /usr/local /var/lib /run /usr/lib/systemd -name '*trassa*' 2>/dev/null || true)
[ -z "$left" ] || fail "после удаления осталось: $left"
! id -u trassa >/dev/null 2>&1 || fail "пользователь trassa остался"
echo "OK"
