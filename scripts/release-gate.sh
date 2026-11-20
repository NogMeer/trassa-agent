#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Последняя проверка перед публикацией выпуска (E05-T29): выпуск без подписи не публикуется. Подпись SHA256SUMS
# проверяется тем же кодом install.sh и теми же ключами, что увидит пользователь, суммы — для всех четырёх
# бинарников. Пустой список ключей в install.sh — отказ.
# Запуск: sh scripts/release-gate.sh <dist> <версия> [install.sh]
set -eu
DIST=$1
VERSION=$2
SCRIPT=${3:-scripts/install.sh}
TRASSA_INSTALL_LIB=1
. "$SCRIPT"
no() {
	echo "Выпуск $VERSION не публикуется: $*" >&2
	exit 1
}
[ -n "$TRASSA_RELEASE_KEYS" ] || no "в install.sh нет ключей выпуска"
[ -s "$DIST/SHA256SUMS" ] || no "нет SHA256SUMS"
[ -s "$DIST/SHA256SUMS.minisig" ] || no "нет подписи SHA256SUMS.minisig"
verify_minisig "$DIST/SHA256SUMS" "$DIST/SHA256SUMS.minisig" "$VERSION" || no "подпись не сошлась с ключами install.sh"
files="trassa-agent-linux-amd64 trassa-agent-linux-arm64 trassa-helper-linux-amd64 trassa-helper-linux-arm64"
for f in $files; do
	check_sum "$DIST/SHA256SUMS" "$f" "$DIST/$f" || no "сумма $f не сошлась"
done
# Имя want занято функциями install.sh, поэтому список — в files.
[ "$(awk '{ print $2 }' "$DIST/SHA256SUMS" | LC_ALL=C sort | tr '\n' ' ')" = "$files " ] || no "в SHA256SUMS лишние или недостающие строки"
echo "Выпуск $VERSION подписан и цел"
