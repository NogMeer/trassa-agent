// SPDX-License-Identifier: AGPL-3.0-only

package update

// ReleaseKeys — открытые ключи minisign владельца для подписи выпусков (R12: два ключа для ротации).
//
// Список совпадает с TRASSA_RELEASE_KEYS в scripts/install.sh (проверяет test/installsh). Пустой список —
// NewVerifier отказывает, и ни одно обновление не ставится: без ключа проверка не «пропускается».
//
// Ключ 1 — trassa-release-1, key_id 9889674CCEE25046: создан 2026-11-23 на машине разработчика, а не на офлайн-
// церемонии; до первых клиентов — ротация на офлайн-ключ (выпуск с парой «этот и офлайн», затем только офлайн).
// Второе место — под будущий офлайн-ключ trassa-release-2.
var ReleaseKeys = []string{
	"RWRGUOLOTGeJmFfIFOk0UF9AXhgfoh1qZK2h8eRTZNCa23uNDmvfNCSp", // trassa-release-1
}
