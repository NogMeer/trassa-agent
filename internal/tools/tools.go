// SPDX-License-Identifier: AGPL-3.0-only

// Package tools — внешние программы, которые помощник согласен поставить: версия → архитектура → sha256 архива
// или бинарника выпуска. Подписанная операция панели не может поставить от root другой бинарник: сумма из тела
// обязана совпасть с этой таблицей. Новая версия — правка таблицы и decisions в одном выпуске агента.
package tools

import (
	"errors"
	"fmt"
	"runtime"
)

// Known — таблица. Источники сумм и проверка подписей — в decisions (Sources).
var Known = map[string]map[string]map[string]string{
	// E13: SHA256SUMS выпуска, подпись ключом CF8F…A907 проверена.
	"restic": {"0.20.0": {
		"amd64": "0ccd9fa7885074a24603b051e01bf9bd8b5e45d6a1791e9d9887e9e9372107f7",
		"arm64": "1188daded239bccb5952a01d2ad33e77a0d3dc34f9d9fc1e7fdda618d44938ef",
	}},
	// E13: SHA256SUMS выпуска, подпись ключом FBF7…54FA проверена.
	"rclone": {"1.75.2": {
		"amd64": "349ac8fba6ff65d6247043f1750cdcb518ec5d500ef91463a10d37c0ccdf3702",
		"arm64": "7e1e8d69654941b7b7df84ee74c5f7fb09cce7d5496947fb7bf16b55ff427d10",
	}},
	// E17: sha256 архивов (digest ассетов GitHub); SHA-512 этих архивов совпадают с подписанным Sigstore
	// checksums.txt, цепочка сертификата до корня Sigstore не проверена.
	"caddy": {"2.11.9": {
		"amd64": "5b8cb7faf8726a2028ad96a66e54e6e81e8f361bc6175e5d22bbd997cc5177fb",
		"arm64": "5e377cff994fc9362a6fcf695c53f226cfca3a3ef85bd3a3687cf252d6310165",
	}},
	// E17: checksums.txt выпуска (не подписан) и digest ассетов GitHub совпадают.
	"railpack": {"0.43.0": {
		"amd64": "248a8f60f36854aabed6124113631078a802de3461660855fc4de9c26065c1fb",
		"arm64": "732ece14eb4f4676a43ebba19431f954edf7b130acb76159ef0f2ff86ac42ac9",
	}},
	// E17: checksums.txt выпуска и digest ассетов GitHub совпадают (бинарник, не архив).
	"docker-compose": {"5.7.0": {
		"amd64": "7758048ad38e580f22559603312874fec8bb638d021a9e64182385fc17cc12a2",
		"arm64": "15861535d14e26555736b49376c95e14bfd94285366c8446bfac7156a972e76f",
	}},
	"docker-buildx": {"0.38.2": {
		"amd64": "7992ec09413b80ff57ba4e081f56fc833d7bac1d5e71143c6c809e7e6065f6d6",
		"arm64": "46c0f334772de3cb0b341cc415caf7339fb5cfc8b8438ebcb5a10e7f23800d36",
	}},
}

// Source — где записан выпуск: файл решений и имя файла выпуска по архитектуре (для сверки таблицы с decisions).
type Source struct {
	Decisions string
	File      func(version, arch string) string
}

// Sources — для теста сверки с decisions.
var Sources = map[string]Source{
	"restic": {"E13-backups.md", func(v, a string) string { return fmt.Sprintf("restic_%s_linux_%s.bz2", v, a) }},
	"rclone": {"E13-backups.md", func(v, a string) string { return fmt.Sprintf("rclone-v%s-linux-%s.zip", v, a) }},
	"caddy":  {"E17-deploy.md", func(v, a string) string { return fmt.Sprintf("caddy_%s_linux_%s.tar.gz", v, a) }},
	"railpack": {"E17-deploy.md", func(v, a string) string {
		return fmt.Sprintf("railpack-v%s-%s-unknown-linux-musl.tar.gz", v, map[string]string{"amd64": "x86_64", "arm64": "arm64"}[a])
	}},
	"docker-compose": {"E17-deploy.md", func(_, a string) string {
		return "docker-compose-linux-" + map[string]string{"amd64": "x86_64", "arm64": "aarch64"}[a]
	}},
	"docker-buildx": {"E17-deploy.md", func(v, a string) string { return fmt.Sprintf("buildx-v%s.linux-%s", v, a) }},
}

// ErrUnknown — версия или сумма не из таблицы (код отказа задаёт эпик: BACKUP_TOOL_UNKNOWN, DEPLOY_TOOL_UNKNOWN).
var ErrUnknown = errors.New("TOOL_UNKNOWN")

// Check — версия и sha256 есть в Known для архитектуры сервера.
func Check(tool, version, sha string) error { return CheckArch(tool, version, sha, runtime.GOARCH) }

// CheckArch — то же для заданной архитектуры.
func CheckArch(tool, version, sha, arch string) error {
	want, ok := Known[tool][version][arch]
	if !ok {
		return fmt.Errorf("%w: %s %s для %s не поддерживается этой версией агента", ErrUnknown, tool, version, arch)
	}
	if sha != want {
		return fmt.Errorf("%w: sha256 %s %s не совпадает с таблицей агента", ErrUnknown, tool, version)
	}
	return nil
}
