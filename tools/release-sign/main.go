// SPDX-License-Identifier: AGPL-3.0-only

// release-sign подписывает SHA256SUMS выпуска ключом minisign владельца (E05-T29): подпись с предварительным
// хэшем (как у «minisign -S»), доверенный комментарий «trassa-agent <версия>» — его проверяют internal/update и
// install.sh. Ключ — содержимое файла секретного ключа minisign в TRASSA_MINISIGN_KEY, пароль — в
// TRASSA_MINISIGN_PASSWORD (секреты CI); ключ на диск не пишется. Владелец может подписать и офлайн тем же
// minisign: minisign -S -s <ключ> -m SHA256SUMS -t "trassa-agent <версия>".
//
// Запуск: go run ./tools/release-sign -version 1.2.3 dist/SHA256SUMS → dist/SHA256SUMS.minisig
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"

	"aead.dev/minisign"

	"github.com/NogMeer/trassa-agent/internal/fsutil"
)

var versionRe = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$`)

func main() {
	version := flag.String("version", "", "версия выпуска без «v»")
	flag.Parse()
	if err := run(*version, flag.Args(), os.Getenv("TRASSA_MINISIGN_KEY"), os.Getenv("TRASSA_MINISIGN_PASSWORD")); err != nil {
		fmt.Fprintln(os.Stderr, "release-sign:", err)
		os.Exit(1)
	}
}

func run(version string, args []string, key, password string) error {
	if !versionRe.MatchString(version) || len(args) != 1 {
		return errors.New("использование: release-sign -version 1.2.3 dist/SHA256SUMS")
	}
	if key == "" {
		return errors.New("нет TRASSA_MINISIGN_KEY: подписать нечем")
	}
	priv, err := minisign.DecryptKey(password, []byte(key))
	if err != nil {
		return fmt.Errorf("ключ minisign: %w", err)
	}
	return sign(priv, version, args[0])
}

// sign пишет <path>.minisig: подпись с предварительным хэшем и комментарием «trassa-agent <версия>».
func sign(priv minisign.PrivateKey, version, path string) error {
	sums, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	r := minisign.NewReader(bytes.NewReader(sums))
	if _, err := io.Copy(io.Discard, r); err != nil {
		return err
	}
	sig := r.SignWithComments(priv, "trassa-agent "+version, "trassa-agent release")
	return fsutil.WriteFileAtomic(path+".minisig", sig, 0o644, fsutil.Keep)
}
