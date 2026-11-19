// SPDX-License-Identifier: AGPL-3.0-only

// Package identity — ключ Ed25519 агента (E05-T11). Ключ создаётся на сервере при регистрации и не покидает его:
// панель знает только открытую часть. Файл — 32 байта seed, владелец trassa, права 0600.
package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"os"

	"github.com/NogMeer/trassa-agent/internal/fsutil"
)

// AuthContext — префикс подписи рукопожатия: "trassa-agent-auth-v1" || nonce || server_id.
const AuthContext = "trassa-agent-auth-v1"

// ChallengeNonceSize — длина nonce из Challenge.
const ChallengeNonceSize = 32

// Identity — закрытый ключ агента.
type Identity struct{ priv ed25519.PrivateKey }

// ErrKeyInsecure — файл ключа доступен группе или остальным; агент с таким ключом не стартует.
var ErrKeyInsecure = errors.New("agent key: права шире 0600")

// Generate создаёт новый ключ. Существующий файл не перезаписывается: повторная регистрация требует удаления
// агента, иначе можно незаметно подменить личность сервера.
func Generate(path string, owner fsutil.Owner) (*Identity, error) {
	if _, err := os.Lstat(path); err == nil {
		return nil, fmt.Errorf("agent key: %s уже существует", path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	if err := fsutil.WriteFileAtomic(path, seed, 0o600, owner); err != nil {
		return nil, err
	}
	return &Identity{priv: ed25519.NewKeyFromSeed(seed)}, nil
}

// Load читает ключ и проверяет права файла.
func Load(path string) (*Identity, error) {
	st, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("agent key: %s не обычный файл", path)
	}
	if st.Mode().Perm()&0o077 != 0 {
		return nil, ErrKeyInsecure
	}
	seed, err := fsutil.ReadLimited(path, ed25519.SeedSize)
	if err != nil {
		return nil, err
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("agent key: ждали %d байт, в файле %d", ed25519.SeedSize, len(seed))
	}
	return &Identity{priv: ed25519.NewKeyFromSeed(seed)}, nil
}

// PublicKey — открытый ключ (32 байта), уходит в панель при регистрации.
func (i *Identity) PublicKey() ed25519.PublicKey { return i.priv.Public().(ed25519.PublicKey) }

// AuthInput — байты, которые подписывает агент в ответ на Challenge.
func AuthInput(nonce []byte, serverID string) []byte {
	msg := make([]byte, 0, len(AuthContext)+len(nonce)+len(serverID))
	msg = append(msg, AuthContext...)
	msg = append(msg, nonce...)
	return append(msg, serverID...)
}

// SignChallenge подписывает вызов шлюза. Nonce не из 32 байт — отказ: подписывать произвольные данные ключом
// агента нельзя.
func (i *Identity) SignChallenge(nonce []byte, serverID string) ([]byte, error) {
	if len(nonce) != ChallengeNonceSize {
		return nil, fmt.Errorf("challenge: nonce %d байт, ждали %d", len(nonce), ChallengeNonceSize)
	}
	return ed25519.Sign(i.priv, AuthInput(nonce, serverID)), nil
}
