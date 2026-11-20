// SPDX-License-Identifier: AGPL-3.0-only

// Package sealed — секреты операций (E13): HPKE RFC 9180, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256,
// AES-256-GCM, одноразовый Seal/Open (crypto/hpke). Ключ X25519 — отдельный, его создаёт и хранит помощник
// (root, 0600); вывод из Ed25519 агента запрещён: тогда процесс без прав расшифровал бы все секреты.
// info привязывает шифротекст к серверу, ключу, операции, типу, плану и полю (decisions E13, «Секреты»).
package sealed

import (
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	agentv1 "github.com/NogMeer/trassa-agent/gen/trassa/agent/v1"
	"github.com/NogMeer/trassa-agent/internal/fsutil"
)

// InfoPrefix — версия формата info.
const InfoPrefix = "trassa/secret/v1"

func suite() (hpke.KDF, hpke.AEAD) { return hpke.HKDFSHA256(), hpke.AES256GCM() }

// Key — ключ помощника.
type Key struct {
	priv *ecdh.PrivateKey
	ID   string
}

// KeyID — первые 16 символов hex sha256 открытого ключа.
func KeyID(pub []byte) string {
	s := sha256.Sum256(pub)
	return hex.EncodeToString(s[:8])
}

// FromBytes — ключ из 32 байт (вектор и файл).
func FromBytes(b []byte) (*Key, error) {
	k, err := ecdh.X25519().NewPrivateKey(b)
	if err != nil {
		return nil, err
	}
	return &Key{priv: k, ID: KeyID(k.PublicKey().Bytes())}, nil
}

// Public — открытый ключ (Hello.encryption_public_key).
func (k *Key) Public() []byte { return k.priv.PublicKey().Bytes() }

// LoadOrCreate — ключ из файла; файла нет — создаётся (0600). Права шире 0600 — отказ.
func LoadOrCreate(path string) (*Key, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		k, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, err
		}
		if err := fsutil.WriteFileAtomic(path, k.Bytes(), 0o600, fsutil.Keep); err != nil {
			return nil, err
		}
		return &Key{priv: k, ID: KeyID(k.PublicKey().Bytes())}, nil
	}
	if err != nil {
		return nil, err
	}
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s: права %o шире 0600", path, st.Mode().Perm())
	}
	return FromBytes(b)
}

// Info — контекст секрета: префикс и поля через 0x00.
func Info(serverID, kid, operationID, opType, planID, field string) []byte {
	return []byte(strings.Join([]string{InfoPrefix, serverID, kid, strings.ToLower(operationID), opType, planID, field}, "\x00"))
}

// ErrKey — секрет зашифрован на другой ключ.
var ErrKey = errors.New("SECRET_KEY_MISMATCH")

// ErrOpen — секрет не расшифровался: подменён, переложен из другой операции или поля.
var ErrOpen = errors.New("SECRET_INVALID")

// Open — расшифровать секрет для поля.
func (k *Key) Open(s *agentv1.SealedSecret, info []byte) ([]byte, error) {
	if s.GetKid() != k.ID {
		return nil, fmt.Errorf("%w: kid %q, у помощника %q", ErrKey, s.GetKid(), k.ID)
	}
	priv, err := hpke.NewDHKEMPrivateKey(k.priv)
	if err != nil {
		return nil, err
	}
	kdf, aead := suite()
	pt, err := hpke.Open(priv, kdf, aead, info, s.GetEncCt())
	if err != nil {
		return nil, ErrOpen
	}
	return pt, nil
}

// Seal — зашифровать на открытый ключ (так делает панель; здесь — для тестов и векторов).
func Seal(pub []byte, info, plaintext []byte) (*agentv1.SealedSecret, error) {
	p, err := ecdh.X25519().NewPublicKey(pub)
	if err != nil {
		return nil, err
	}
	pk, err := hpke.NewDHKEMPublicKey(p)
	if err != nil {
		return nil, err
	}
	kdf, aead := suite()
	ct, err := hpke.Seal(pk, kdf, aead, info, plaintext)
	if err != nil {
		return nil, err
	}
	return &agentv1.SealedSecret{Kid: KeyID(pub), EncCt: ct}, nil
}
