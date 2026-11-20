// SPDX-License-Identifier: AGPL-3.0-only

// Package verify проверяет подписи панели Trassa (E05, R8).
//
// На подпись идёт `контекст || 0x00 || тело`: контекст разделяет назначения — подпись операции нельзя выдать за
// подпись подтверждения с теми же байтами. Проверка идёт по полученным байтам до их разбора.
package verify

import (
	"crypto/ed25519"
	"errors"
)

// Контексты подписи; совпадают с apps/api/src/modules/operations/signing/signer.ts.
const (
	ContextOperation = "trassa-operation-v1"
	ContextConfirm   = "trassa-confirm-v1"
	// ContextCancel — отмена релиза или сборки (E17, SignedCancel).
	ContextCancel = "trassa-cancel-v1"
)

// PanelKey — открытый ключ подписи панели. Ключей в агенте один или два (ротация, E26).
type PanelKey struct {
	ID        string
	PublicKey ed25519.PublicKey
}

// ErrSignatureInvalid — подпись не сошлась ни с одним ключом; помощник отвечает кодом SIGNATURE_INVALID.
var ErrSignatureInvalid = errors.New("SIGNATURE_INVALID")

// Input — байты, на которые ставится подпись.
func Input(context string, body []byte) []byte {
	msg := make([]byte, 0, len(context)+1+len(body))
	msg = append(msg, context...)
	msg = append(msg, 0)
	return append(msg, body...)
}

// Signature проверяет подпись ключом keyID. Пустой список ключей — ошибка (R1): без ключа ничего не принимается.
// Длины ключа и подписи проверяются до вызова ed25519.Verify — на ключе не из 32 байт он паникует.
func Signature(keys []PanelKey, keyID, context string, body, sig []byte) error {
	if len(keys) == 0 || len(sig) != ed25519.SignatureSize {
		return ErrSignatureInvalid
	}
	for _, k := range keys {
		if k.ID != keyID || len(k.PublicKey) != ed25519.PublicKeySize {
			continue
		}
		if ed25519.Verify(k.PublicKey, Input(context, body), sig) {
			return nil
		}
	}
	return ErrSignatureInvalid
}
