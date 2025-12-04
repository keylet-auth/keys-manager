package keys_manager

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

type AESGCMEncryptor struct {
	key []byte // pass key: must be 32 bytes for AES-256
}

func NewAESGCMEncryptor(masterKey []byte) (*AESGCMEncryptor, error) {
	if len(masterKey) != 32 {
		return nil, fmt.Errorf("master key must be 32 bytes, got %d", len(masterKey))
	}
	return &AESGCMEncryptor{key: masterKey}, nil
}

func (e *AESGCMEncryptor) Encrypt(privateKey []byte) (*EncryptedKey, error) {
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return nil, fmt.Errorf("cipher init: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm init: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, privateKey, nil)

	return &EncryptedKey{
		Nonce:      nonce,
		Ciphertext: ciphertext,
	}, nil
}

func (e *AESGCMEncryptor) Decrypt(enc *EncryptedKey) ([]byte, error) {
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return nil, fmt.Errorf("cipher init: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm init: %w", err)
	}

	if len(enc.Nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("invalid nonce size: %d", len(enc.Nonce))
	}

	plain, err := gcm.Open(nil, enc.Nonce, enc.Ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	return plain, nil
}
