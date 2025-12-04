package keys_manager

import (
	"crypto"
	"time"
)

type RotationConfig struct {
	TTL time.Duration
}

type RotationPolicy func() (RotationConfig, error)

type Alg string

const (
	AlgRS256 Alg = "RS256"
	AlgES256 Alg = "ES256"
	AlgEdDSA Alg = "EdDSA"
)

type EncryptedKey struct {
	Nonce      []byte
	Ciphertext []byte
}

type Key struct {
	KID          string
	Alg          Alg
	IsActive     bool
	CreatedAt    time.Time
	ExpiresAt    *time.Time
	EncryptedKey *EncryptedKey
}

type CachedKey struct {
	key  *Key
	priv crypto.Signer
	pub  crypto.PublicKey
}

type Encryptor interface {
	Encrypt(privateKey []byte) (*EncryptedKey, error)
	Decrypt(encrypted *EncryptedKey) ([]byte, error)
}

type Store interface {
	List() ([]*Key, error)
	Rotate(newKey *Key, oldKey *Key) error
}
