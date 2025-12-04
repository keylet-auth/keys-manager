package keys_manager

import "fmt"

type MockEncryptor struct {
	ForceDecryptError bool
}

func (m MockEncryptor) Encrypt(b []byte) (*EncryptedKey, error) {
	return &EncryptedKey{
		Nonce:      []byte{},
		Ciphertext: append([]byte(nil), b...),
	}, nil
}

func (m MockEncryptor) Decrypt(e *EncryptedKey) ([]byte, error) {
	if m.ForceDecryptError {
		return nil, fmt.Errorf("forced decrypt error")
	}
	return append([]byte(nil), e.Ciphertext...), nil
}
