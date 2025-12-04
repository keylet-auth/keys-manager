package keys_manager

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func randomMasterKey(t *testing.T) []byte {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		t.Fatalf("rand.Read failed: %v", err)
	}
	return key
}

func TestAESGCM_EncryptDecrypt(t *testing.T) {
	masterKey := randomMasterKey(t)

	enc, err := NewAESGCMEncryptor(masterKey)
	if err != nil {
		t.Fatalf("NewAESGCMEncryptor error: %v", err)
	}

	original := []byte("super-secret-private-key")

	encrypted, err := enc.Encrypt(original)
	if err != nil {
		t.Fatalf("Encrypt error: %v", err)
	}

	decrypted, err := enc.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Decrypt error: %v", err)
	}

	if !bytes.Equal(original, decrypted) {
		t.Fatalf("decrypt mismatch: got %q, want %q", decrypted, original)
	}
}

func TestAESGCM_EncryptProducesDifferentCiphertexts(t *testing.T) {
	masterKey := randomMasterKey(t)

	enc, _ := NewAESGCMEncryptor(masterKey)

	data := []byte("same-data")

	enc1, _ := enc.Encrypt(data)
	enc2, _ := enc.Encrypt(data)

	if bytes.Equal(enc1.Ciphertext, enc2.Ciphertext) {
		t.Fatalf("ciphertexts must differ for same input (AES-GCM uses random nonce)")
	}
	if bytes.Equal(enc1.Nonce, enc2.Nonce) {
		t.Fatalf("nonce must be random")
	}
}

func TestAESGCM_WrongMasterKeyLength(t *testing.T) {
	key := make([]byte, 16) // should be 32 bytes

	_, err := NewAESGCMEncryptor(key)
	if err == nil {
		t.Fatalf("expected error for wrong master key length")
	}
}

func TestAESGCM_DecryptWithWrongMasterKey(t *testing.T) {
	masterKey1 := randomMasterKey(t)
	masterKey2 := randomMasterKey(t)

	enc1, _ := NewAESGCMEncryptor(masterKey1)
	enc2, _ := NewAESGCMEncryptor(masterKey2)

	msg := []byte("hello world")

	encrypted, _ := enc1.Encrypt(msg)

	_, err := enc2.Decrypt(encrypted)
	if err == nil {
		t.Fatalf("expected decryption failure with wrong master key")
	}
}

func TestAESGCM_InvalidNonce(t *testing.T) {
	masterKey := randomMasterKey(t)
	enc, _ := NewAESGCMEncryptor(masterKey)

	orig := []byte("test")
	encrypted, _ := enc.Encrypt(orig)

	encrypted.Nonce = []byte{1, 2, 3, 4}

	_, err := enc.Decrypt(encrypted)
	if err == nil {
		t.Fatalf("expected error due to invalid nonce size")
	}
}

func TestAESGCM_CorruptedCiphertext(t *testing.T) {
	masterKey := randomMasterKey(t)
	enc, _ := NewAESGCMEncryptor(masterKey)

	msg := []byte("test message")
	encrypted, _ := enc.Encrypt(msg)

	encrypted.Ciphertext[0] ^= 0xFF

	_, err := enc.Decrypt(encrypted)
	if err == nil {
		t.Fatalf("expected authentication error due to tampered ciphertext")
	}
}

func TestAESGCM_EmptyData(t *testing.T) {
	masterKey := randomMasterKey(t)
	enc, _ := NewAESGCMEncryptor(masterKey)

	encrypted, err := enc.Encrypt([]byte{})
	if err != nil {
		t.Fatalf("Encrypt empty data error: %v", err)
	}

	decrypted, err := enc.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Decrypt empty data error: %v", err)
	}

	if len(decrypted) != 0 {
		t.Fatalf("expected empty result, got %q", decrypted)
	}
}
