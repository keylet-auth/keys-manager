package keys_manager

import (
	"testing"
	"time"
)

func testSigningAndVerification(t *testing.T, alg Alg) {
	store := NewMockStore()
	enc := MockEncryptor{}

	priv, err := generatePrivateKey(alg)
	if err != nil {
		t.Fatalf("%s: private key generation failed: %v", alg, err)
	}

	raw, err := marshalPKCS8(priv)
	if err != nil {
		t.Fatalf("%s: marshal PKCS8 failed: %v", alg, err)
	}

	encKey, err := enc.Encrypt(raw)
	if err != nil {
		t.Fatalf("%s: encrypt failed: %v", alg, err)
	}

	k := &Key{
		KID:          "k1",
		Alg:          alg,
		IsActive:     true,
		CreatedAt:    time.Now(),
		EncryptedKey: encKey,
	}

	store.Save(k)

	km, err := NewKeyManager(store, enc, func() (RotationConfig, error) {
		return RotationConfig{}, nil
	})
	if err != nil {
		t.Fatalf("%s: failed to create KM: %v", alg, err)
	}

	data := []byte("hello world")

	sig, err := km.Sign(alg, func(_ string) ([]byte, error) {
		return data, nil
	})
	if err != nil {
		t.Fatalf("%s: sign error: %v", alg, err)
	}

	if len(sig) == 0 {
		t.Fatalf("%s: signature is empty", alg)
	}

	if alg == AlgES256 && len(sig) != 64 {
		t.Fatalf("%s: expected RAW signature length 64, got %d", alg, len(sig))
	}

	if err := km.Verify("k1", data, sig); err != nil {
		t.Fatalf("%s: verify failed: %v", alg, err)
	}

	if err := km.Verify("k1", []byte("wrong"), sig); err == nil {
		t.Fatalf("%s: verify passed for WRONG data", alg)
	}
}

func TestSignAndVerify_RS256(t *testing.T) {
	testSigningAndVerification(t, AlgRS256)
}

func TestSignAndVerify_ES256(t *testing.T) {
	testSigningAndVerification(t, AlgES256)
}

func TestSignAndVerify_EdDSA(t *testing.T) {
	testSigningAndVerification(t, AlgEdDSA)
}
