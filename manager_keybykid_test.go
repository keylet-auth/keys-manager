package keys_manager

import "testing"

func TestKeyByKID(t *testing.T) {
	store := NewMockStore()
	enc := MockEncryptor{}

	priv, _ := generatePrivateKey(AlgRS256)
	raw, _ := marshalPKCS8(priv)
	encKey, _ := enc.Encrypt(raw)

	store.Save(&Key{
		KID:          "k1",
		Alg:          AlgRS256,
		IsActive:     true,
		EncryptedKey: encKey,
	})

	km, err := NewKeyManager(store, enc, func() (RotationConfig, error) {
		return RotationConfig{}, nil
	})

	if err != nil {
		t.Fatalf("error: %v", err)
	}

	ck := km.keyByKID("k1")

	if ck.key.KID != "k1" {
		t.Fatalf("wrong key returned")
	}
}
