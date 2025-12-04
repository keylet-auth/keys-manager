package keys_manager

import "testing"

func TestSignAndVerify(t *testing.T) {
	store := NewMockStore()
	enc := MockEncryptor{}

	priv, _ := generatePrivateKey(AlgRS256)
	raw, _ := marshalPKCS8(priv)
	encKey, _ := enc.Encrypt(raw)

	k := &Key{
		KID:          "k1",
		Alg:          AlgRS256,
		IsActive:     true,
		EncryptedKey: encKey,
	}

	store.Save(k)

	km, _ := NewKeyManager(store, enc, func() (RotationConfig, error) {
		return RotationConfig{}, nil
	})

	data := []byte("hello world")

	sig, err := km.Sign(AlgRS256, data)
	if err != nil {
		t.Fatalf("sign error: %v", err)
	}

	if len(sig) == 0 {
		t.Fatalf("empty signature")
	}

	if err := km.Verify("k1", AlgRS256, data, sig); err != nil {
		t.Fatalf("verify failed: %v", err)
	}
}
