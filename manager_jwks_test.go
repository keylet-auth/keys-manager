package keys_manager

import (
	"encoding/json"
	"testing"
)

func TestJWKS(t *testing.T) {
	store := NewMockStore()
	enc := MockEncryptor{}

	priv, _ := generatePrivateKey(AlgES256)
	raw, _ := marshalPKCS8(priv)
	encKey, _ := enc.Encrypt(raw)

	store.Save(&Key{
		KID:          "ec1",
		Alg:          AlgES256,
		IsActive:     true,
		EncryptedKey: encKey,
	})

	km, _ := NewKeyManager(store, enc, func() (RotationConfig, error) {
		return RotationConfig{}, nil
	})

	out, err := km.JWKS()
	if err != nil {
		t.Fatalf("jwks error: %v", err)
	}

	var jwks JWKS
	if err := json.Unmarshal(out, &jwks); err != nil {
		t.Fatalf("bad jwks json: %v", err)
	}

	if len(jwks.Keys) != 1 {
		t.Fatalf("expected 1 jwk, got %d", len(jwks.Keys))
	}

	if jwks.Keys[0].Kid != "ec1" {
		t.Fatalf("wrong kid in jwks")
	}
}
