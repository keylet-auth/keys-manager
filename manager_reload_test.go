package keys_manager

import "testing"

func TestReloadCache(t *testing.T) {
	store := NewMockStore()
	enc := MockEncryptor{}

	priv1, _ := generatePrivateKey(AlgRS256)
	raw1, _ := marshalPKCS8(priv1)
	encKey1, _ := enc.Encrypt(raw1)

	priv2, _ := generatePrivateKey(AlgRS256)
	raw2, _ := marshalPKCS8(priv2)
	encKey2, _ := enc.Encrypt(raw2)

	k1 := &Key{
		KID:          "k1",
		Alg:          AlgRS256,
		IsActive:     true,
		EncryptedKey: encKey1,
	}

	k2 := &Key{
		KID:          "k2",
		Alg:          AlgRS256,
		IsActive:     false,
		EncryptedKey: encKey2,
	}

	store.Save(k1)
	store.Save(k2)

	km, err := NewKeyManager(store, enc, func() (RotationConfig, error) {
		return RotationConfig{}, nil
	})
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	ck := km.activeKey(AlgRS256)
	if ck == nil {
		t.Fatalf("activeKey returned nil")
	}
	if ck.key.KID != "k1" {
		t.Fatalf("expected active key k1, got %s", ck.key.KID)
	}

	km.mu.RLock()
	if len(km.cache) != 2 {
		t.Fatalf("expected 2 keys in cache, got %d", len(km.cache))
	}
	km.mu.RUnlock()

	err = km.ReloadCache()
	if err != nil {
		t.Fatalf("ReloadCache returned error: %v", err)
	}

	ck2 := km.activeKey(AlgRS256)
	if ck2 == nil || ck2.key.KID != "k1" {
		t.Fatalf("after reload, expected active key k1, got %v", ck2)
	}

	if km.keyByKID("k2") == nil {
		t.Fatalf("expected key k2 present in cache after reload")
	}
}

func TestReloadCache_InvalidKey(t *testing.T) {
	store := NewMockStore()

	enc := MockEncryptor{
		ForceDecryptError: true,
	}

	store.Save(&Key{
		KID:          "broken",
		Alg:          AlgRS256,
		IsActive:     true,
		EncryptedKey: &EncryptedKey{Nonce: []byte{1, 2, 3}, Ciphertext: []byte{4, 5, 6}},
	})

	km := &KeyManager{
		store:     store,
		encryptor: enc,
		active:    make(map[Alg]*CachedKey),
		cache:     make(map[string]*CachedKey),
	}

	err := km.ReloadCache()
	if err == nil {
		t.Fatalf("expected ReloadCache error when decrypt fails")
	}
}

func TestReloadCache_UpdatesChangedStore(t *testing.T) {
	store := NewMockStore()
	enc := MockEncryptor{}

	priv1, _ := generatePrivateKey(AlgRS256)
	raw1, _ := marshalPKCS8(priv1)
	encKey1, _ := enc.Encrypt(raw1)

	k1 := &Key{
		KID:          "k1",
		Alg:          AlgRS256,
		IsActive:     true,
		EncryptedKey: encKey1,
	}

	store.Save(k1)

	km, _ := NewKeyManager(store, enc, func() (RotationConfig, error) {
		return RotationConfig{}, nil
	})

	priv2, _ := generatePrivateKey(AlgRS256)
	raw2, _ := marshalPKCS8(priv2)
	encKey2, _ := enc.Encrypt(raw2)

	k2 := &Key{
		KID:          "k2",
		Alg:          AlgRS256,
		IsActive:     true,
		EncryptedKey: encKey2,
	}

	store.Save(k2)

	err := km.ReloadCache()
	if err != nil {
		t.Fatalf("reload failed: %v", err)
	}

	ck := km.activeKey(AlgRS256)
	if ck.key.KID != "k2" {
		t.Fatalf("expected active k2 after reload, got %s", ck.key.KID)
	}
}
