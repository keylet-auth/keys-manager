package keys_manager

import (
	"crypto"
	"fmt"
	"testing"
	"time"
)

type FailingEncryptor struct {
	Fail bool
}

func (e FailingEncryptor) Encrypt(b []byte) (*EncryptedKey, error) {
	if e.Fail {
		return nil, fmt.Errorf("encrypt failed")
	}
	return (&MockEncryptor{}).Encrypt(b)
}

func (e FailingEncryptor) Decrypt(k *EncryptedKey) ([]byte, error) {
	return (&MockEncryptor{}).Decrypt(k)
}

type FailingStore struct {
	MockStore
	FailList   bool
	FailRotate bool
}

func (s *FailingStore) List() ([]*Key, error) {
	if s.FailList {
		return nil, fmt.Errorf("list failed")
	}
	return s.MockStore.List()
}

func (s *FailingStore) Rotate(new, old *Key) error {
	if s.FailRotate {
		return fmt.Errorf("rotate failed")
	}
	return s.MockStore.Rotate(new, old)
}

func TestRotate_ExistingKey(t *testing.T) {
	store := NewMockStore()
	enc := MockEncryptor{}

	oldPriv, _ := generatePrivateKey(AlgRS256)
	exp := time.Now().Add(time.Hour)

	oldKey := makeTestKey("old", AlgRS256, true, &exp, enc, oldPriv)
	store.Save(oldKey)

	km, _ := NewKeyManager(store, enc, func() (RotationConfig, error) {
		return RotationConfig{TTL: time.Hour}, nil
	})

	err := km.Rotate(AlgRS256)
	if err != nil {
		t.Fatalf("Rotate returned error: %v", err)
	}

	keys, _ := store.List()
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys after rotation, got %d", len(keys))
	}

	var oldInactive, newActive bool
	var newKey *Key

	for _, k := range keys {
		if k.KID == "old" {
			if k.IsActive {
				t.Fatalf("old key must be inactive after rotation")
			}
			oldInactive = true
		} else {
			if !k.IsActive {
				t.Fatalf("new key must be active")
			}
			newActive = true
			newKey = k
		}
	}

	if !oldInactive || !newActive {
		t.Fatalf("some keys missing after rotation")
	}

	if newKey.ExpiresAt == nil {
		t.Fatalf("new key must have ExpiresAt")
	}
	if newKey.ExpiresAt.Before(time.Now()) {
		t.Fatalf("ExpiresAt must be in the future")
	}
}

func TestRotate_NoExistingKey(t *testing.T) {
	store := NewMockStore()
	enc := MockEncryptor{}

	km, _ := NewKeyManager(store, enc, func() (RotationConfig, error) {
		return RotationConfig{TTL: 2 * time.Hour}, nil
	})

	err := km.Rotate(AlgRS256)
	if err != nil {
		t.Fatalf("Rotate returned error: %v", err)
	}

	keys, _ := store.List()
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}

	k := keys[0]

	if !k.IsActive {
		t.Fatalf("newly created key must be active")
	}
	if k.ExpiresAt == nil {
		t.Fatalf("ExpiresAt not set")
	}
	if k.ExpiresAt.Before(time.Now().Add(1 * time.Hour)) {
		t.Fatalf("ExpiresAt should respect TTL=2h")
	}
}

func TestRotate_GeneratesUniqueKID(t *testing.T) {
	store := NewMockStore()
	enc := MockEncryptor{}

	km, _ := NewKeyManager(store, enc, func() (RotationConfig, error) {
		return RotationConfig{TTL: time.Hour}, nil
	})

	_ = km.Rotate(AlgRS256)
	keys1, _ := store.List()
	kid1 := keys1[0].KID

	_ = km.Rotate(AlgRS256)
	keys2, _ := store.List()

	var kid2 string
	for _, k := range keys2 {
		if k.KID != kid1 {
			kid2 = k.KID
			break
		}
	}

	if kid1 == kid2 {
		t.Fatalf("Rotate must produce new unique KID")
	}
}

func TestRotate_EncryptorFails(t *testing.T) {
	store := NewMockStore()

	km, _ := NewKeyManager(store, FailingEncryptor{Fail: true}, func() (RotationConfig, error) {
		return RotationConfig{TTL: time.Hour}, nil
	})

	err := km.Rotate(AlgRS256)
	if err == nil {
		t.Fatalf("expected error when Encrypt fails")
	}
}

func TestRotate_StoreListFailsDuringRotate(t *testing.T) {
	store := &FailingStore{
		MockStore: *NewMockStore(),
		FailList:  false,
	}

	enc := MockEncryptor{}

	km, err := NewKeyManager(store, enc, func() (RotationConfig, error) {
		return RotationConfig{TTL: time.Hour}, nil
	})
	if err != nil {
		t.Fatalf("unexpected init error: %v", err)
	}

	priv, _ := generatePrivateKey(AlgRS256)
	exp := time.Now().Add(time.Hour)
	oldKey := makeTestKey("old", AlgRS256, true, &exp, enc, priv)
	_ = store.Save(oldKey)

	store.FailList = true

	err = km.Rotate(AlgRS256)
	if err == nil {
		t.Fatalf("expected error when store.List fails during Rotate, got nil")
	}
}

func TestRotate_StoreRotateFails(t *testing.T) {
	store := &FailingStore{
		MockStore:  *NewMockStore(),
		FailRotate: true,
	}

	enc := MockEncryptor{}

	km, _ := NewKeyManager(store, enc, func() (RotationConfig, error) {
		return RotationConfig{TTL: time.Hour}, nil
	})

	err := km.Rotate(AlgRS256)
	if err == nil {
		t.Fatalf("expected error when store.Rotate fails")
	}
}

func TestRotate_PolicyFails(t *testing.T) {
	store := NewMockStore()
	enc := MockEncryptor{}

	km, _ := NewKeyManager(store, enc, func() (RotationConfig, error) {
		return RotationConfig{}, fmt.Errorf("policy error")
	})

	err := km.Rotate(AlgRS256)
	if err == nil {
		t.Fatalf("expected error from failed policy()")
	}
}

func makeTestKey(kid string, alg Alg, active bool, exp *time.Time, enc Encryptor, priv crypto.Signer) *Key {
	raw, _ := marshalPKCS8(priv)
	encKey, _ := enc.Encrypt(raw)

	return &Key{
		KID:          kid,
		Alg:          alg,
		IsActive:     active,
		CreatedAt:    time.Now(),
		ExpiresAt:    exp,
		EncryptedKey: encKey,
	}
}
