package keys_manager

import (
	"errors"
	"testing"
	"time"
)

func mockPolicy() (RotationConfig, error) {
	return RotationConfig{TTL: time.Hour}, nil
}

func TestInitKeys_KeyAlreadyExists_NoRotate(t *testing.T) {
	store := NewMockStore()
	enc := MockEncryptor{}

	priv, _ := generatePrivateKey(AlgRS256)
	exp := time.Now().Add(time.Hour)

	existing := makeTestKey("old", AlgRS256, true, &exp, enc, priv)
	store.Save(existing)

	km, err := NewKeyManager(store, enc, mockPolicy)
	if err != nil {
		t.Fatalf("NewKeyManager error: %v", err)
	}

	err = km.InitKeys([]Alg{AlgRS256})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if store.RotateCount != 0 {
		t.Fatalf("Rotate was called unexpectedly: %d", store.RotateCount)
	}
}

func TestInitKeys_MissingKey_RotateCalled(t *testing.T) {
	store := NewMockStore()
	enc := MockEncryptor{}

	km, err := NewKeyManager(store, enc, mockPolicy)
	if err != nil {
		t.Fatalf("NewKeyManager error: %v", err)
	}

	err = km.InitKeys([]Alg{AlgRS256})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if store.RotateCount != 1 {
		t.Fatalf("expected Rotate to be called once, got %d", store.RotateCount)
	}
}

func TestInitKeys_PartialKeys(t *testing.T) {
	store := NewMockStore()
	enc := MockEncryptor{}

	priv, _ := generatePrivateKey(AlgRS256)
	exp := time.Now().Add(time.Hour)
	store.Save(makeTestKey("old", AlgRS256, true, &exp, enc, priv))

	km, err := NewKeyManager(store, enc, mockPolicy)
	if err != nil {
		t.Fatalf("NewKeyManager error: %v", err)
	}

	err = km.InitKeys([]Alg{AlgRS256, AlgES256})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if store.RotateCount != 1 {
		t.Fatalf("expected Rotate to be called once (ES256), got %d", store.RotateCount)
	}
}

func TestInitKeys_RotateFails(t *testing.T) {
	store := NewMockStore()
	enc := MockEncryptor{}

	store.RotateErr = errors.New("boom")

	km, err := NewKeyManager(store, enc, mockPolicy)
	if err != nil {
		t.Fatalf("NewKeyManager error: %v", err)
	}

	err = km.InitKeys([]Alg{AlgRS256})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}
