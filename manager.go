package keys_manager

import (
	"crypto"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

type KeyManager struct {
	store     Store
	encryptor Encryptor
	policy    RotationPolicy

	mu     sync.RWMutex
	active map[Alg]*CachedKey
	cache  map[string]*CachedKey
}

func NewKeyManager(
	store Store,
	enc Encryptor,
	policy RotationPolicy,
) (*KeyManager, error) {
	km := &KeyManager{
		store:     store,
		encryptor: enc,
		policy:    policy,
		active:    make(map[Alg]*CachedKey),
		cache:     make(map[string]*CachedKey),
	}

	if err := km.ReloadCache(); err != nil {
		return nil, err
	}

	return km, nil
}

func (km *KeyManager) activeKey(alg Alg) *CachedKey {
	km.mu.RLock()
	ck := km.active[alg]
	km.mu.RUnlock()

	if ck != nil {
		return ck
	}

	_ = km.ReloadCache()

	km.mu.RLock()
	defer km.mu.RUnlock()
	return km.active[alg]
}

func (km *KeyManager) keyByKID(kid string) *CachedKey {
	km.mu.RLock()
	ck := km.cache[kid]
	km.mu.RUnlock()

	if ck != nil {
		return ck
	}

	_ = km.ReloadCache()

	km.mu.RLock()
	defer km.mu.RUnlock()
	return km.cache[kid]
}

func (km *KeyManager) Sign(
	alg Alg,
	build func(kid string) ([]byte, error),
) ([]byte, error) {
	ck := km.activeKey(alg)
	if ck == nil {
		return nil, fmt.Errorf("no active key for alg %s", alg)
	}

	signingInput, err := build(ck.key.KID)
	if err != nil {
		return nil, err
	}

	opts, err := signingOptions(alg)
	if err != nil {
		return nil, err
	}

	var digest []byte
	if opts.HashFunc() != crypto.Hash(0) {
		h := opts.HashFunc().New()
		h.Write(signingInput)
		digest = h.Sum(nil)
	} else {
		digest = signingInput
	}

	sig, err := ck.priv.Sign(rand.Reader, digest, opts)
	if err != nil {
		return nil, err
	}

	if alg != AlgES256 {
		return sig, nil
	}

	rawSig, err := DERToRawECDSA(alg, sig)
	if err != nil {
		return nil, fmt.Errorf("ecdsa convert: %w", err)
	}

	return rawSig, nil
}

func (km *KeyManager) Verify(kid string, payload, sig []byte) error {
	ck := km.keyByKID(kid)
	if ck == nil {
		return fmt.Errorf("key %s not found", kid)
	}

	return verifySignature(ck.key.Alg, ck.pub, payload, sig)
}

func (km *KeyManager) JWKS() ([]byte, error) {
	km.mu.RLock()
	defer km.mu.RUnlock()

	jwks := buildJWKS(km.cache)
	return json.Marshal(jwks)
}

func (km *KeyManager) Rotate(alg Alg) error {
	policy, err := km.policy()
	if err != nil {
		return err
	}

	keys, err := km.store.List()
	if err != nil {
		return err
	}

	var oldKey *Key
	for _, k := range keys {
		if k.Alg == alg && k.IsActive {
			cloned := *k
			cloned.IsActive = false
			oldKey = &cloned
			break
		}
	}

	newPriv, err := generatePrivateKey(alg)
	if err != nil {
		return err
	}

	privBytes, err := marshalPKCS8(newPriv)
	if err != nil {
		return err
	}

	encrypted, err := km.encryptor.Encrypt(privBytes)
	if err != nil {
		return err
	}

	now := time.Now()
	expires := now.Add(policy.TTL)

	newKey := &Key{
		Alg:          alg,
		IsActive:     true,
		CreatedAt:    now,
		ExpiresAt:    &expires,
		EncryptedKey: encrypted,
		KID:          generateKID(alg),
	}

	if err := km.store.Rotate(newKey, oldKey); err != nil {
		return err
	}

	return km.ReloadCache()
}

func (km *KeyManager) RotateExpired() error {
	km.mu.RLock()
	active := make(map[Alg]*CachedKey, len(km.active))
	for alg, ck := range km.active {
		active[alg] = ck
	}
	km.mu.RUnlock()

	now := time.Now()
	var errs []error

	for alg, ck := range active {
		if ck.key.ExpiresAt != nil && ck.key.ExpiresAt.Before(now) {
			if err := km.Rotate(alg); err != nil {
				errs = append(errs, fmt.Errorf("rotate %s: %w", alg, err))
			}
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("rotation errors: %v", errs)
	}

	return nil
}

func (km *KeyManager) ReloadCache() error {
	keys, err := km.store.List()
	if err != nil {
		return err
	}

	newCache := make(map[string]*CachedKey)
	newActive := make(map[Alg]*CachedKey)

	for _, k := range keys {
		privBytes, err := km.encryptor.Decrypt(k.EncryptedKey)
		if err != nil {
			return fmt.Errorf("decrypt key %s: %w", k.KID, err)
		}

		priv, err := parsePrivateKey(privBytes)
		if err != nil {
			return fmt.Errorf("parse key %s: %w", k.KID, err)
		}

		ck := &CachedKey{
			key:  k,
			priv: priv,
			pub:  priv.Public(),
		}

		newCache[k.KID] = ck

		if k.IsActive {
			newActive[k.Alg] = ck
		}
	}

	km.mu.Lock()
	km.cache = newCache
	km.active = newActive
	km.mu.Unlock()

	return nil
}

func (km *KeyManager) InitKeys(algs []Alg) error {
	for _, alg := range algs {
		km.mu.RLock()
		_, exists := km.active[alg]
		km.mu.RUnlock()

		if exists {
			continue
		}

		if err := km.Rotate(alg); err != nil {
			return fmt.Errorf("failed to initialize key for alg %s: %w", alg, err)
		}
	}

	return nil
}
