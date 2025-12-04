# 🔐 Key Manager Library

A lightweight, extensible, production-ready key management subsystem designed for applications that require:

- secure storage of private keys
- automated and manual key rotation
- in-memory caching of active keys
- cryptographic signing and verification
- publishing public keys in JWK/JWKS format
- pluggable encryption and storage backends

The library focuses on security, simplicity, and clean separation of concerns.

---

## ✨ Features
### 🔸 Secure storage of private keys

All private keys are stored only in encrypted form using a pluggable Encryptor interface.
A built-in AES-256-GCM encryptor is included out of the box.

### 🔸 Automated and manual key rotation

The KeyManager supports two rotation workflows:
- Manual rotation per algorithm (Rotate(alg))
- Automatic rotation for expired keys during cache reload (ReloadCache())

Rotation policies (TTL, metadata, future constraints) are provided via a user-defined RotationPolicy function.

### 🔸 In-memory key cache

To avoid unnecessary decryption and database access, the manager maintains two caches:

- cache[kid] — all known keys
- active[alg] — currently active signing key per algorithm

Caches are fully rebuilt during `ReloadCache()`.

### 🔸 Signing and verification

The manager supports signing and verification using:

- RSA (RS256)
- ECDSA P-256 (ES256)
- Ed25519 (EdDSA)

The design keeps signing and verification algorithm-agnostic, relying on Go’s `crypto.Signer` interfaces.

### 🔸 Public key export (JWKS)

The manager can produce a JWKS document containing all public keys stored in the system.

### 🔸 Pluggable backends

The following interfaces allow full customization:

| Interface          | Purpose                                                |
| ------------------ | ------------------------------------------------------ |
| **Store**          | Storage of encrypted private keys, metadata, key state |
| **Encryptor**      | Encryption/decryption of private keys at rest          |
| **RotationPolicy** | Defines TTL and rotation behavior                      |

You can implement backends using files, SQL, Redis, Vault, KMS, HSM, or any other mechanism.

### 🔸 Included AES-256-GCM encryptor

The package ships with a secure AES-GCM based encryptor:

- takes a 32-byte master key
- encrypts/decrypts PKCS8 private keys
- uses random nonces
- authenticated encryption (AEAD)

This enables safe use in Kubernetes by storing the master key as a base64-encoded secret.

---

## 📦 Installation

```bash
go get github.com/keylet-auth/keys-manager
```
---

## 🚀 Quick Start

### 1. Create an Encryptor (AES-GCM)

```go
masterKey := mustLoad32ByteKeyFromEnv()
encryptor, err := NewAESGCMEncryptor(masterKey)
```

### 2. Provide a Store implementation
Example: a simple in-memory or database-backed store implementing:

```go
type Store interface {
    Save(key *Key) error
    List() ([]*Key, error)
    GetByKID(kid string) (*Key, error)
    Rotate(newKey *Key, oldKey *Key) error
}
```

### 3. Create a KeyManager

```go
km, err := NewKeyManager(store, encryptor, func() (RotationConfig, error) {
    return RotationConfig{TTL: time.Hour * 24}, nil
})
```

### 4. Rotate keys

```go
if err := km.Rotate(AlgRS256); err != nil {
    log.Fatal(err)
}
```

### 5. Sign or verify data

```go
sig, err := km.Sign(AlgRS256, data)
err = km.Verify(kid, AlgRS256, data, sig)
```

### 6. Export public keys (JWKS)

```go
jwksJSON, _ := km.JWKS()
```
---

## 🔧 Architecture Overview

```
┌──────────────────────────────┐
│          KeyManager          │
│------------------------------│
│ - caches active keys         │
│ - loads from Store           │
│ - decrypts via Encryptor     │
│ - rotates keys automatically │
│ - exposes sign/verify        │
└─────────────┬────────────────┘
              │
   ┌──────────┴──────────┐
   ▼                     ▼
Encryptor            Store
AES-GCM (built-in)   DB / Redis / Vault / KMS / FS / custom
```
The KeyManager itself does not store any unencrypted private keys on disk,
and does not control where or how keys are persisted — this is delegated to the Store.
---

## 🔒 Included AES-GCM Encryptor

The library contains a production-grade implementation:
- AES-256-GCM
- random per-encryption nonce
- authenticated encryption
- works with raw PKCS8 private key bytes
- deterministic decryption
- safe failure modes

Master key storage example for Kubernetes:

```bash
kubectl create secret generic key-manager-secret \
  --from-literal=MASTER_KEY=$(openssl rand -base64 32)
```

and then mount via env or file.

---

## 🧪 Testing
The library includes a rich test suite covering:
- signing & verification
- rotation logic
- cache rebuilding
- AES-GCM encryption/decryption
- corrupted data handling
- time-based expiration checks
---

## 🛠 Extending the Library
You can:
- add new algorithms
- integrate external KMS/HSM
- implement multi-region Stores
- version encryption keys
- implement master-key rotation
- publish JWKS for distributed systems
The architecture is intentionally modular and easy to extend.
---
## 📄 License
MIT License.

---
## 🤖 Note
**This README was assisted/generated by AI**