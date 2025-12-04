package keys_manager

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"
)

func TestVerifySignature_RS256(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa generate: %v", err)
	}

	payload := []byte("test message")

	h := sha256.New()
	h.Write(payload)
	digest := h.Sum(nil)

	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, digest)
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	err = verifySignature(AlgRS256, &priv.PublicKey, payload, sig)
	if err != nil {
		t.Fatalf("verify failed on valid signature: %v", err)
	}

	sig[0] ^= 0xFF

	if err := verifySignature(AlgRS256, &priv.PublicKey, payload, sig); err == nil {
		t.Fatalf("verify should fail on modified signature")
	}

	if err := verifySignature(AlgRS256, ed25519.PublicKey{}, payload, sig); err == nil {
		t.Fatalf("verify should fail on wrong key type")
	}
}

func TestVerifySignature_ES256(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa generate: %v", err)
	}

	payload := []byte("hello es256")

	h := sha256.New()
	h.Write(payload)
	digest := h.Sum(nil)

	r, s, err := ecdsa.Sign(rand.Reader, priv, digest)
	if err != nil {
		t.Fatalf("ecdsa sign failed: %v", err)
	}

	rb := r.Bytes()
	sb := s.Bytes()

	rbPadded := make([]byte, 32)
	sbPadded := make([]byte, 32)
	copy(rbPadded[32-len(rb):], rb)
	copy(sbPadded[32-len(sb):], sb)

	sig := append(rbPadded, sbPadded...)

	if err := verifySignature(AlgES256, &priv.PublicKey, payload, sig); err != nil {
		t.Fatalf("verify failed: %v", err)
	}

	sig[10] ^= 0xAA
	if err := verifySignature(AlgES256, &priv.PublicKey, payload, sig); err == nil {
		t.Fatalf("verify should fail on modified signature")
	}

	if err := verifySignature(AlgES256, ed25519.PublicKey{}, payload, sig); err == nil {
		t.Fatalf("verify should fail on wrong key type")
	}
}

func TestVerifySignature_EdDSA(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 generate: %v", err)
	}

	payload := []byte("hello eddsa")

	sig := ed25519.Sign(priv, payload)

	if err := verifySignature(AlgEdDSA, pub, payload, sig); err != nil {
		t.Fatalf("verify failed: %v", err)
	}

	sig[3] ^= 0x55
	if err := verifySignature(AlgEdDSA, pub, payload, sig); err == nil {
		t.Fatalf("verify should fail on bad signature")
	}

	if err := verifySignature(AlgEdDSA, &rsa.PublicKey{}, payload, sig); err == nil {
		t.Fatalf("verify should fail on wrong key type")
	}
}

func TestVerifySignature_UnsupportedAlg(t *testing.T) {
	err := verifySignature(Alg("BAD"), nil, []byte("x"), []byte("y"))
	if err == nil {
		t.Fatal("expected error for unsupported algorithm")
	}
}
