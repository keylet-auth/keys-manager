package keys_manager

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"testing"
)

func isBase64URL(t *testing.T, s string) {
	t.Helper()
	_, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("invalid base64url: %v, value=%s", err, s)
	}
}

func TestBuildJWKS_RS256(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("RSA key gen error: %v", err)
	}

	ck := &CachedKey{
		key: &Key{
			KID: "rs1",
			Alg: AlgRS256,
		},
		priv: priv,
		pub:  &priv.PublicKey,
	}

	jwks := buildJWKS(map[string]*CachedKey{"rs1": ck})

	if len(jwks.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(jwks.Keys))
	}

	k := jwks.Keys[0]

	if k.Kty != "RSA" {
		t.Fatalf("expected kty=RSA, got %s", k.Kty)
	}
	if k.Alg != "RS256" {
		t.Fatalf("expected alg=RS256, got %s", k.Alg)
	}
	if k.Kid != "rs1" {
		t.Fatalf("expected kid=rs1, got %s", k.Kid)
	}

	if k.N == "" {
		t.Fatalf("missing modulus N")
	}
	if k.E == "" {
		t.Fatalf("missing exponent E")
	}

	isBase64URL(t, k.N)
	isBase64URL(t, k.E)
}

func TestBuildJWKS_ES256(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ECDSA key gen error: %v", err)
	}

	ck := &CachedKey{
		key: &Key{
			KID: "ec1",
			Alg: AlgES256,
		},
		priv: priv,
		pub:  &priv.PublicKey,
	}

	jwks := buildJWKS(map[string]*CachedKey{"ec1": ck})

	if len(jwks.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(jwks.Keys))
	}

	k := jwks.Keys[0]

	if k.Kty != "EC" {
		t.Fatalf("expected kty=EC, got %s", k.Kty)
	}
	if k.Crv != "P-256" {
		t.Fatalf("expected crv=P-256, got %s", k.Crv)
	}

	if k.X == "" || k.Y == "" {
		t.Fatalf("missing EC x/y coordinates")
	}

	isBase64URL(t, k.X)
	isBase64URL(t, k.Y)
}

func TestBuildJWKS_Ed25519(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Ed25519 key gen error: %v", err)
	}

	ck := &CachedKey{
		key: &Key{
			KID: "ed1",
			Alg: AlgEdDSA,
		},
		priv: priv,
		pub:  pub,
	}

	jwks := buildJWKS(map[string]*CachedKey{"ed1": ck})

	if len(jwks.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(jwks.Keys))
	}

	k := jwks.Keys[0]

	if k.Kty != "OKP" {
		t.Fatalf("expected kty=OKP, got %s", k.Kty)
	}
	if k.Crv != "Ed25519" {
		t.Fatalf("expected crv=Ed25519, got %s", k.Crv)
	}
	if k.X == "" {
		t.Fatalf("missing Ed25519 public key x")
	}

	isBase64URL(t, k.X)

	if k.Y != "" {
		t.Fatalf("Y must be empty for OKP keys, got %s", k.Y)
	}
}

func TestBuildJWKS_SkipNilKeys(t *testing.T) {
	jwks := buildJWKS(map[string]*CachedKey{
		"a": nil,
		"b": {key: nil},
	})

	if len(jwks.Keys) != 0 {
		t.Fatalf("expected 0 keys, got %d", len(jwks.Keys))
	}
}
