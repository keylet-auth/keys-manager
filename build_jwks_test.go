package keys_manager

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func TestBuildJWKS_AllKeysReturned(t *testing.T) {
	// --- generate keys ---
	rsaPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	edPub, _, _ := ed25519.GenerateKey(rand.Reader)

	cache := map[string]*CachedKey{
		"rsa": {
			key: &Key{KID: "rsa1", Alg: AlgRS256, IsActive: true},
			pub: &rsaPriv.PublicKey,
		},
		"ec": {
			key: &Key{KID: "ec1", Alg: AlgES256, IsActive: false},
			pub: &ecPriv.PublicKey,
		},
		"okp": {
			key: &Key{KID: "okp1", Alg: AlgEdDSA, IsActive: true},
			pub: edPub,
		},
	}

	jwks := buildJWKS(cache)

	if len(jwks.Keys) != 3 {
		t.Fatalf("expected all 3 keys in JWKS, got %d", len(jwks.Keys))
	}

	find := func(kid string) *JWK {
		for _, k := range jwks.Keys {
			if k.Kid == kid {
				return &k
			}
		}
		return nil
	}

	// --- RSA ---
	rsaJWK := find("rsa1")
	if rsaJWK == nil {
		t.Fatalf("RSA key missing from JWKS")
	}
	if rsaJWK.Kty != "RSA" || rsaJWK.Alg != "RS256" {
		t.Fatalf("invalid RSA jwk: %+v", rsaJWK)
	}
	if rsaJWK.N == "" || rsaJWK.E == "" {
		t.Fatalf("RSA fields missing")
	}

	// --- EC ---
	ecJWK := find("ec1")
	if ecJWK == nil {
		t.Fatalf("EC key missing from JWKS")
	}
	if ecJWK.Kty != "EC" || ecJWK.Crv != "P-256" {
		t.Fatalf("invalid EC jwk: %+v", ecJWK)
	}
	if ecJWK.X == "" || ecJWK.Y == "" {
		t.Fatalf("EC fields missing")
	}

	// --- Ed25519 ---
	okpJWK := find("okp1")
	if okpJWK == nil {
		t.Fatalf("OKP key missing from JWKS")
	}
	if okpJWK.Kty != "OKP" || okpJWK.Crv != "Ed25519" {
		t.Fatalf("invalid OKP jwk: %+v", okpJWK)
	}
	if okpJWK.X == "" {
		t.Fatalf("OKP field X missing")
	}
}
