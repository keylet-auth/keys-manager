package keys_manager

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"time"
)

func b64(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func b64big(i *big.Int) string {
	return b64(i.Bytes())
}

func generateKID(alg Alg) string {
	const size = 12

	buf := make([]byte, size)

	_, err := rand.Read(buf)

	if err == nil {
		randomPart := base64.RawURLEncoding.EncodeToString(buf)
		return fmt.Sprintf("%s_%s", alg, randomPart)
	}

	ts := []byte(time.Now().Format(time.RFC3339Nano))
	fallback := base64.RawURLEncoding.EncodeToString(append(ts, buf...))

	return fmt.Sprintf("%s_%s", alg, fallback)
}

func signingOptions(alg Alg) (crypto.SignerOpts, error) {
	switch alg {
	case AlgRS256, AlgES256:
		return crypto.SHA256, nil
	case AlgEdDSA:
		return crypto.Hash(0), nil
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", alg)
	}
}

func marshalPKCS8(priv crypto.Signer) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("marshal pkcs8: %w", err)
	}

	return der, nil
}

func parsePrivateKey(der []byte) (crypto.Signer, error) {
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse pkcs8: %w", err)
	}

	switch k := key.(type) {
	case *rsa.PrivateKey:
		return k, nil
	case *ecdsa.PrivateKey:
		return k, nil
	case ed25519.PrivateKey:
		return k, nil
	default:
		return nil, fmt.Errorf("unsupported private key type %T", k)
	}
}

func verifySignature(alg Alg, pub crypto.PublicKey, payload, sig []byte) error {
	switch alg {
	case AlgRS256:
		rsaKey, ok := pub.(*rsa.PublicKey)
		if !ok {
			return errors.New("verify: public key is not RSA")
		}

		h := sha256.New()
		h.Write(payload)
		digest := h.Sum(nil)

		if err := rsa.VerifyPKCS1v15(rsaKey, crypto.SHA256, digest, sig); err != nil {
			return fmt.Errorf("verify: rsa signature invalid: %w", err)
		}
		return nil

	case AlgES256:
		ecKey, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return errors.New("verify: public key is not ECDSA")
		}

		h := sha256.New()
		h.Write(payload)
		digest := h.Sum(nil)

		if len(sig)%2 != 0 {
			return errors.New("verify: invalid ECDSA signature length")
		}
		half := len(sig) / 2

		r := new(big.Int).SetBytes(sig[:half])
		s := new(big.Int).SetBytes(sig[half:])

		if !ecdsa.Verify(ecKey, digest, r, s) {
			return errors.New("verify: ecdsa signature invalid")
		}

		return nil

	case AlgEdDSA:
		edKey, ok := pub.(ed25519.PublicKey)
		if !ok {
			return errors.New("verify: public key is not Ed25519")
		}

		if !ed25519.Verify(edKey, payload, sig) {
			return errors.New("verify: eddsa signature invalid")
		}

		return nil

	default:
		return fmt.Errorf("verify: unsupported alg %q", alg)
	}
}

func generatePrivateKey(alg Alg) (crypto.Signer, error) {
	switch alg {
	case AlgRS256:
		return rsa.GenerateKey(rand.Reader, 2048)
	case AlgES256:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case AlgEdDSA:
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		return priv, err
	}
	return nil, fmt.Errorf("unknown alg: %s", alg)
}

func buildJWKS(cache map[string]*CachedKey) *JWKS {
	out := &JWKS{Keys: []JWK{}}

	for _, ck := range cache {
		if ck == nil || ck.key == nil {
			continue
		}

		k := JWK{
			Kid: ck.key.KID,
			Alg: string(ck.key.Alg),
			Use: "sig",
		}

		switch pub := ck.pub.(type) {

		// -------------------------
		// RSA
		// -------------------------
		case *rsa.PublicKey:
			k.Kty = "RSA"
			k.N = b64big(pub.N)
			k.E = b64big(big.NewInt(int64(pub.E)))

		// -------------------------
		// EC (ES256)
		// -------------------------
		case *ecdsa.PublicKey:
			k.Kty = "EC"
			k.Crv = "P-256"
			k.X = b64big(pub.X)
			k.Y = b64big(pub.Y)

		// -------------------------
		// OKP (Ed25519)
		// -------------------------
		case ed25519.PublicKey:
			k.Kty = "OKP"
			k.Crv = "Ed25519"
			k.X = b64(pub)

		default:
			continue
		}

		out.Keys = append(out.Keys, k)
	}

	return out
}
