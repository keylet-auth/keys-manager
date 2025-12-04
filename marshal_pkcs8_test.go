package keys_manager

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"testing"
)

func TestMarshalPKCS8_AllKeyTypes(t *testing.T) {
	tests := []struct {
		name   string
		newKey func() (crypto.Signer, error)
	}{
		{
			name: "RSA",
			newKey: func() (crypto.Signer, error) {
				return rsa.GenerateKey(rand.Reader, 2048)
			},
		},
		{
			name: "ECDSA P-256",
			newKey: func() (crypto.Signer, error) {
				return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			},
		},
		{
			name: "Ed25519",
			newKey: func() (crypto.Signer, error) {
				_, priv, err := ed25519.GenerateKey(rand.Reader)
				return priv, err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			priv, err := tt.newKey()
			if err != nil {
				t.Fatalf("failed to generate key: %v", err)
			}

			der, err := marshalPKCS8(priv)
			if err != nil {
				t.Fatalf("marshalPKCS8 returned error: %v", err)
			}

			if len(der) == 0 {
				t.Fatalf("marshalPKCS8 returned empty DER")
			}

			parsed, err := x509.ParsePKCS8PrivateKey(der)
			if err != nil {
				t.Fatalf("DER cannot be parsed back as PKCS#8: %v", err)
			}

			switch parsed.(type) {
			case *rsa.PrivateKey:
				if _, ok := priv.(*rsa.PrivateKey); !ok {
					t.Fatalf("parsed key type mismatch: expected RSA")
				}
			case *ecdsa.PrivateKey:
				if _, ok := priv.(*ecdsa.PrivateKey); !ok {
					t.Fatalf("parsed key type mismatch: expected ECDSA")
				}
			case ed25519.PrivateKey:
				if _, ok := priv.(ed25519.PrivateKey); !ok {
					t.Fatalf("parsed key type mismatch: expected Ed25519")
				}
			default:
				t.Fatalf("parsed key type unsupported: %T", parsed)
			}
		})
	}
}
