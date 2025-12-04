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

func TestParsePrivateKey_AllKeyTypes(t *testing.T) {
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
			original, err := tt.newKey()
			if err != nil {
				t.Fatalf("cannot generate key: %v", err)
			}

			der, err := x509.MarshalPKCS8PrivateKey(original)
			if err != nil {
				t.Fatalf("marshal pkcs8 error: %v", err)
			}

			parsed, err := parsePrivateKey(der)
			if err != nil {
				t.Fatalf("parsePrivateKey failed: %v", err)
			}

			switch original.(type) {
			case *rsa.PrivateKey:
				if _, ok := parsed.(*rsa.PrivateKey); !ok {
					t.Fatalf("expected RSA key, got %T", parsed)
				}
			case *ecdsa.PrivateKey:
				if _, ok := parsed.(*ecdsa.PrivateKey); !ok {
					t.Fatalf("expected ECDSA key, got %T", parsed)
				}
			case ed25519.PrivateKey:
				if _, ok := parsed.(ed25519.PrivateKey); !ok {
					t.Fatalf("expected Ed25519 key, got %T", parsed)
				}
			default:
				t.Fatalf("unexpected key type in test: %T", original)
			}
		})
	}
}
