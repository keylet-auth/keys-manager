package keys_manager

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func TestGeneratePrivateKey(t *testing.T) {
	tests := []struct {
		name     string
		alg      Alg
		wantType interface{}
		wantErr  bool
	}{
		{
			name:     "RS256 returns RSA key",
			alg:      AlgRS256,
			wantType: &rsa.PrivateKey{},
		},
		{
			name:     "ES256 returns ECDSA P-256 key",
			alg:      AlgES256,
			wantType: &ecdsa.PrivateKey{},
		},
		{
			name:     "EdDSA returns Ed25519 key",
			alg:      AlgEdDSA,
			wantType: ed25519.PrivateKey{},
		},
		{
			name:    "Unknown algorithm returns error",
			alg:     Alg("INVALID"),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signer, err := generatePrivateKey(tt.alg)

			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for alg %q, got nil", tt.alg)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error for alg %q: %v", tt.alg, err)
			}

			switch tt.wantType.(type) {
			case *rsa.PrivateKey:
				if _, ok := signer.(*rsa.PrivateKey); !ok {
					t.Fatalf("expected RSA key, got %T", signer)
				}

			case *ecdsa.PrivateKey:
				if _, ok := signer.(*ecdsa.PrivateKey); !ok {
					t.Fatalf("expected ECDSA key, got %T", signer)
				}

			case ed25519.PrivateKey:
				if _, ok := signer.(ed25519.PrivateKey); !ok {
					t.Fatalf("expected Ed25519 key, got %T", signer)
				}
			}
			
			if _, err := signer.Sign(rand.Reader, []byte("test"), crypto.Hash(0)); err != nil {
				if tt.alg == AlgEdDSA {
					t.Fatalf("ed25519 signer must sign raw payload: %v", err)
				}
			}
		})
	}
}
