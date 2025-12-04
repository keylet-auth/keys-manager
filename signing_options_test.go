package keys_manager

import (
	"crypto"
	"testing"
)

func TestSigningOptions(t *testing.T) {
	tests := []struct {
		name     string
		alg      Alg
		wantHash crypto.Hash
		wantErr  bool
	}{
		{
			name:     "RS256 uses SHA256",
			alg:      AlgRS256,
			wantHash: crypto.SHA256,
		},
		{
			name:     "ES256 uses SHA256",
			alg:      AlgES256,
			wantHash: crypto.SHA256,
		},
		{
			name:     "EdDSA uses Hash(0)",
			alg:      AlgEdDSA,
			wantHash: crypto.Hash(0),
		},
		{
			name:    "Unsupported algorithm returns error",
			alg:     Alg("INVALID"),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			opts, err := signingOptions(tt.alg)

			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for alg %q, got nil", tt.alg)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error for alg %q: %v", tt.alg, err)
			}

			hashOpt, ok := opts.(crypto.Hash)
			if !ok {
				t.Fatalf("opts is not crypto.Hash, got %T", opts)
			}

			if hashOpt != tt.wantHash {
				t.Fatalf("expected hash %v, got %v", tt.wantHash, hashOpt)
			}
		})
	}
}
