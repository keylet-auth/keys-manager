package keys_manager

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestGenerateKID_BasicProperties(t *testing.T) {
	algs := []Alg{AlgRS256, AlgES256, AlgEdDSA}

	for _, alg := range algs {
		t.Run(string(alg), func(t *testing.T) {
			kid := generateKID(alg)

			prefix := string(alg) + "_"
			if !strings.HasPrefix(kid, prefix) {
				t.Fatalf("[%s] kid %q does not start with prefix %q",
					alg, kid, prefix)
			}

			b64 := kid[len(prefix):]

			_, err := base64.RawURLEncoding.DecodeString(b64)
			if err != nil {
				t.Fatalf("[%s] kid %q has invalid base64 %q: %v",
					alg, kid, b64, err)
			}

			if strings.Contains(b64, "=") {
				t.Fatalf("[%s] kid %q contains '=' padding", alg, kid)
			}

			if len(kid) <= len(prefix) {
				t.Fatalf("[%s] kid %q too short", alg, kid)
			}
		})
	}
}

func TestGenerateKID_Uniqueness(t *testing.T) {
	kid1 := generateKID(AlgRS256)
	kid2 := generateKID(AlgRS256)

	if kid1 == kid2 {
		t.Fatalf("two KIDs are equal: %q and %q", kid1, kid2)
	}
}
