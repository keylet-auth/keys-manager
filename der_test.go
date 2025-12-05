package keys_manager

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"math/big"
	"strings"
	"testing"
)

func TestDERToRawECDSA_Success(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	data := []byte("hello world")
	hash := sha256.Sum256(data)

	der, err := priv.Sign(rand.Reader, hash[:], nil)
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	raw, err := DERToRawECDSA(AlgES256, der)
	if err != nil {
		t.Fatalf("DERToRawECDSA failed: %v", err)
	}

	if len(raw) != 64 {
		t.Fatalf("expected raw len = 64, got %d", len(raw))
	}

	r := new(big.Int).SetBytes(raw[:32])
	s := new(big.Int).SetBytes(raw[32:])

	if !ecdsa.Verify(&priv.PublicKey, hash[:], r, s) {
		t.Fatal("ecdsa.Verify returned false for valid signature")
	}
}

func TestDERToRawECDSA_Padding(t *testing.T) {
	sig := ecdsaSignature{
		R: big.NewInt(12345),
		S: big.NewInt(67890),
	}

	der, err := asn1.Marshal(sig)
	if err != nil {
		t.Fatalf("asn1 marshal failed: %v", err)
	}

	raw, err := DERToRawECDSA(AlgES256, der)
	if err != nil {
		t.Fatalf("DERToRawECDSA failed: %v", err)
	}

	if len(raw) != 64 {
		t.Fatalf("expected raw len = 64, got %d", len(raw))
	}

	if raw[31] == 0 {
		t.Errorf("expected last byte of R to be non-zero (padding incorrect)")
	}

	if raw[63] == 0 {
		t.Errorf("expected last byte of S to be non-zero (padding incorrect)")
	}
}

func TestDERToRawECDSA_RTooLarge(t *testing.T) {
	rBytes := make([]byte, 33)
	rBytes[0] = 1
	r := new(big.Int).SetBytes(rBytes)

	s := big.NewInt(1)

	der, err := asn1.Marshal(ecdsaSignature{R: r, S: s})
	if err != nil {
		t.Fatalf("asn1 marshal failed: %v", err)
	}

	_, err = DERToRawECDSA(AlgES256, der)
	if err == nil {
		t.Fatal("expected error for R too large, got nil")
	}

	if !strings.Contains(err.Error(), "R/S too large") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDERToRawECDSA_STooLarge(t *testing.T) {
	sBytes := make([]byte, 33)
	sBytes[0] = 1
	s := new(big.Int).SetBytes(sBytes)

	r := big.NewInt(1)

	der, err := asn1.Marshal(ecdsaSignature{R: r, S: s})
	if err != nil {
		t.Fatalf("asn1 marshal failed: %v", err)
	}

	_, err = DERToRawECDSA(AlgES256, der)
	if err == nil {
		t.Fatal("expected error for S too large, got nil")
	}

	if !strings.Contains(err.Error(), "R/S too large") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDERToRawECDSA_InvalidDER(t *testing.T) {
	_, err := DERToRawECDSA(AlgES256, []byte{0xFF, 0x00, 0x01})
	if err == nil {
		t.Fatal("expected ASN.1 error, got nil")
	}

	if !strings.Contains(err.Error(), "asn1 unmarshal") {
		t.Fatalf("unexpected error: %v", err)
	}
}
