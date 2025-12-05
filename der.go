package keys_manager

import (
	"encoding/asn1"
	"fmt"
	"math/big"
)

type ecdsaSignature struct {
	R, S *big.Int
}

func DERToRawECDSA(alg Alg, der []byte) ([]byte, error) {
	var sig ecdsaSignature

	_, err := asn1.Unmarshal(der, &sig)
	if err != nil {
		return nil, fmt.Errorf("asn1 unmarshal: %w", err)
	}

	var size = 32

	rBytes := sig.R.Bytes()
	sBytes := sig.S.Bytes()

	if len(rBytes) > size || len(sBytes) > size {
		return nil, fmt.Errorf("R/S too large for alg %s", alg)
	}

	raw := make([]byte, size*2)

	copy(raw[size-len(rBytes):size], rBytes)
	copy(raw[2*size-len(sBytes):], sBytes)

	return raw, nil
}
