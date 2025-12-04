package keys_manager

type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use,omitempty"`

	// RSA
	N string `json:"n,omitempty"`
	E string `json:"e,omitempty"`

	// EC
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`

	// Ed25519 (OKP)
	CrvOKP string `json:"crv,omitempty"`
	XOKP   string `json:"x,omitempty"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}
