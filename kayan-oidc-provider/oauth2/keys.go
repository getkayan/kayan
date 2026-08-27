package oauth2

import (
	"crypto/rsa"
	"encoding/base64"
	"math/big"
)

// JWK represents a JSON Web Key.
type JWK struct {
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// JWKS represents a JSON Web Key Set.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// PublicKeyToJWK converts an RSA public key to a JWK.
func PublicKeyToJWK(key *rsa.PublicKey, kid string) JWK {
	n := base64.RawURLEncoding.EncodeToString(key.N.Bytes())

	// Encode E as base64url per RFC 7518
	eStr := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())

	return JWK{
		Kty: "RSA",
		Alg: "RS256",
		Use: "sig",
		Kid: kid,
		N:   n,
		E:   eStr,
	}
}
