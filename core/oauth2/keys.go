package oauth2

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
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
	eBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(eBytes, uint32(key.E))

	// Trim leading zeros
	start := 0
	for start < len(eBytes) && eBytes[start] == 0 {
		start++
	}
	eStr := base64.RawURLEncoding.EncodeToString(eBytes[start:])

	return JWK{
		Kty: "RSA",
		Alg: "RS256",
		Use: "sig",
		Kid: kid,
		N:   n,
		E:   eStr,
	}
}
