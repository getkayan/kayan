package keys

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"
)

// JWK is a JSON Web Key (RFC 7517).
//
// Only the members needed for the key types Kayan publishes are present.
// Members not applicable to a key type are omitted from the JSON.
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
	Kid string `json:"kid,omitempty"`

	// RSA (RFC 7518 section 6.3).
	N string `json:"n,omitempty"`
	E string `json:"e,omitempty"`

	// EC and OKP (RFC 7518 section 6.2, RFC 8037 section 2).
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}

// JWKS is a JSON Web Key Set (RFC 7517 section 5).
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// KeyToJWK converts the public half of k to a JWK.
//
// RSA, ECDSA (P-256, P-384, P-521), and Ed25519 keys are supported. Symmetric
// keys return [ErrUnsupportedKey]: publishing an HMAC secret in JWKS would
// disclose the signing key.
func KeyToJWK(k *Key) (JWK, error) {
	if err := k.Validate(); err != nil {
		return JWK{}, err
	}

	pub, err := PublicKeyOf(k)
	if err != nil {
		return JWK{}, err
	}

	jwk := JWK{
		Use: k.keyUse(),
		Alg: k.Algorithm(),
		Kid: k.KID,
	}

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		jwk.Kty = "RSA"
		jwk.N = base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
		jwk.E = encodeExponent(pub.E)

	case *ecdsa.PublicKey:
		crv, size, err := curveParams(pub.Curve)
		if err != nil {
			return JWK{}, fmt.Errorf("%w: key %q: %w", ErrUnsupportedKey, k.KID, err)
		}
		jwk.Kty = "EC"
		jwk.Crv = crv
		// RFC 7518 section 6.2.1.2 requires the octet strings be left-padded to
		// the full coordinate size; Bytes() drops leading zeros.
		jwk.X = encodeCoordinate(pub.X, size)
		jwk.Y = encodeCoordinate(pub.Y, size)

	case ed25519.PublicKey:
		jwk.Kty = "OKP"
		jwk.Crv = "Ed25519"
		jwk.X = base64.RawURLEncoding.EncodeToString(pub)

	default:
		return JWK{}, fmt.Errorf("%w: key %q has type %T", ErrUnsupportedKey, k.KID, pub)
	}

	return jwk, nil
}

// BuildJWKS assembles the key set to publish at the JWKS endpoint.
//
// Keys that cannot be represented as a JWK — symmetric keys in particular —
// are skipped rather than failing the whole set, so an HS256 session key
// alongside an RS256 token key does not break the endpoint.
//
// The caller serves the result; Kayan does not write HTTP responses.
//
//	jwks, err := keys.BuildJWKS(ctx, provider)
//	if err != nil { /* ... */ }
//	json.NewEncoder(w).Encode(jwks)
func BuildJWKS(ctx context.Context, p Provider) (JWKS, error) {
	if p == nil {
		return JWKS{}, ErrNoKey
	}

	all, err := p.Verification(ctx)
	if err != nil {
		return JWKS{}, err
	}

	set := JWKS{Keys: make([]JWK, 0, len(all))}
	for _, k := range all {
		jwk, err := KeyToJWK(k)
		if err != nil {
			// Symmetric and unrepresentable keys simply do not belong in JWKS.
			continue
		}
		set.Keys = append(set.Keys, jwk)
	}
	return set, nil
}

// encodeExponent renders an RSA public exponent as base64url with leading
// zero bytes removed, per RFC 7518 section 6.3.1.2.
func encodeExponent(e int) string {
	if e <= 0 {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(big.NewInt(int64(e)).Bytes())
}

// encodeCoordinate renders an EC coordinate as a fixed-width base64url octet
// string, left-padded to size bytes as RFC 7518 section 6.2.1.2 requires.
func encodeCoordinate(v *big.Int, size int) string {
	b := v.Bytes()
	if len(b) < size {
		padded := make([]byte, size)
		copy(padded[size-len(b):], b)
		b = padded
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// curveParams maps an elliptic curve to its JWK name and coordinate size.
func curveParams(c elliptic.Curve) (name string, size int, err error) {
	switch c {
	case elliptic.P256():
		return "P-256", 32, nil
	case elliptic.P384():
		return "P-384", 48, nil
	case elliptic.P521():
		// 521 bits rounds up to 66 octets.
		return "P-521", 66, nil
	default:
		return "", 0, fmt.Errorf("unsupported curve")
	}
}
