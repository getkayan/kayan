package keys

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
)

// Errors returned when reading a JWK supplied by someone else.
var (
	// ErrMalformedJWK reports a key that could not be read as one.
	ErrMalformedJWK = errors.New("keys: malformed JWK")

	// ErrSymmetricJWK reports an "oct" key where a public key was required.
	//
	// It is separate from [ErrUnsupportedKey] because the mistake it catches
	// is specific: verifying an asymmetric signature against a symmetric key
	// is the algorithm-confusion attack, and a caller that reads a generic
	// "unsupported" cannot tell that case from an unfamiliar curve.
	ErrSymmetricJWK = errors.New("keys: symmetric JWK cannot be used as a public key")
)

// ParseJWKS reads a JSON Web Key Set (RFC 7517 section 5).
//
// It is the inverse of [BuildJWKS] and exists for the direction where the key
// set came from somebody else: a relying party's registered keys, or a
// federation partner's published set. It validates nothing beyond the JSON
// shape -- call [JWK.PublicKey] to turn an individual key into something
// usable, since that is where a key can fail to be one.
func ParseJWKS(data []byte) (JWKS, error) {
	var set JWKS
	if err := json.Unmarshal(data, &set); err != nil {
		return JWKS{}, fmt.Errorf("%w: %v", ErrMalformedJWK, err)
	}
	return set, nil
}

// Find returns the key with the given kid.
//
// An empty kid matches only when the set holds exactly one key. Falling back
// to "the first key" for a kid-less token is how a signature made with a
// retired key keeps verifying after a rotation, so the ambiguous case is a
// miss rather than a guess.
func (s JWKS) Find(kid string) (JWK, bool) {
	if kid == "" {
		if len(s.Keys) == 1 {
			return s.Keys[0], true
		}
		return JWK{}, false
	}
	for _, key := range s.Keys {
		if key.Kid == kid {
			return key, true
		}
	}
	return JWK{}, false
}

// PublicKey converts j into a usable public key.
//
// RSA, ECDSA (P-256, P-384, P-521), and Ed25519 are supported, matching what
// [KeyToJWK] produces. An "oct" key returns [ErrSymmetricJWK]: handing an HMAC
// secret to a routine that expects a public key is the shape of the
// algorithm-confusion attack, where a token signed with HS256 over the
// published RSA modulus verifies as if it were RS256.
func (j JWK) PublicKey() (crypto.PublicKey, error) {
	switch j.Kty {
	case "RSA":
		n, err := decodeBigInt(j.N, "n")
		if err != nil {
			return nil, err
		}
		e, err := decodeBase64URL(j.E, "e")
		if err != nil {
			return nil, err
		}
		if len(e) == 0 || len(e) > 8 {
			// Beyond 8 bytes the exponent cannot fit an int, and a zero-length
			// one is not a number at all.
			return nil, fmt.Errorf("%w: exponent length %d", ErrMalformedJWK, len(e))
		}
		exponent := 0
		for _, b := range e {
			exponent = exponent<<8 | int(b)
		}
		if exponent < 2 {
			return nil, fmt.Errorf("%w: RSA exponent %d", ErrMalformedJWK, exponent)
		}
		// A short modulus is not a key, it is a signature that anyone can
		// forge. RFC 7518 requires at least 2048 bits for RS256.
		if n.BitLen() < 2048 {
			return nil, fmt.Errorf("%w: RSA modulus is %d bits, minimum 2048",
				ErrMalformedJWK, n.BitLen())
		}
		return &rsa.PublicKey{N: n, E: exponent}, nil

	case "EC":
		curve, size, err := curveForName(j.Crv)
		if err != nil {
			return nil, err
		}
		x, err := decodeCoordinate(j.X, "x", size)
		if err != nil {
			return nil, err
		}
		y, err := decodeCoordinate(j.Y, "y", size)
		if err != nil {
			return nil, err
		}
		key := &ecdsa.PublicKey{Curve: curve, X: x, Y: y}
		// A point off the curve is not a public key. Accepting one enables
		// invalid-curve attacks, where the arithmetic leaks the private
		// scalar of whatever key is used alongside it.
		if !curve.IsOnCurve(x, y) {
			return nil, fmt.Errorf("%w: EC point is not on %s", ErrMalformedJWK, j.Crv)
		}
		return key, nil

	case "OKP":
		if j.Crv != "Ed25519" {
			return nil, fmt.Errorf("%w: OKP curve %q", ErrUnsupportedKey, j.Crv)
		}
		x, err := decodeBase64URL(j.X, "x")
		if err != nil {
			return nil, err
		}
		if len(x) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%w: Ed25519 key is %d bytes, want %d",
				ErrMalformedJWK, len(x), ed25519.PublicKeySize)
		}
		return ed25519.PublicKey(x), nil

	case "oct":
		return nil, ErrSymmetricJWK

	default:
		return nil, fmt.Errorf("%w: kty %q", ErrUnsupportedKey, j.Kty)
	}
}

// curveForName maps a JWK curve name to its curve and coordinate width.
func curveForName(name string) (elliptic.Curve, int, error) {
	switch name {
	case "P-256":
		return elliptic.P256(), 32, nil
	case "P-384":
		return elliptic.P384(), 48, nil
	case "P-521":
		return elliptic.P521(), 66, nil
	default:
		return nil, 0, fmt.Errorf("%w: EC curve %q", ErrUnsupportedKey, name)
	}
}

// decodeBase64URL decodes an unpadded base64url member.
func decodeBase64URL(value, member string) ([]byte, error) {
	if value == "" {
		return nil, fmt.Errorf("%w: %q is missing", ErrMalformedJWK, member)
	}
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("%w: %q: %v", ErrMalformedJWK, member, err)
	}
	return raw, nil
}

// decodeBigInt decodes a member into a positive integer.
func decodeBigInt(value, member string) (*big.Int, error) {
	raw, err := decodeBase64URL(value, member)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(raw), nil
}

// decodeCoordinate decodes an EC coordinate, requiring the fixed width its
// curve defines.
//
// RFC 7518 section 6.2.1.2 requires the octet string to be exactly the field
// size, left-padded. Accepting a short one would let two different encodings
// of the same key produce different thumbprints.
func decodeCoordinate(value, member string, size int) (*big.Int, error) {
	raw, err := decodeBase64URL(value, member)
	if err != nil {
		return nil, err
	}
	if len(raw) != size {
		return nil, fmt.Errorf("%w: %q is %d bytes, want %d for this curve",
			ErrMalformedJWK, member, len(raw), size)
	}
	return new(big.Int).SetBytes(raw), nil
}
