package oidc

import (
	"context"
	"crypto"
	"encoding/base64"
	"fmt"

	// Registers the digests the signing algorithms below use.
	_ "crypto/sha256"
	_ "crypto/sha512"
)

// signingAlgorithm reports the JWS algorithm ID tokens are signed with, which
// is what decides the digest used for at_hash and c_hash.
func (s *Server) signingAlgorithm(ctx context.Context) (string, error) {
	if s.keyProvider == nil {
		// The fallback signing path hardcodes RS256.
		return "RS256", nil
	}
	key, err := s.keyProvider.Active(ctx)
	if err != nil {
		return "", fmt.Errorf("oidc: resolve signing key: %w", err)
	}
	if key == nil || key.Method == nil {
		return "", fmt.Errorf("oidc: signing key carries no algorithm")
	}
	return key.Method.Alg(), nil
}

// halfHash computes an OIDC Core section 3.1.3.6 hash claim: the value is
// digested with the hash the signing algorithm uses, and the claim is the
// left-most half of that digest, base64url-encoded without padding.
//
// The digest is tied to the signing algorithm rather than fixed at SHA-256,
// because a relying party derives which hash to verify with from the token's
// "alg" header. Emitting a SHA-256 hash in an ES512-signed token produces a
// value every conforming client rejects.
func halfHash(algorithm, value string) (string, error) {
	digest, err := digestFor(algorithm)
	if err != nil {
		return "", err
	}

	hasher := digest.New()
	hasher.Write([]byte(value))
	sum := hasher.Sum(nil)

	return base64.RawURLEncoding.EncodeToString(sum[:len(sum)/2]), nil
}

// digestFor maps a JWS algorithm to the hash its "SHA-2 family" suffix names.
func digestFor(algorithm string) (crypto.Hash, error) {
	switch algorithm {
	case "RS256", "ES256", "PS256", "HS256":
		return crypto.SHA256, nil
	case "RS384", "ES384", "PS384", "HS384":
		return crypto.SHA384, nil
	case "RS512", "ES512", "PS512", "HS512":
		return crypto.SHA512, nil
	case "EdDSA":
		// Ed25519 signs with SHA-512 internally, and OIDC Core leaves the hash
		// for EdDSA unspecified. SHA-512 is what the surrounding signature
		// uses, so it is the consistent choice.
		return crypto.SHA512, nil
	default:
		return 0, fmt.Errorf("oidc: no hash defined for signing algorithm %q", algorithm)
	}
}
