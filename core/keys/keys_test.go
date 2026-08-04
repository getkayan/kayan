package keys

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

// testKeys builds one key per supported algorithm family.
func testKeys(t *testing.T) map[string]*Key {
	t.Helper()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA key: %v", err)
	}
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate Ed25519 key: %v", err)
	}

	return map[string]*Key{
		"RS256": {KID: "rsa-1", Method: jwt.SigningMethodRS256, Private: rsaKey, Public: &rsaKey.PublicKey},
		"ES256": {KID: "ec-1", Method: jwt.SigningMethodES256, Private: ecKey, Public: &ecKey.PublicKey},
		"EdDSA": {KID: "ed-1", Method: jwt.SigningMethodEdDSA, Private: edPriv, Public: edPub},
		"HS256": {KID: "hmac-1", Method: jwt.SigningMethodHS256, Private: []byte("symmetric-secret-for-tests-only")},
	}
}

// TestSignAndVerifyAcrossAlgorithms proves the algorithm is genuinely the
// caller's choice: the same wiring signs and verifies with RSA, ECDSA, Ed25519,
// and HMAC without any change to Kayan.
func TestSignAndVerifyAcrossAlgorithms(t *testing.T) {
	ctx := context.Background()

	for alg, key := range testKeys(t) {
		t.Run(alg, func(t *testing.T) {
			provider := NewStaticProvider(key)
			signer := NewJWTSigner(provider)

			claims := jwt.MapClaims{"sub": "user-1", "iss": "https://kayan.test"}
			token, err := signer.Sign(ctx, claims, nil)
			if err != nil {
				t.Fatalf("sign: %v", err)
			}

			parsed, err := jwt.Parse(token, Keyfunc(ctx, provider))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if !parsed.Valid {
				t.Fatal("token reported invalid")
			}
			if got := parsed.Method.Alg(); got != alg {
				t.Errorf("alg = %q, want %q", got, alg)
			}
			if got := parsed.Header["kid"]; got != key.KID {
				t.Errorf("kid = %v, want %q", got, key.KID)
			}
		})
	}
}

// TestKeyfuncRejectsAlgorithmConfusion is the regression test for the attack
// where a token issued under an asymmetric key is re-signed as HMAC using the
// public key as the shared secret.
//
// The assertion deliberately inspects Keyfunc's own error rather than settling
// for "jwt.Parse failed". golang-jwt independently refuses to verify HMAC with
// an *rsa.PublicKey, so a test that only checked err != nil would keep passing
// with this package's algorithm check deleted — it would be testing the
// dependency, not the code here.
func TestKeyfuncRejectsAlgorithmConfusion(t *testing.T) {
	ctx := context.Background()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	key := &Key{KID: "rsa-1", Method: jwt.SigningMethodRS256, Private: rsaKey, Public: &rsaKey.PublicKey}
	provider := NewStaticProvider(key)

	// Forge a token that claims the same kid but is signed HS256.
	forged := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": "attacker"})
	forged.Header["kid"] = "rsa-1"
	raw, err := forged.SignedString([]byte("does-not-matter"))
	if err != nil {
		t.Fatalf("sign forged token: %v", err)
	}

	// Drive Keyfunc directly: it must refuse to hand back any key material.
	header, _, err := jwt.NewParser().ParseUnverified(raw, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("parse forged token header: %v", err)
	}

	material, err := Keyfunc(ctx, provider)(header)
	if err == nil {
		t.Fatal("Keyfunc returned a key for a token whose alg does not match the key")
	}
	if material != nil {
		t.Errorf("Keyfunc returned key material (%T) alongside an error", material)
	}
	if !strings.Contains(err.Error(), "does not match key") {
		t.Errorf("error = %v, want the algorithm mismatch from this package", err)
	}

	// End to end, the forged token must not verify.
	if _, err := jwt.Parse(raw, Keyfunc(ctx, provider)); err == nil {
		t.Fatal("algorithm confusion accepted: forged HS256 token verified against an RS256 key")
	}
}

// TestKeyfuncRejectsUnknownKID proves an unknown kid does not silently fall
// back to the active key.
func TestKeyfuncRejectsUnknownKID(t *testing.T) {
	ctx := context.Background()
	keys := testKeys(t)
	provider := NewStaticProvider(keys["RS256"])

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"sub": "user-1"})
	token.Header["kid"] = "not-a-real-kid"
	raw, err := token.SignedString(keys["RS256"].Private)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	_, err = jwt.Parse(raw, Keyfunc(ctx, provider))
	if !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("error = %v, want ErrKeyNotFound", err)
	}
}

// TestKeyfuncRejectsMissingKID proves a token with no kid is rejected rather
// than defaulting to whichever key happens to be active.
func TestKeyfuncRejectsMissingKID(t *testing.T) {
	ctx := context.Background()
	keys := testKeys(t)
	provider := NewStaticProvider(keys["RS256"])

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"sub": "user-1"})
	raw, err := token.SignedString(keys["RS256"].Private)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if _, err := jwt.Parse(raw, Keyfunc(ctx, provider)); err == nil {
		t.Fatal("token without kid was accepted")
	}
}

// TestRotation is the requirement from the plan: after rotating, tokens issued
// under the old key still verify, and newly issued tokens carry the new kid.
func TestRotation(t *testing.T) {
	ctx := context.Background()

	oldRSA, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate old key: %v", err)
	}
	newRSA, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate new key: %v", err)
	}

	oldKey := &Key{KID: "kid-A", Method: jwt.SigningMethodRS256, Private: oldRSA, Public: &oldRSA.PublicKey}
	newKey := &Key{KID: "kid-B", Method: jwt.SigningMethodRS256, Private: newRSA, Public: &newRSA.PublicKey}

	provider := NewStaticProvider(oldKey)
	signer := NewJWTSigner(provider)

	// Issue under kid-A.
	tokenA, err := signer.Sign(ctx, jwt.MapClaims{"sub": "user-1"}, nil)
	if err != nil {
		t.Fatalf("sign under kid-A: %v", err)
	}

	if err := provider.Rotate(newKey); err != nil {
		t.Fatalf("rotate: %v", err)
	}

	// The pre-rotation token must still verify.
	if _, err := jwt.Parse(tokenA, Keyfunc(ctx, provider)); err != nil {
		t.Fatalf("token issued before rotation no longer verifies: %v", err)
	}

	// New tokens must carry kid-B.
	tokenB, err := signer.Sign(ctx, jwt.MapClaims{"sub": "user-1"}, nil)
	if err != nil {
		t.Fatalf("sign after rotation: %v", err)
	}
	parsed, err := jwt.Parse(tokenB, Keyfunc(ctx, provider))
	if err != nil {
		t.Fatalf("parse post-rotation token: %v", err)
	}
	if got := parsed.Header["kid"]; got != "kid-B" {
		t.Errorf("kid = %v, want kid-B", got)
	}

	// Both keys must remain publishable so relying parties can verify either.
	jwks, err := BuildJWKS(ctx, provider)
	if err != nil {
		t.Fatalf("build JWKS: %v", err)
	}
	if len(jwks.Keys) != 2 {
		t.Fatalf("JWKS has %d keys, want 2", len(jwks.Keys))
	}
	if jwks.Keys[0].Kid != "kid-B" {
		t.Errorf("first JWKS key = %q, want the active key kid-B", jwks.Keys[0].Kid)
	}
}

func TestStaticProviderRejectsInvalidKeys(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	tests := []struct {
		name string
		key  *Key
	}{
		{"nil key", nil},
		{"missing KID", &Key{Method: jwt.SigningMethodRS256, Private: rsaKey}},
		{"missing method", &Key{KID: "k", Private: rsaKey}},
		{"no private key", &Key{KID: "k", Method: jwt.SigningMethodRS256, Public: &rsaKey.PublicKey}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewStaticProviderWithError(tc.key); err == nil {
				t.Fatal("invalid key accepted")
			}
		})
	}
}

func TestStaticProviderRejectsDuplicateKID(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	active := &Key{KID: "same", Method: jwt.SigningMethodRS256, Private: rsaKey, Public: &rsaKey.PublicKey}
	retired := &Key{KID: "same", Method: jwt.SigningMethodRS256, Public: &rsaKey.PublicKey}

	if _, err := NewStaticProviderWithError(active, retired); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("error = %v, want ErrInvalidKey", err)
	}
}

// TestRetiredKeyCannotSign proves a verification-only key is never promoted
// into the signing path.
func TestRetiredKeyCannotSign(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	verifyOnly := &Key{KID: "old", Method: jwt.SigningMethodRS256, Public: &rsaKey.PublicKey}

	if verifyOnly.CanSign() {
		t.Fatal("key without private material reports CanSign")
	}
	provider := NewStaticProvider(
		&Key{KID: "new", Method: jwt.SigningMethodRS256, Private: rsaKey, Public: &rsaKey.PublicKey},
		verifyOnly,
	)
	if err := provider.Rotate(verifyOnly); err == nil {
		t.Fatal("rotated to a key that cannot sign")
	}
}

func TestPublicKeyOfDerivesFromPrivate(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	// Public deliberately omitted.
	k := &Key{KID: "k", Method: jwt.SigningMethodRS256, Private: rsaKey}
	pub, err := PublicKeyOf(k)
	if err != nil {
		t.Fatalf("PublicKeyOf: %v", err)
	}
	if pub.(*rsa.PublicKey).N.Cmp(rsaKey.PublicKey.N) != 0 {
		t.Error("derived public key does not match the private key")
	}
}
