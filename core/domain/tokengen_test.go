package domain

import (
	"encoding/base64"
	"testing"
)

// The token generator produces magic-link tokens, OTP secrets, authorization
// codes and refresh tokens. Its only job is to be unguessable, and nothing
// tested that it is.

// TestGeneratedTokensAreUnique. A generator that repeats issues one user's
// magic link to another. Collisions at this size are impossible by chance, so
// any repeat here means the source is not random.
func TestGeneratedTokensAreUnique(t *testing.T) {
	generate := NewTokenGenerator(DefaultTokenBytes)

	const rounds = 2000
	seen := make(map[string]bool, rounds)
	for range rounds {
		token, err := generate()
		if err != nil {
			t.Fatalf("generate: %v", err)
		}
		if seen[token] {
			t.Fatalf("a token repeated within %d draws; the source is not random", rounds)
		}
		seen[token] = true
	}
}

// TestTokenCarriesTheRequestedEntropy. The encoded form is what callers see,
// so it is easy to check its length and believe the entropy matches. Decoding
// is what actually measures it.
func TestTokenCarriesTheRequestedEntropy(t *testing.T) {
	for _, size := range []int{16, 32, 64} {
		token, err := NewTokenGenerator(size)()
		if err != nil {
			t.Fatalf("generate: %v", err)
		}

		raw, err := base64.RawURLEncoding.DecodeString(token)
		if err != nil {
			t.Fatalf("token is not unpadded base64url: %v", err)
		}
		if len(raw) != size {
			t.Errorf("token decodes to %d bytes, want %d", len(raw), size)
		}
	}
}

// TestWeakGeneratorPanicsAtStartup.
//
// Fewer than 128 bits is guessable at scale. The panic is deliberate: a
// generator configured too small should stop the process at startup rather
// than spend the deployment's lifetime issuing tokens an attacker can reach.
func TestWeakGeneratorPanicsAtStartup(t *testing.T) {
	for _, size := range []int{0, 1, 8, 15} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("a %d-byte generator was accepted", size)
				}
			}()
			NewTokenGenerator(size)
		}()
	}

	// 16 bytes is the documented floor and must be allowed.
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("a 16-byte generator panicked: %v", r)
		}
	}()
	NewTokenGenerator(16)
}

// TestDefaultsAreStrongEnough pins the constants themselves. A later edit that
// lowered either would weaken every token in the library at once, and no other
// test would object.
func TestDefaultsAreStrongEnough(t *testing.T) {
	if DefaultTokenBytes < 16 {
		t.Errorf("DefaultTokenBytes is %d; below 16 is under 128 bits", DefaultTokenBytes)
	}

	token, err := DefaultTokenGenerator()
	if err != nil {
		t.Fatalf("DefaultTokenGenerator: %v", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(raw) != DefaultTokenBytes {
		t.Errorf("the default generator produced %d bytes, want %d", len(raw), DefaultTokenBytes)
	}
}

// TestTokenGeneratorOrDefault. A component handed no generator must fall back
// to the strong default rather than to a zero value that produces nothing.
func TestTokenGeneratorOrDefault(t *testing.T) {
	token, err := TokenGeneratorOrDefault(nil)()
	if err != nil {
		t.Fatalf("the nil fallback failed: %v", err)
	}
	if token == "" {
		t.Fatal("the nil fallback produced an empty token")
	}

	// A supplied generator is used as given, not silently replaced.
	custom := TokenGenerator(func() (string, error) { return "supplied", nil })
	got, err := TokenGeneratorOrDefault(custom)()
	if err != nil {
		t.Fatalf("supplied generator: %v", err)
	}
	if got != "supplied" {
		t.Errorf("token = %q, want the supplied generator to be used", got)
	}
}

// TestTokensAreURLSafe. These travel in magic links and query strings; a
// token needing escaping would be corrupted by any layer that re-encodes it,
// and the failure would look like an invalid token rather than a mangled one.
func TestTokensAreURLSafe(t *testing.T) {
	generate := NewTokenGenerator(DefaultTokenBytes)

	for range 200 {
		token, err := generate()
		if err != nil {
			t.Fatalf("generate: %v", err)
		}
		for _, r := range token {
			isSafe := (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') ||
				(r >= '0' && r <= '9') || r == '-' || r == '_'
			if !isSafe {
				t.Fatalf("token %q contains %q, which needs escaping in a URL", token, r)
			}
		}
	}
}
