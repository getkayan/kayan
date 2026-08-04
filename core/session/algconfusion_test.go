package session

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Algorithm-confusion corpus.
//
// When a strategy is configured with an asymmetric key, the verifying key is
// public. An attacker who re-signs a token as HS256 using that public key as
// the HMAC secret produces a token that verifies — unless the algorithm is
// pinned to the one the strategy was configured with.
//
// Every entry point that parses a token must reject the whole corpus. Delete
// was the path that did not, which let an attacker revoke any session.

func newRSAStrategy(t *testing.T) (*JWTStrategy, *rsa.PrivateKey) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	strategy := NewJWTStrategy(JWTConfig{
		SigningMethod: jwt.SigningMethodRS256,
		SigningKey:    key,
		VerifyingKey:  &key.PublicKey,
		Expiry:        time.Hour,
	})
	return strategy, key
}

// publicKeyPEM renders a public key the way it is normally published — in a
// JWKS document, in metadata, or in a config file. This is the attacker's
// input: it is not secret.
func publicKeyPEM(t *testing.T, pub *rsa.PublicKey) []byte {
	t.Helper()

	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

// forgedTokens builds the corpus for a strategy configured with key.
func forgedTokens(t *testing.T, key *rsa.PrivateKey) map[string]string {
	t.Helper()

	claims := &JWTClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "victim",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	corpus := make(map[string]string)

	// The classic attack: HMAC with the PEM-encoded public key as the secret.
	hs256 := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	raw, err := hs256.SignedString(publicKeyPEM(t, &key.PublicKey))
	if err != nil {
		t.Fatalf("sign HS256 with the public key PEM: %v", err)
	}
	corpus["HS256 signed with the public key PEM"] = raw

	// Same attack with the DER bytes, which some verifiers hand over instead.
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	hs256der := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	raw, err = hs256der.SignedString(der)
	if err != nil {
		t.Fatalf("sign HS256 with the public key DER: %v", err)
	}
	corpus["HS256 signed with the public key DER"] = raw

	// A stronger HMAC variant, in case only HS256 were special-cased.
	hs512 := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	raw, err = hs512.SignedString(publicKeyPEM(t, &key.PublicKey))
	if err != nil {
		t.Fatalf("sign HS512 with the public key PEM: %v", err)
	}
	corpus["HS512 signed with the public key PEM"] = raw

	// alg:none — an unsigned token asserting the same claims.
	none := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
	raw, err = none.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("sign alg:none: %v", err)
	}
	corpus["alg:none"] = raw

	return corpus
}

// TestAlgorithmConfusionRejectedOnEveryPath drives the corpus through every
// method that parses a token. A gap on any one of them is exploitable.
func TestAlgorithmConfusionRejectedOnEveryPath(t *testing.T) {
	strategy, key := newRSAStrategy(t)
	corpus := forgedTokens(t, key)

	// Delete only parses when a revocation store is configured; without one it
	// is a no-op and would report success for any input.
	revoking := NewJWTStrategy(JWTConfig{
		SigningMethod: jwt.SigningMethodRS256,
		SigningKey:    key,
		VerifyingKey:  &key.PublicKey,
		Expiry:        time.Hour,
	}).WithRevocationStore(NewMemoryRevocationStore())

	for name, token := range corpus {
		t.Run(name, func(t *testing.T) {
			t.Run("Validate", func(t *testing.T) {
				if _, err := strategy.Validate(token); err == nil {
					t.Fatal("forged token accepted")
				}
			})

			t.Run("Refresh", func(t *testing.T) {
				if _, err := strategy.Refresh(token); err == nil {
					t.Fatal("forged token accepted")
				}
			})

			t.Run("Delete", func(t *testing.T) {
				err := revoking.Delete(token)
				if err == nil {
					t.Fatal("forged token accepted: an attacker could revoke any session")
				}
				// Assert the rejection comes from the algorithm pin rather than
				// an incidental failure, so the test still fails if the pin is
				// removed.
				if !strings.Contains(err.Error(), "unexpected signing method") {
					t.Errorf("error = %v, want rejection by the algorithm pin", err)
				}
			})
		})
	}
}

// TestGenuineTokenStillWorks guards against the fix rejecting everything.
func TestGenuineTokenStillWorks(t *testing.T) {
	strategy, key := newRSAStrategy(t)
	revoking := NewJWTStrategy(JWTConfig{
		SigningMethod: jwt.SigningMethodRS256,
		SigningKey:    key,
		VerifyingKey:  &key.PublicKey,
		Expiry:        time.Hour,
	}).WithRevocationStore(NewMemoryRevocationStore())

	sess, err := revoking.Create("ignored", "user-1")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if _, err := strategy.Validate(sess.ID); err != nil {
		t.Fatalf("a genuine token failed to validate: %v", err)
	}
	if err := revoking.Delete(sess.ID); err != nil {
		t.Fatalf("a genuine token failed to delete: %v", err)
	}
	if _, err := revoking.Validate(sess.ID); err == nil {
		t.Error("the session validated after being revoked")
	}
}

// TestHMACStrategyRejectsAsymmetricTokens covers the mirror case: a strategy
// configured for HS256 must not accept an RS256 token.
func TestHMACStrategyRejectsAsymmetricTokens(t *testing.T) {
	strategy := NewHS256Strategy("test-secret-not-for-production", time.Hour)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, &JWTClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "attacker",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	})
	raw, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if _, err := strategy.Validate(raw); err == nil {
		t.Fatal("an RS256 token was accepted by an HS256 strategy")
	}
}
