package oauth2

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/getkayan/kayan/core/keys"
	"github.com/golang-jwt/jwt/v5"
)

// newRotatingKeys builds a provider holding two RSA keys: an active one and a
// retired one that must still verify.
func newRotatingKeys(t *testing.T) (*keys.StaticProvider, *keys.Key, *keys.Key) {
	t.Helper()

	oldRSA, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate old key: %v", err)
	}
	newRSA, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate new key: %v", err)
	}

	oldKey := &keys.Key{
		KID: "kid-old", Method: jwt.SigningMethodRS256,
		Private: oldRSA, Public: &oldRSA.PublicKey,
	}
	newKey := &keys.Key{
		KID: "kid-new", Method: jwt.SigningMethodRS256,
		Private: newRSA, Public: &newRSA.PublicKey,
	}

	provider := keys.NewStaticProvider(oldKey)
	if err := provider.Rotate(newKey); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	return provider, oldKey, newKey
}

// TestAccessTokenUsesTheKeyProvider is the key-rotation test.
//
// GenerateAccessToken hardcoded jwt.SigningMethodRS256 and the single key the
// provider was constructed with, ignoring WithKeyProvider entirely -- while
// JWKS() published from the key provider and oidc.Server.sign honoured it. The
// two halves therefore disagreed the moment anyone rotated: JWKS advertised
// the new key set, access tokens stayed signed with the original key, and
// every relying party's verification failed with nothing erroring on the
// serving side.
//
// This is the worst failure mode in the module because it passes every other
// test. GenerateAccessToken had no direct coverage at all.
func TestAccessTokenUsesTheKeyProvider(t *testing.T) {
	keyProvider, _, newKey := newRotatingKeys(t)
	provider, _ := newSecureProvider(t, WithKeyProvider(keyProvider))

	token, err := provider.GenerateAccessToken(testClientID, "user-1", []string{"openid"})
	if err != nil {
		t.Fatalf("GenerateAccessToken: %v", err)
	}

	parsed, _, err := jwt.NewParser().ParseUnverified(token, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("parse token: %v", err)
	}
	kid, _ := parsed.Header["kid"].(string)
	if kid != newKey.KID {
		t.Errorf("access token kid = %q, want %q -- it was not signed by the active key",
			kid, newKey.KID)
	}

	// The published JWKS is how a relying party finds the verification key, so
	// the token must verify against the key the provider actually advertises.
	set, err := provider.JWKS(context.Background())
	if err != nil {
		t.Fatalf("JWKS: %v", err)
	}
	var advertised bool
	for _, jwk := range set.Keys {
		if jwk.Kid == kid {
			advertised = true
			break
		}
	}
	if !advertised {
		t.Errorf("the token was signed with kid %q, which JWKS does not advertise", kid)
	}

	verified, err := jwt.Parse(token, func(tok *jwt.Token) (any, error) {
		return newKey.Public, nil
	})
	if err != nil || !verified.Valid {
		t.Errorf("the access token does not verify against the active key: %v", err)
	}
}

// TestIntrospectResolvesKeyByKID covers the same split on the reading side.
//
// Introspect verified against the provider's single construction key and
// ignored the token's kid, so a token signed by any other key in the set --
// including one minted moments earlier under the active key -- was reported
// inactive. After a rotation that silently invalidates live tokens.
func TestIntrospectResolvesKeyByKID(t *testing.T) {
	keyProvider, _, _ := newRotatingKeys(t)
	provider, _ := newSecureProvider(t, WithKeyProvider(keyProvider))

	token, err := provider.GenerateAccessToken(testClientID, "user-1", []string{"openid"})
	if err != nil {
		t.Fatalf("GenerateAccessToken: %v", err)
	}

	got, err := provider.Introspect(context.Background(), token)
	if err != nil {
		t.Fatalf("Introspect: %v", err)
	}
	if !got.Active {
		t.Error("Introspect reported a token it had just issued as inactive")
	}
}

// TestIntrospectRejectsAnUnknownKey keeps the check honest: resolving by kid
// must not turn into accepting whatever the token claims.
func TestIntrospectRejectsAnUnknownKey(t *testing.T) {
	keyProvider, _, _ := newRotatingKeys(t)
	provider, _ := newSecureProvider(t, WithKeyProvider(keyProvider))

	strangerRSA, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate stranger key: %v", err)
	}
	claims := jwt.MapClaims{"iss": "https://issuer.example.test", "sub": "attacker"}
	forged := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	forged.Header["kid"] = "kid-not-in-the-set"
	signed, err := forged.SignedString(strangerRSA)
	if err != nil {
		t.Fatalf("sign forged token: %v", err)
	}

	got, err := provider.Introspect(context.Background(), signed)
	if err != nil {
		t.Fatalf("Introspect: %v", err)
	}
	if got.Active {
		t.Error("Introspect accepted a token signed by a key outside the provider's set")
	}
}
