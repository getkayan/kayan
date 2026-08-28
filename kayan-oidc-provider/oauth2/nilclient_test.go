package oauth2

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"

	"testing"
	"time"

	"github.com/getkayan/kayan/core/domain"
	"golang.org/x/crypto/bcrypt"
)

// nilMissStore reports an unknown client the way a store built on a driver
// that returns an empty result rather than an error naturally would.
//
// ClientStore is implemented by the application -- that is the whole point of
// the seam -- so this shape is not hypothetical. Every other method is the
// securityStore's.
type nilMissStore struct{ *securityStore }

func (s *nilMissStore) GetClient(_ context.Context, id string) (*Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c, ok := s.clients[id]; ok {
		return c, nil
	}
	return nil, nil
}

// newNilMissProvider mirrors newSecureProvider but with a store that reports a
// miss as (nil, nil).
func newNilMissProvider(t testing.TB) *Provider {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	inner := newSecurityStore()
	hasher := domain.NewBcryptHasher(bcrypt.MinCost)
	hash, err := hasher.Hash(testClientSecret)
	if err != nil {
		t.Fatalf("hash secret: %v", err)
	}
	inner.clients[testClientID] = &Client{
		ID:           testClientID,
		SecretHash:   hash,
		RedirectURIs: []string{testRedirectURI},
	}
	store := &nilMissStore{securityStore: inner}
	return NewProvider(store, store, store, "https://issuer.example.test", key, "kid-1",
		WithClientSecretHasher(hasher))
}

// TestUnknownClientReportedAsNilDoesNotPanic is the central test.
//
// ParseAuthorizeRequest runs on an unauthenticated query string and went
// straight from GetClient to client.RedirectURIs. A store that reports a miss
// as (nil, nil) turned any request naming a client id that does not exist into
// a nil dereference inside the caller's HTTP handler -- an unauthenticated
// remote crash of the authorization endpoint, triggered by a single query
// parameter.
func TestUnknownClientReportedAsNilDoesNotPanic(t *testing.T) {
	provider := newNilMissProvider(t)

	values := authorizeValues()
	values.Set("client_id", "no-such-client")

	req, err := provider.ParseAuthorizeRequest(context.Background(), values)
	if err == nil {
		t.Fatal("ParseAuthorizeRequest accepted a client the store does not have")
	}
	if req != nil {
		t.Error("a request was returned alongside the error")
	}
	assertOAuthError(t, err, "invalid_client")
}

// TestGenerateAuthCodeRefusesNilClient covers the path where the panic was not
// the worst outcome. The redirect allowlist is the only thing keeping this
// endpoint from being an open redirector, and a nil client has no allowlist,
// so the check must refuse rather than be skipped.
func TestGenerateAuthCodeRefusesNilClient(t *testing.T) {
	provider := newNilMissProvider(t)

	code, err := provider.GenerateAuthCode(context.Background(), "no-such-client", "user-1",
		"https://attacker.test/callback", []string{"openid"}, challengeFor("verifier"), challengeMethodS256)

	if err == nil {
		t.Fatal("GenerateAuthCode issued a code for a client the store does not have")
	}
	if code != "" {
		t.Errorf("a code was issued alongside the error: %q", code)
	}
	assertOAuthError(t, err, "invalid_client")
}

// TestValidateClientRefusesNilClient covers client authentication. A nil
// client must fail exactly as an unknown one does.
func TestValidateClientRefusesNilClient(t *testing.T) {
	provider := newNilMissProvider(t)

	client, err := provider.ValidateClient(context.Background(), "no-such-client", testClientSecret)
	if err == nil {
		t.Fatal("ValidateClient authenticated a client the store does not have")
	}
	if client != nil {
		t.Error("a client was returned alongside the error")
	}
	assertOAuthError(t, err, "invalid_client")
}

// TestNilClientDoesNotShortenTheTimingPath keeps client authentication from
// becoming an enumeration oracle through the new branch.
//
// The unknown-client path deliberately spends a bcrypt comparison so response
// timing does not distinguish "no such client" from "wrong secret". A nil
// client that skipped that work would answer measurably faster, which is the
// oracle the existing code went out of its way to close.
func TestNilClientDoesNotShortenTheTimingPath(t *testing.T) {
	provider := newNilMissProvider(t)
	ctx := context.Background()

	measure := func(id string) time.Duration {
		start := time.Now()
		_, _ = provider.ValidateClient(ctx, id, "wrong-secret")
		return time.Since(start)
	}

	// The registered client with a wrong secret is the reference: it always
	// performs a real comparison.
	known := measure(testClientID)
	missing := measure("no-such-client")

	// Deliberately loose. The assertion is that the nil path does comparable
	// work, not that the two are equal -- a tight bound would be flaky, and a
	// flaky security test gets deleted.
	if missing*8 < known {
		t.Errorf("unknown client answered in %v against %v for a known one; the nil "+
			"path skips the comparison and distinguishes the two", missing, known)
	}
}

// assertOAuthError checks the error carries the expected OAuth 2.0 code.
// Asserting only err != nil would pass on a nil dereference recovered
// elsewhere, or on an unrelated validation rejecting the request first.
func assertOAuthError(t *testing.T, err error, code string) {
	t.Helper()
	var oerr *Error
	if !errors.As(err, &oerr) {
		t.Fatalf("error = %v (%T), want an *oauth2.Error", err, err)
	}
	if oerr.Code != code {
		t.Errorf("error code = %q, want %q", oerr.Code, code)
	}
}
