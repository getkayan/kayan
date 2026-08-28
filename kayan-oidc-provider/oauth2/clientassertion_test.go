package oauth2

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/getkayan/kayan/core/domain"
	"github.com/getkayan/kayan/core/keys"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

const (
	assertionIssuer  = "https://issuer.example.test"
	assertionTokenEP = "https://issuer.example.test/oauth2/token"
	assertionClient  = "jwt-client"
	assertionKID     = "client-key-1"
)

// assertionFixture is a provider with one private_key_jwt client registered,
// plus the private key that client signs with.
type assertionFixture struct {
	provider *Provider
	store    *securityStore
	replay   *MemoryClientAssertionStore
	key      *rsa.PrivateKey
}

func newAssertionFixture(t testing.TB, opts ...ProviderOption) *assertionFixture {
	t.Helper()

	providerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("provider key: %v", err)
	}
	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("client key: %v", err)
	}

	jwk, err := keys.KeyToJWK(&keys.Key{
		KID: assertionKID, Method: jwt.SigningMethodRS256,
		Private: clientKey, Public: &clientKey.PublicKey,
	})
	if err != nil {
		t.Fatalf("KeyToJWK: %v", err)
	}
	set, err := json.Marshal(keys.JWKS{Keys: []keys.JWK{jwk}})
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}

	store := newSecurityStore()
	store.clients[assertionClient] = &Client{
		ID:                      assertionClient,
		TokenEndpointAuthMethod: AuthMethodPrivateKeyJWT,
		JWKS:                    set,
		RedirectURIs:            []string{testRedirectURI},
		GrantTypes:              []string{GrantClientCredentials, GrantAuthorizationCode, GrantRefreshToken},
	}

	replay := NewMemoryClientAssertionStore()
	opts = append([]ProviderOption{
		WithClientSecretHasher(domain.NewBcryptHasher(bcrypt.MinCost)),
		WithClientAssertions(replay),
		WithTokenEndpointURL(assertionTokenEP),
	}, opts...)

	provider := NewProvider(store, store, store, assertionIssuer, providerKey, "kid-1", opts...)
	return &assertionFixture{provider: provider, store: store, replay: replay, key: clientKey}
}

// sign builds an assertion from claims, defaulting the ones a well-behaved
// client always sends so each test can override exactly one.
func (f *assertionFixture) sign(t testing.TB, overrides jwt.MapClaims) string {
	t.Helper()
	now := time.Now()
	claims := jwt.MapClaims{
		"iss": assertionClient,
		"sub": assertionClient,
		"aud": assertionIssuer,
		"jti": "jti-" + now.Format(time.RFC3339Nano),
		"exp": now.Add(2 * time.Minute).Unix(),
		"iat": now.Unix(),
	}
	for name, value := range overrides {
		if value == nil {
			delete(claims, name)
			continue
		}
		claims[name] = value
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = assertionKID
	signed, err := token.SignedString(f.key)
	if err != nil {
		t.Fatalf("sign assertion: %v", err)
	}
	return signed
}

// tokenValues builds a client_credentials token request carrying assertion.
func tokenValues(assertion string) url.Values {
	return url.Values{
		"grant_type":            {GrantClientCredentials},
		"client_assertion_type": {ClientAssertionTypeJWTBearer},
		"client_assertion":      {assertion},
	}
}

// parse runs the assertion through the real token-endpoint entry point, so
// every test exercises the path a request actually takes rather than an
// internal helper.
func (f *assertionFixture) parse(t testing.TB, values url.Values) (*TokenRequest, error) {
	t.Helper()
	return f.provider.ParseTokenRequest(context.Background(), values, "")
}

func TestPrivateKeyJWTAuthenticates(t *testing.T) {
	f := newAssertionFixture(t)

	req, err := f.parse(t, tokenValues(f.sign(t, nil)))
	if err != nil {
		t.Fatalf("ParseTokenRequest: %v", err)
	}
	if req.Client == nil || req.Client.ID != assertionClient {
		t.Fatalf("authenticated client = %+v, want %q", req.Client, assertionClient)
	}
}

// TestPrivateKeyJWTAcceptsTokenEndpointAudience covers the other audience RFC
// 7523 section 3 allows. Relying parties disagree about which to send, and
// rejecting one of them makes the method unusable with about half of them.
func TestPrivateKeyJWTAcceptsTokenEndpointAudience(t *testing.T) {
	f := newAssertionFixture(t)

	if _, err := f.parse(t, tokenValues(f.sign(t, jwt.MapClaims{"aud": assertionTokenEP}))); err != nil {
		t.Fatalf("token endpoint audience rejected: %v", err)
	}

	// The array form is what most client libraries emit.
	if _, err := f.parse(t, tokenValues(f.sign(t, jwt.MapClaims{
		"aud": []string{"https://other.example.test", assertionTokenEP},
	}))); err != nil {
		t.Fatalf("array audience rejected: %v", err)
	}
}

// TestAssertionReplayIsRefused is the central test.
//
// An assertion is a signed message, not proof of a live key. Anyone who
// observes one -- a reverse proxy, an access log that captured the POST body,
// a mirrored TLS session -- holds a working credential until it expires.
// Single-use jti is what makes possession of the key, rather than of the
// message, the thing that authenticates.
func TestAssertionReplayIsRefused(t *testing.T) {
	f := newAssertionFixture(t)
	assertion := f.sign(t, nil)

	if _, err := f.parse(t, tokenValues(assertion)); err != nil {
		t.Fatalf("first use failed: %v", err)
	}

	req, err := f.parse(t, tokenValues(assertion))
	if err == nil {
		t.Fatal("a captured assertion authenticated a second time")
	}
	if req != nil {
		t.Error("a request was returned alongside the replay error")
	}
	assertOAuthError(t, err, "invalid_client")
}

// TestAssertionWithoutStoreIsRefused. Enabling private_key_jwt without replay
// protection would downgrade it to a bearer credential while still reading as
// asymmetric client authentication, so the absent store fails closed.
func TestAssertionWithoutStoreIsRefused(t *testing.T) {
	f := newAssertionFixture(t)
	assertion := f.sign(t, nil)
	// Rebuild without the store, keeping the same client registration and key.
	providerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("provider key: %v", err)
	}
	bare := NewProvider(f.store, f.store, f.store, assertionIssuer, providerKey, "kid-1",
		WithTokenEndpointURL(assertionTokenEP))

	_, err = bare.ParseTokenRequest(context.Background(), tokenValues(assertion), "")
	if err == nil {
		t.Fatal("an assertion was accepted with no replay store configured")
	}
	assertOAuthError(t, err, "invalid_client")
}

// TestAssertionForAnotherProviderIsRefused covers cross-provider replay.
//
// A relying party that federates with several providers signs an assertion for
// each with the same key. Without an audience check, any provider it talks to
// can take the assertion it received and present it to the others, becoming
// that client everywhere.
func TestAssertionForAnotherProviderIsRefused(t *testing.T) {
	f := newAssertionFixture(t)

	for _, aud := range []any{
		"https://attacker.example.test",
		[]string{"https://attacker.example.test"},
		nil, // absent entirely
	} {
		assertion := f.sign(t, jwt.MapClaims{"aud": aud})
		if _, err := f.parse(t, tokenValues(assertion)); err == nil {
			t.Errorf("aud %v was accepted", aud)
		}
	}
}

// TestRejectedAssertionDoesNotSpendItsJTI.
//
// jti is consumed last on purpose. If a failed check spent it, anyone could
// capture a legitimate client's assertions, replay them with a broken
// audience, and burn the identifiers before the client uses them -- a denial
// of service against the client, delivered through the defence.
func TestRejectedAssertionDoesNotSpendItsJTI(t *testing.T) {
	f := newAssertionFixture(t)

	// Same jti, first presented with an audience that fails.
	now := time.Now()
	bad := f.sign(t, jwt.MapClaims{"jti": "shared-id", "aud": "https://attacker.example.test",
		"exp": now.Add(2 * time.Minute).Unix()})
	if _, err := f.parse(t, tokenValues(bad)); err == nil {
		t.Fatal("the wrong-audience assertion was accepted")
	}

	good := f.sign(t, jwt.MapClaims{"jti": "shared-id", "exp": now.Add(2 * time.Minute).Unix()})
	if _, err := f.parse(t, tokenValues(good)); err != nil {
		t.Errorf("the client's own assertion was refused after a rejected one burned its jti: %v", err)
	}
}

// TestAssertionAlgorithmConfusionIsRefused locks the outcome of the classic
// attack: an assertion signed HS256 with the client's own published RSA
// modulus as the HMAC secret, and an unsigned one.
//
// Being honest about what this proves: removing jwt.WithValidMethods does not
// make it pass, because jwt/v5 refuses an *rsa.PublicKey as an HMAC key on its
// own. The allowlist is the layer that survives a key resolver returning raw
// bytes, which TestSymmetricClientKeyIsRefused covers directly.
func TestAssertionAlgorithmConfusionIsRefused(t *testing.T) {
	f := newAssertionFixture(t)
	now := time.Now()
	claims := jwt.MapClaims{
		"iss": assertionClient, "sub": assertionClient, "aud": assertionIssuer,
		"jti": "confused", "exp": now.Add(2 * time.Minute).Unix(),
	}

	t.Run("HS256 over the public modulus", func(t *testing.T) {
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		token.Header["kid"] = assertionKID
		forged, err := token.SignedString(f.key.PublicKey.N.Bytes())
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		if _, err := f.parse(t, tokenValues(forged)); err == nil {
			t.Fatal("an HS256 assertion keyed on the public modulus authenticated")
		}
	})

	t.Run("alg none", func(t *testing.T) {
		token := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
		token.Header["kid"] = assertionKID
		forged, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		if _, err := f.parse(t, tokenValues(forged)); err == nil {
			t.Fatal("an unsigned assertion authenticated")
		}
	})
}

// TestAssertionSignedByAnotherKeyIsRefused. The registered JWKS is the whole
// basis of the decision; a signature from any other key must not verify, and
// an unregistered kid must not fall back to some other key in the set.
func TestAssertionSignedByAnotherKeyIsRefused(t *testing.T) {
	f := newAssertionFixture(t)
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}

	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": assertionClient, "sub": assertionClient, "aud": assertionIssuer,
		"jti": "wrong-key", "exp": now.Add(2 * time.Minute).Unix(),
	})
	token.Header["kid"] = assertionKID
	forged, err := token.SignedString(other)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if _, err := f.parse(t, tokenValues(forged)); err == nil {
		t.Fatal("an assertion signed by an unregistered key authenticated")
	}

	// An unknown kid must miss rather than resolve to the one key present.
	unknownKid := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": assertionClient, "sub": assertionClient, "aud": assertionIssuer,
		"jti": "unknown-kid", "exp": now.Add(2 * time.Minute).Unix(),
	})
	unknownKid.Header["kid"] = "not-registered"
	signed, err := unknownKid.SignedString(f.key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := f.parse(t, tokenValues(signed)); err == nil {
		t.Fatal("an assertion naming an unregistered kid authenticated")
	}
}

// TestAssertionClaimRequirements covers the claims whose absence the JWT
// library treats as valid. exp and jti in particular: without exp an assertion
// never expires, and without jti there is nothing to record as spent, so both
// turn the credential into a permanent bearer token.
func TestAssertionClaimRequirements(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name     string
		override jwt.MapClaims
	}{
		{"no exp", jwt.MapClaims{"exp": nil}},
		{"expired", jwt.MapClaims{"exp": now.Add(-time.Hour).Unix()}},
		{"exp beyond the lifetime bound", jwt.MapClaims{"exp": now.Add(48 * time.Hour).Unix()}},
		{"no jti", jwt.MapClaims{"jti": nil}},
		{"no iss", jwt.MapClaims{"iss": nil}},
		{"sub names another party", jwt.MapClaims{"sub": "someone-else"}},
		{"not yet valid", jwt.MapClaims{"nbf": now.Add(time.Hour).Unix()}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newAssertionFixture(t)
			if _, err := f.parse(t, tokenValues(f.sign(t, tc.override))); err == nil {
				t.Fatalf("%s was accepted", tc.name)
			}
		})
	}
}

// TestAssertionIssuerMustMatchClientID. Letting client_id and iss disagree
// means the request is authenticated as the assertion's signer and attributed
// to whichever client the form named.
func TestAssertionIssuerMustMatchClientID(t *testing.T) {
	f := newAssertionFixture(t)

	values := tokenValues(f.sign(t, nil))
	values.Set("client_id", "some-other-client")

	if _, err := f.parse(t, values); err == nil {
		t.Fatal("an assertion authenticated a request naming a different client_id")
	}
}

// TestSecretClientCannotUseAnAssertion.
//
// A registration declares one authentication method. Without this check,
// putting a JWKS on a client_secret_basic client would quietly add a second
// working credential, and the registration would still read as secret-based
// to anyone auditing it.
func TestSecretClientCannotUseAnAssertion(t *testing.T) {
	f := newAssertionFixture(t)
	registration := f.store.clients[assertionClient]
	registration.TokenEndpointAuthMethod = AuthMethodClientSecretBasic

	if _, err := f.parse(t, tokenValues(f.sign(t, nil))); err == nil {
		t.Fatal("a client registered for client_secret_basic authenticated with an assertion")
	}
}

// TestAssertionClientCannotUseASecret is the same rule in the other direction.
//
// A deployment that migrates a client to private_key_jwt without deleting the
// row's old hash would otherwise keep the shared secret working, which is
// exactly the credential the migration existed to remove.
func TestAssertionClientCannotUseASecret(t *testing.T) {
	f := newAssertionFixture(t)
	hasher := domain.NewBcryptHasher(bcrypt.MinCost)
	hash, err := hasher.Hash(testClientSecret)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	f.store.clients[assertionClient].SecretHash = hash

	_, err = f.provider.ValidateClient(context.Background(), assertionClient, testClientSecret)
	if err == nil {
		t.Fatal("a private_key_jwt client authenticated with a leftover client secret")
	}
	assertOAuthError(t, err, "invalid_client")
}

// TestTwoCredentialsAreRefused. Sending both a secret and an assertion is a
// request probing which credential the endpoint honours, and RFC 6749
// section 2.3 permits exactly one method per request.
func TestTwoCredentialsAreRefused(t *testing.T) {
	f := newAssertionFixture(t)
	assertion := f.sign(t, nil)

	t.Run("basic header and assertion", func(t *testing.T) {
		_, err := f.provider.ParseTokenRequest(context.Background(), tokenValues(assertion),
			"Basic "+basicHeader(assertionClient, testClientSecret))
		if err == nil {
			t.Fatal("a request carrying both a Basic header and an assertion was accepted")
		}
		// The specific error matters. Without the guard this request is
		// refused anyway -- as secret authentication against a private_key_jwt
		// registration -- so asserting only err != nil would pass either way.
		var oerr *Error
		if !errors.As(err, &oerr) || oerr.Description != "more than one client authentication method was used" {
			t.Errorf("error = %v, want the request refused for carrying two credentials", err)
		}
	})

	t.Run("client_secret and assertion", func(t *testing.T) {
		values := tokenValues(assertion)
		values.Set("client_secret", testClientSecret)
		if _, err := f.parse(t, values); err == nil {
			t.Fatal("a request carrying both client_secret and an assertion was accepted")
		}
	})
}

// TestWrongAssertionTypeIsRefused. RFC 7523 section 2.2 defines exactly one
// value; accepting others would mean accepting a credential format nothing in
// this package validates.
func TestWrongAssertionTypeIsRefused(t *testing.T) {
	f := newAssertionFixture(t)

	values := tokenValues(f.sign(t, nil))
	values.Set("client_assertion_type", "urn:example:something-else")

	if _, err := f.parse(t, values); err == nil {
		t.Fatal("an unknown client_assertion_type was accepted")
	}
}

// TestMemoryAssertionStoreIsConcurrencySafe. Two replays arriving together
// must not both succeed, which is why check-and-record is a single method.
func TestMemoryAssertionStoreIsConcurrencySafe(t *testing.T) {
	store := NewMemoryClientAssertionStore()
	expiry := time.Now().Add(time.Minute)

	const attempts = 256
	results := make(chan error, attempts)
	for range attempts {
		go func() {
			results <- store.ConsumeAssertionID(context.Background(), assertionClient, "one-id", expiry)
		}()
	}

	accepted := 0
	for range attempts {
		if err := <-results; err == nil {
			accepted++
		} else if !errors.Is(err, ErrAssertionReplayed) {
			t.Errorf("unexpected error: %v", err)
		}
	}
	if accepted != 1 {
		t.Errorf("%d of %d concurrent uses of one jti succeeded, want exactly 1", accepted, attempts)
	}
}

// TestAssertionStoreScopesJTIPerClient. A shared namespace would let one
// client spend another's identifiers, denying service to any client whose jti
// scheme is predictable.
func TestAssertionStoreScopesJTIPerClient(t *testing.T) {
	store := NewMemoryClientAssertionStore()
	expiry := time.Now().Add(time.Minute)

	if err := store.ConsumeAssertionID(context.Background(), "client-a", "1", expiry); err != nil {
		t.Fatalf("first: %v", err)
	}
	if err := store.ConsumeAssertionID(context.Background(), "client-b", "1", expiry); err != nil {
		t.Errorf("client-b was blocked by client-a's identifier: %v", err)
	}
}

// basicHeader builds the base64 payload of a Basic authorization header.
func basicHeader(id, secret string) string {
	return base64.StdEncoding.EncodeToString([]byte(url.QueryEscape(id) + ":" + url.QueryEscape(secret)))
}

// TestSymmetricClientKeyIsRefused is the algorithm-confusion case with a
// failure mode this layer can actually produce.
//
// If a client registers an "oct" JWK -- or a jwks_uri serves one -- and the
// key resolver hands back its bytes, then an assertion signed HS256 with that
// same secret verifies. The secret is registered, so anyone who can read the
// client registration can mint assertions. Two things refuse it: JWK.PublicKey
// rejects oct outright, and the algorithm allowlist excludes every MAC.
func TestSymmetricClientKeyIsRefused(t *testing.T) {
	f := newAssertionFixture(t)

	secret := []byte("a-registered-shared-secret-value")
	set, err := json.Marshal(keys.JWKS{Keys: []keys.JWK{{
		Kty: "oct", Kid: assertionKID, Alg: "HS256",
		X: base64.RawURLEncoding.EncodeToString(secret),
	}}})
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}
	f.store.clients[assertionClient].JWKS = set

	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": assertionClient, "sub": assertionClient, "aud": assertionIssuer,
		"jti": "symmetric", "exp": now.Add(2 * time.Minute).Unix(),
	})
	token.Header["kid"] = assertionKID
	forged, err := token.SignedString(secret)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if _, err := f.parse(t, tokenValues(forged)); err == nil {
		t.Fatal("an assertion signed with a registered symmetric key authenticated")
	}
}
