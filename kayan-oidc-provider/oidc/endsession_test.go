package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/getkayan/kayan/core/keys"
	"github.com/getkayan/kayan/kayan-oidc-provider/oauth2"
	"github.com/golang-jwt/jwt/v5"
)

// end_session_endpoint was advertised in discovery with nothing behind it: no
// parser, no validation of post_logout_redirect_uri, and no field on Client to
// validate against. An unvalidated redirect target on an authentication
// endpoint is an open redirector that inherits the provider's reputation,
// which is a phishing primitive rather than a missing feature.

type stubClientStore struct {
	clients map[string]*oauth2.Client
	seenCtx context.Context
	err     error
}

func (s *stubClientStore) GetClient(ctx context.Context, id string) (*oauth2.Client, error) {
	s.seenCtx = ctx
	if s.err != nil {
		return nil, s.err
	}
	return s.clients[id], nil // a miss is (nil, nil), as real stores do
}
func (s *stubClientStore) CreateClient(context.Context, *oauth2.Client) error { return nil }
func (s *stubClientStore) DeleteClient(context.Context, string) error         { return nil }

const testIssuer = "https://issuer.example.test"

func endSessionServer(t *testing.T, clients *stubClientStore) (*Server, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	provider := keys.NewStaticProvider(&keys.Key{
		KID: "kid-1", Method: jwt.SigningMethodRS256,
		Private: key, Public: &key.PublicKey,
	})
	opts := []ServerOption{WithServerKeyProvider(provider)}
	if clients != nil {
		opts = append(opts, WithClientStore(clients))
	}
	return NewServer(testIssuer, nil, "", opts...), key
}

// mintHint builds an id_token_hint signed by key with the given kid.
func mintHint(t *testing.T, key *rsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	if kid != "" {
		token.Header["kid"] = kid
	}
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("sign hint: %v", err)
	}
	return signed
}

func validClaims() jwt.MapClaims {
	return jwt.MapClaims{
		"iss": testIssuer,
		"aud": "client-1",
		"sub": "user-1",
		"sid": "session-1",
		"iat": time.Now().Add(-time.Hour).Unix(),
		"exp": time.Now().Add(-time.Minute).Unix(), // expired on purpose
	}
}

func storeWith(uris ...string) *stubClientStore {
	return &stubClientStore{clients: map[string]*oauth2.Client{
		"client-1": {ID: "client-1", PostLogoutRedirectURIs: uris},
	}}
}

// TestEndSessionVerifiesTheHintSignature is the base property, and it had no
// test in the design: a hint is only evidence because this provider signed it.
func TestEndSessionVerifiesTheHintSignature(t *testing.T) {
	server, _ := endSessionServer(t, storeWith("https://rp.example.test/done"))

	// Signed by a key the provider never published, but otherwise perfect:
	// right algorithm, a kid that exists, valid issuer, audience and subject.
	attacker, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate attacker key: %v", err)
	}
	hint := mintHint(t, attacker, "kid-1", validClaims())

	_, err = server.ParseEndSessionRequest(context.Background(), url.Values{
		"id_token_hint": {hint},
	})
	if !errors.Is(err, ErrInvalidIDTokenHint) {
		t.Errorf("error = %v, want ErrInvalidIDTokenHint", err)
	}
}

// TestInvalidHintDoesNotFallBackToClientID is the highest-value test here.
//
// "The hint did not verify, so try client_id instead" is the natural
// implementation and exactly the downgrade an attacker wants: send a
// deliberately broken hint alongside any client_id, and the request is
// validated against that client's allowlist instead of the one the hint would
// have selected.
func TestInvalidHintDoesNotFallBackToClientID(t *testing.T) {
	server, _ := endSessionServer(t, storeWith("https://rp.example.test/done"))

	_, err := server.ParseEndSessionRequest(context.Background(), url.Values{
		"id_token_hint":            {"not-a-token-at-all"},
		"client_id":                {"client-1"},
		"post_logout_redirect_uri": {"https://rp.example.test/done"},
	})
	if !errors.Is(err, ErrInvalidIDTokenHint) {
		t.Errorf("error = %v, want ErrInvalidIDTokenHint: a broken hint fell through "+
			"to the client_id path", err)
	}
}

// TestUnregisteredRedirectIsRefused is the open-redirect check.
func TestUnregisteredRedirectIsRefused(t *testing.T) {
	server, key := endSessionServer(t, storeWith("https://rp.example.test/done"))
	hint := mintHint(t, key, "kid-1", validClaims())

	_, err := server.ParseEndSessionRequest(context.Background(), url.Values{
		"id_token_hint":            {hint},
		"post_logout_redirect_uri": {"https://attacker.example.test/harvest"},
	})
	if !errors.Is(err, ErrPostLogoutRedirectNotRegistered) {
		t.Errorf("error = %v, want ErrPostLogoutRedirectNotRegistered", err)
	}
}

// TestEmptyAllowlistDeniesEveryRedirect pins the safe reading of a client that
// registered no post-logout URIs.
func TestEmptyAllowlistDeniesEveryRedirect(t *testing.T) {
	client := &oauth2.Client{ID: "client-1"}
	if client.AllowsPostLogoutRedirectURI("https://rp.example.test/done") {
		t.Error("a client with no registered URIs allowed a redirect")
	}
	if client.AllowsPostLogoutRedirectURI("") {
		t.Error("a client with no registered URIs allowed an empty redirect")
	}
}

// TestRedirectRequiresAnIdentifiedClient covers the case with no hint and no
// client_id: there is no allowlist to check, so there is no safe target.
func TestRedirectRequiresAnIdentifiedClient(t *testing.T) {
	server, _ := endSessionServer(t, storeWith("https://rp.example.test/done"))

	_, err := server.ParseEndSessionRequest(context.Background(), url.Values{
		"post_logout_redirect_uri": {"https://rp.example.test/done"},
	})
	if !errors.Is(err, ErrUnknownClient) {
		t.Errorf("error = %v, want ErrUnknownClient", err)
	}
}

// TestValidRequestReturnsTheRedirect keeps the feature working. Without it the
// tests above would pass against a parser that refused everything.
func TestValidRequestReturnsTheRedirect(t *testing.T) {
	store := storeWith("https://rp.example.test/done")
	server, key := endSessionServer(t, store)
	hint := mintHint(t, key, "kid-1", validClaims())

	req, err := server.ParseEndSessionRequest(context.Background(), url.Values{
		"id_token_hint":            {hint},
		"post_logout_redirect_uri": {"https://rp.example.test/done"},
		"state":                    {"xyz"},
	})
	if err != nil {
		t.Fatalf("ParseEndSessionRequest: %v", err)
	}
	if req.ClientID != "client-1" || req.Subject != "user-1" || req.SessionID != "session-1" {
		t.Errorf("request = %+v, want the hint's client, subject and session", req)
	}
	if req.ConfirmationRequired {
		t.Error("a hint naming the session still required confirmation")
	}
	if got := req.RedirectURL(); got != "https://rp.example.test/done?state=xyz" {
		t.Errorf("RedirectURL = %q", got)
	}
}

// TestConfirmationRequiredWithoutASessionID covers the case the design got
// wrong first: matching only the subject would let a token minted for one
// device silently end a session on another.
func TestConfirmationRequiredWithoutASessionID(t *testing.T) {
	server, key := endSessionServer(t, storeWith("https://rp.example.test/done"))
	claims := validClaims()
	delete(claims, "sid")
	hint := mintHint(t, key, "kid-1", claims)

	req, err := server.ParseEndSessionRequest(context.Background(), url.Values{"id_token_hint": {hint}})
	if err != nil {
		t.Fatalf("ParseEndSessionRequest: %v", err)
	}
	if !req.ConfirmationRequired {
		t.Error("a hint naming no session did not require confirmation")
	}
}

// TestRedirectURLPreservesRegisteredQuery covers a break that would look like
// a working implementation. Relying parties register URIs carrying their own
// parameters, and replacing the query drops them.
func TestRedirectURLPreservesRegisteredQuery(t *testing.T) {
	req := &EndSessionRequest{
		PostLogoutRedirectURI: "https://rp.example.test/done?tenant=acme",
		State:                 "xyz",
	}
	got := req.RedirectURL()

	parsed, err := url.Parse(got)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	values := parsed.Query()
	if values.Get("tenant") != "acme" {
		t.Errorf("RedirectURL dropped the registered query parameter: %q", got)
	}
	if values.Get("state") != "xyz" {
		t.Errorf("state missing from %q", got)
	}
	if len(values["state"]) != 1 {
		t.Errorf("state appears %d times in %q", len(values["state"]), got)
	}
	if parsed.Fragment != "" {
		t.Errorf("RedirectURL produced a fragment: %q", got)
	}
}

// TestRedirectURLOmitsAbsentState pins the specification's rule that state is
// returned only when it was sent, rather than emitted empty.
func TestRedirectURLOmitsAbsentState(t *testing.T) {
	req := &EndSessionRequest{PostLogoutRedirectURI: "https://rp.example.test/done"}
	if got := req.RedirectURL(); got != "https://rp.example.test/done" {
		t.Errorf("RedirectURL = %q, want the bare URI with no state parameter", got)
	}
	if (&EndSessionRequest{}).RedirectURL() != "" {
		t.Error("a request with no validated target produced a redirect")
	}
}

// TestNoClientStoreFailsClosed covers a nil-interface panic reachable from any
// query string, and the refusal that replaces it.
func TestNoClientStoreFailsClosed(t *testing.T) {
	server, key := endSessionServer(t, nil)
	hint := mintHint(t, key, "kid-1", validClaims())

	// With a hint and no redirect there is nothing to validate, so this must
	// still parse rather than reaching the store.
	if _, err := server.ParseEndSessionRequest(context.Background(), url.Values{
		"id_token_hint": {hint},
	}); err != nil {
		t.Errorf("a hint-only request with no client store failed: %v", err)
	}

	// With a redirect there is no allowlist to check it against.
	if _, err := server.ParseEndSessionRequest(context.Background(), url.Values{
		"id_token_hint":            {hint},
		"post_logout_redirect_uri": {"https://rp.example.test/done"},
	}); !errors.Is(err, ErrNoClientStore) {
		t.Errorf("error = %v, want ErrNoClientStore", err)
	}
}

// TestUnknownClientFromStore covers a store reporting a miss as (nil, nil),
// which the in-repo mock does. Dereferencing that panics.
func TestUnknownClientFromStore(t *testing.T) {
	server, key := endSessionServer(t, &stubClientStore{clients: map[string]*oauth2.Client{}})
	hint := mintHint(t, key, "kid-1", validClaims())

	if _, err := server.ParseEndSessionRequest(context.Background(), url.Values{
		"id_token_hint":            {hint},
		"post_logout_redirect_uri": {"https://rp.example.test/done"},
	}); !errors.Is(err, ErrUnknownClient) {
		t.Errorf("error = %v, want ErrUnknownClient", err)
	}
}

// TestHintWithoutAKIDIsRefused keeps a rotation hole shut: resolving a
// kid-less token against the active key would let one signed by a retired key
// keep identifying a client after the rotation that retired it.
func TestHintWithoutAKIDIsRefused(t *testing.T) {
	server, key := endSessionServer(t, storeWith("https://rp.example.test/done"))
	hint := mintHint(t, key, "", validClaims())

	if _, err := server.ParseEndSessionRequest(context.Background(), url.Values{
		"id_token_hint": {hint},
	}); !errors.Is(err, ErrInvalidIDTokenHint) {
		t.Errorf("error = %v, want ErrInvalidIDTokenHint", err)
	}
}

// TestHintFromAnotherIssuerIsRefused covers the reachable case: a deployment
// issuing under several issuer values from one key, which per-tenant issuers
// do. A token from a genuinely foreign provider fails the signature check
// first, so this is not that.
func TestHintFromAnotherIssuerIsRefused(t *testing.T) {
	server, key := endSessionServer(t, storeWith("https://rp.example.test/done"))
	claims := validClaims()
	claims["iss"] = "https://other-tenant.example.test"
	hint := mintHint(t, key, "kid-1", claims)

	if _, err := server.ParseEndSessionRequest(context.Background(), url.Values{
		"id_token_hint": {hint},
	}); !errors.Is(err, ErrInvalidIDTokenHint) {
		t.Errorf("error = %v, want ErrInvalidIDTokenHint", err)
	}
}

// TestExpiredHintIsAccepted pins a deliberate choice. A user signing out holds
// a token for the session being ended, and that token is routinely expired --
// refusing it would break the ordinary case.
func TestExpiredHintIsAccepted(t *testing.T) {
	server, key := endSessionServer(t, storeWith("https://rp.example.test/done"))
	claims := validClaims()
	claims["exp"] = time.Now().Add(-24 * time.Hour).Unix()
	hint := mintHint(t, key, "kid-1", claims)

	if _, err := server.ParseEndSessionRequest(context.Background(), url.Values{
		"id_token_hint": {hint},
	}); err != nil {
		t.Errorf("an expired hint was refused: %v", err)
	}
}

// TestContextReachesTheClientStore covers tenant scoping: the store's query
// must run in the caller's context, not a background one.
func TestContextReachesTheClientStore(t *testing.T) {
	store := storeWith("https://rp.example.test/done")
	server, key := endSessionServer(t, store)
	hint := mintHint(t, key, "kid-1", validClaims())

	type ctxKey struct{}
	ctx := context.WithValue(context.Background(), ctxKey{}, "tenant-a")

	if _, err := server.ParseEndSessionRequest(ctx, url.Values{
		"id_token_hint":            {hint},
		"post_logout_redirect_uri": {"https://rp.example.test/done"},
	}); err != nil {
		t.Fatalf("ParseEndSessionRequest: %v", err)
	}
	if store.seenCtx == nil || store.seenCtx.Value(ctxKey{}) != "tenant-a" {
		t.Error("the caller's context did not reach the client store")
	}
}

// TestDiscoveryRefusesToAdvertiseWhatItCannotServe covers the same
// advertised-but-unimplemented defect this whole change exists to close. A
// relying party that trusts the metadata builds a logout flow the provider
// cannot complete.
func TestDiscoveryRefusesToAdvertiseWhatItCannotServe(t *testing.T) {
	server, _ := endSessionServer(t, nil)

	_, err := server.BuildDiscovery(context.Background(), DiscoveryOptions{
		Endpoints: Endpoints{EndSession: "https://issuer.example.test/oidc/logout"},
	})
	if err == nil {
		t.Fatal("discovery advertised an end-session endpoint with no client store")
	}
	if !strings.Contains(err.Error(), "WithClientStore") {
		t.Errorf("error = %v, want one naming the missing option", err)
	}

	// With a store it is advertised normally.
	withStore, _ := endSessionServer(t, storeWith("https://rp.example.test/done"))
	doc, err := withStore.BuildDiscovery(context.Background(), DiscoveryOptions{
		Endpoints: Endpoints{EndSession: "https://issuer.example.test/oidc/logout"},
	})
	if err != nil {
		t.Fatalf("BuildDiscovery: %v", err)
	}
	if doc.EndSessionEndpoint == "" {
		t.Error("a provider that can serve logout did not advertise it")
	}
}
