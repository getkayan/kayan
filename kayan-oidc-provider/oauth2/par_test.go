package oauth2

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/getkayan/kayan/core/domain"
	"golang.org/x/crypto/bcrypt"
)

// parFixture is a provider with PAR enabled and one confidential client.
type parFixture struct {
	provider *Provider
	store    *securityStore
	pushed   *MemoryPushedRequestStore
}

func newPARFixture(t testing.TB, opts ...ProviderOption) *parFixture {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	store := newSecurityStore()
	hasher := domain.NewBcryptHasher(bcrypt.MinCost)
	hash, err := hasher.Hash(testClientSecret)
	if err != nil {
		t.Fatalf("hash secret: %v", err)
	}
	store.clients[testClientID] = &Client{
		ID:           testClientID,
		SecretHash:   hash,
		RedirectURIs: []string{testRedirectURI},
	}

	pushed := NewMemoryPushedRequestStore()
	opts = append([]ProviderOption{
		WithClientSecretHasher(hasher),
		WithPushedRequests(pushed),
	}, opts...)

	provider := NewProvider(store, store, store, "https://issuer.example.test", key, "kid-1", opts...)
	return &parFixture{provider: provider, store: store, pushed: pushed}
}

// basicAuth builds the Authorization header for the test client.
func basicAuth() string {
	return "Basic " + base64.StdEncoding.EncodeToString(
		[]byte(url.QueryEscape(testClientID)+":"+url.QueryEscape(testClientSecret)))
}

// push lodges a well-formed authorization request.
func (f *parFixture) push(t testing.TB, values url.Values) *PushedRequest {
	t.Helper()
	request, err := f.provider.PushAuthorizationRequest(context.Background(), values, basicAuth())
	if err != nil {
		t.Fatalf("PushAuthorizationRequest: %v", err)
	}
	return request
}

func TestPushedRequestIsRedeemable(t *testing.T) {
	f := newPARFixture(t)

	request := f.push(t, authorizeValues())
	if !strings.HasPrefix(request.URI, RequestURIPrefix) {
		t.Errorf("request_uri = %q, want the URN form", request.URI)
	}
	if request.ExpiresIn(time.Now()) <= 0 {
		t.Error("the pushed request expires immediately")
	}

	parsed, err := f.provider.ParseAuthorizeRequest(context.Background(), url.Values{
		"client_id":   {testClientID},
		"request_uri": {request.URI},
	})
	if err != nil {
		t.Fatalf("ParseAuthorizeRequest: %v", err)
	}
	if parsed.RedirectURI != testRedirectURI {
		t.Errorf("RedirectURI = %q, want the pushed value", parsed.RedirectURI)
	}
	if parsed.State != "opaque-state" {
		t.Errorf("State = %q, want the pushed value", parsed.State)
	}
}

// TestQueryParametersCannotOverrideAPushedRequest is the central test.
//
// The whole value of PAR is that the parameters were fixed at push time, over
// a direct authenticated channel. If the authorization endpoint merged in
// whatever else arrived on the URL, anyone holding a victim's request_uri
// could append their own redirect_uri and receive the authorization code --
// which is the request tampering PAR exists to prevent, reintroduced at the
// one place it matters.
func TestQueryParametersCannotOverrideAPushedRequest(t *testing.T) {
	f := newPARFixture(t)
	f.store.clients[testClientID].RedirectURIs = append(
		f.store.clients[testClientID].RedirectURIs, "https://attacker.test/callback")

	request := f.push(t, authorizeValues())

	parsed, err := f.provider.ParseAuthorizeRequest(context.Background(), url.Values{
		"client_id":    {testClientID},
		"request_uri":  {request.URI},
		"redirect_uri": {"https://attacker.test/callback"},
		"state":        {"attacker-state"},
		"scope":        {"openid admin"},
	})
	if err != nil {
		t.Fatalf("ParseAuthorizeRequest: %v", err)
	}

	if parsed.RedirectURI != testRedirectURI {
		t.Errorf("RedirectURI = %q; a query parameter overrode the pushed request "+
			"and the code would go to the attacker", parsed.RedirectURI)
	}
	if parsed.State != "opaque-state" {
		t.Errorf("State = %q, want the pushed value", parsed.State)
	}
	for _, scope := range parsed.Scopes {
		if scope == "admin" {
			t.Error("a scope was added on the authorization URL after the request was pushed")
		}
	}
}

// TestRequestURIIsSingleUse. RFC 9126 section 6: a request_uri is one-time
// use. A reusable one is a bearer reference to a validated authorization
// request that stays good for its whole lifetime.
func TestRequestURIIsSingleUse(t *testing.T) {
	f := newPARFixture(t)
	request := f.push(t, authorizeValues())

	values := url.Values{"client_id": {testClientID}, "request_uri": {request.URI}}
	if _, err := f.provider.ParseAuthorizeRequest(context.Background(), values); err != nil {
		t.Fatalf("first redemption: %v", err)
	}
	if _, err := f.provider.ParseAuthorizeRequest(context.Background(), values); err == nil {
		t.Fatal("a request_uri was redeemed twice")
	}
}

// TestConcurrentRedemptionsElectOneWinner. Single-use has to hold under
// concurrency or it is not a property, which is why the store consumes in one
// call.
func TestConcurrentRedemptionsElectOneWinner(t *testing.T) {
	f := newPARFixture(t)
	request := f.push(t, authorizeValues())
	values := url.Values{"client_id": {testClientID}, "request_uri": {request.URI}}

	const attempts = 64
	var wg sync.WaitGroup
	results := make(chan error, attempts)
	for range attempts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := f.provider.ParseAuthorizeRequest(context.Background(), values)
			results <- err
		}()
	}
	wg.Wait()
	close(results)

	accepted := 0
	for err := range results {
		if err == nil {
			accepted++
		}
	}
	if accepted != 1 {
		t.Errorf("%d of %d concurrent redemptions succeeded, want exactly 1", accepted, attempts)
	}
}

// TestRequestURICannotBeRedeemedByAnotherClient.
//
// A captured request_uri redeemed under a different client would run one
// client's validated request against another's registration -- including its
// redirect allowlist.
func TestRequestURICannotBeRedeemedByAnotherClient(t *testing.T) {
	f := newPARFixture(t)
	f.store.clients["other-client"] = &Client{
		ID:           "other-client",
		RedirectURIs: []string{"https://other.test/callback"},
	}

	request := f.push(t, authorizeValues())

	_, err := f.provider.ParseAuthorizeRequest(context.Background(), url.Values{
		"client_id":   {"other-client"},
		"request_uri": {request.URI},
	})
	if err == nil {
		t.Fatal("a pushed request was redeemed under a different client")
	}
}

// TestExpiredRequestURIIsRefused. The lifetime is the window in which a leaked
// request_uri is useful, so it has to actually end.
func TestExpiredRequestURIIsRefused(t *testing.T) {
	f := newPARFixture(t, WithPushedRequestTTL(time.Millisecond))
	request := f.push(t, authorizeValues())

	// The store's own expiry check uses wall-clock time.
	time.Sleep(5 * time.Millisecond)

	_, err := f.provider.ParseAuthorizeRequest(context.Background(), url.Values{
		"client_id":   {testClientID},
		"request_uri": {request.URI},
	})
	if err == nil {
		t.Fatal("an expired request_uri was redeemed")
	}
}

// TestPushRefusesAnInvalidRequest.
//
// Validating at push time is the point: the client learns about a bad request
// over a direct authenticated channel where it can read the error, instead of
// the end user meeting it as a redirect. Storing an unvalidated request would
// move the failure to the browser and hand out a request_uri for a request
// that can never be completed.
func TestPushRefusesAnInvalidRequest(t *testing.T) {
	f := newPARFixture(t)

	values := authorizeValues()
	values.Set("redirect_uri", "https://attacker.test/callback")

	request, err := f.provider.PushAuthorizationRequest(context.Background(), values, basicAuth())
	if err == nil {
		t.Fatal("a request with an unregistered redirect_uri was pushed")
	}
	if request != nil {
		t.Error("a request_uri was returned alongside the error")
	}
}

// TestPushRequiresClientAuthentication. The endpoint accepts a fully formed
// authorization request; an unauthenticated one would let anyone lodge
// requests against any client and enumerate registrations by the errors.
func TestPushRequiresClientAuthentication(t *testing.T) {
	f := newPARFixture(t)

	if _, err := f.provider.PushAuthorizationRequest(context.Background(), authorizeValues(), ""); err == nil {
		t.Fatal("a pushed request was accepted with no client authentication")
	}
}

// TestPushRejectsANestedRequestURI. RFC 9126 section 2.1 forbids it. Chaining
// would let a second push inherit the first's already-validated parameters
// while presenting its own client authentication.
func TestPushRejectsANestedRequestURI(t *testing.T) {
	f := newPARFixture(t)
	first := f.push(t, authorizeValues())

	values := authorizeValues()
	values.Set("request_uri", first.URI)

	if _, err := f.provider.PushAuthorizationRequest(context.Background(), values, basicAuth()); err == nil {
		t.Fatal("a pushed request carrying a request_uri was accepted")
	}
}

// TestPushedRequestDropsClientCredentials. A stored request that kept the
// secret would persist it, and re-present it at redemption where nothing
// authenticates.
func TestPushedRequestDropsClientCredentials(t *testing.T) {
	f := newPARFixture(t)

	values := authorizeValues()
	values.Set("client_secret", testClientSecret)

	request, err := f.provider.PushAuthorizationRequest(context.Background(), values, "")
	if err != nil {
		t.Fatalf("PushAuthorizationRequest: %v", err)
	}
	for _, name := range []string{"client_secret", "client_assertion", "client_assertion_type"} {
		if request.Parameters.Get(name) != "" {
			t.Errorf("the stored request kept %s", name)
		}
	}
}

// TestNonURNRequestURIIsRefusedByShape.
//
// A request_uri that is a URL is the RFC 9101 fetch-the-request-object
// feature, which this provider does not implement. A URL never matches a
// stored entry, so it would be refused regardless -- this asserts it is
// refused for its shape, before reaching the store at all.
//
// The distinction is the point of the check. "Unknown request_uri" invites the
// obvious next step of resolving it, and that step turns the authorization
// endpoint into a fetcher of attacker-chosen addresses. Refusing the form says
// the feature is absent rather than that this particular URL was not found.
func TestNonURNRequestURIIsRefusedByShape(t *testing.T) {
	f := newPARFixture(t)

	for _, uri := range []string{
		"https://attacker.test/request.jwt",
		"http://169.254.169.254/latest/meta-data/",
		"file:///etc/passwd",
	} {
		_, err := f.provider.ParseAuthorizeRequest(context.Background(), url.Values{
			"client_id":   {testClientID},
			"request_uri": {uri},
		})
		if err == nil {
			t.Errorf("request_uri %q was accepted", uri)
			continue
		}
		var oerr *Error
		if !errors.As(err, &oerr) {
			t.Errorf("request_uri %q: error = %v, want an *oauth2.Error", uri, err)
			continue
		}
		if !strings.Contains(oerr.Description, "must be a pushed authorization request URN") {
			t.Errorf("request_uri %q was refused as %q, not for its shape; a URL must "+
				"not reach the store, where the next change is to resolve it",
				uri, oerr.Description)
		}
	}
}

// TestPARCanBeRequired. FAPI 2.0 requires it: without enforcement a client may
// still send a plain authorization request, so the integrity PAR provides is
// available rather than guaranteed, and an attacker who can influence a
// redirect uses the path that has none.
func TestPARCanBeRequired(t *testing.T) {
	f := newPARFixture(t, WithRequirePushedRequests(true))

	if _, err := f.provider.ParseAuthorizeRequest(context.Background(), authorizeValues()); err == nil {
		t.Fatal("a plain authorization request was accepted by a provider that requires PAR")
	}

	request := f.push(t, authorizeValues())
	if _, err := f.provider.ParseAuthorizeRequest(context.Background(), url.Values{
		"client_id":   {testClientID},
		"request_uri": {request.URI},
	}); err != nil {
		t.Fatalf("a pushed request was refused by a provider that requires PAR: %v", err)
	}
}

// TestPARDisabledWithoutAStore. Serving the endpoint with nowhere to persist
// would hand out request_uri values that resolve to nothing.
func TestPARDisabledWithoutAStore(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	store := newSecurityStore()
	provider := NewProvider(store, store, store, "https://issuer.example.test", key, "kid-1")

	if provider.SupportsPushedRequests() {
		t.Error("a provider with no store reported PAR support")
	}

	_, err = provider.PushAuthorizationRequest(context.Background(), authorizeValues(), basicAuth())
	if err == nil {
		t.Fatal("the endpoint served a request with no store configured")
	}
	if !errors.Is(err, ErrNoPushedRequestStore) {
		t.Errorf("error = %v, want ErrNoPushedRequestStore", err)
	}
}
