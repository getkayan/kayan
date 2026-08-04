package oauth2

import (
	"context"
	"encoding/base64"
	"errors"
	"net/url"
	"testing"

	"github.com/getkayan/kayan/core/domain"
	"golang.org/x/crypto/bcrypt"
)

// authorizeValues builds a well-formed authorization request.
func authorizeValues() url.Values {
	return url.Values{
		"client_id":             {testClientID},
		"redirect_uri":          {testRedirectURI},
		"response_type":         {ResponseTypeCode},
		"scope":                 {"openid profile"},
		"state":                 {"opaque-state"},
		"nonce":                 {"request-nonce"},
		"code_challenge":        {challengeFor("verifier")},
		"code_challenge_method": {challengeMethodS256},
	}
}

func TestParseAuthorizeRequest(t *testing.T) {
	ctx := context.Background()
	provider, _ := newSecureProvider(t)

	req, err := provider.ParseAuthorizeRequest(ctx, authorizeValues())
	if err != nil {
		t.Fatalf("ParseAuthorizeRequest: %v", err)
	}

	if req.ClientID != testClientID {
		t.Errorf("ClientID = %q, want %q", req.ClientID, testClientID)
	}
	if req.RedirectURI != testRedirectURI {
		t.Errorf("RedirectURI = %q, want %q", req.RedirectURI, testRedirectURI)
	}
	if req.Nonce != "request-nonce" {
		t.Errorf("Nonce = %q, want request-nonce", req.Nonce)
	}
	if req.State != "opaque-state" {
		t.Errorf("State = %q", req.State)
	}
	if len(req.Scopes) != 2 {
		t.Errorf("Scopes = %v, want two entries", req.Scopes)
	}
}

// TestParseAuthorizeRequestRejects covers the checks that must happen inside
// the parser. A caller hand-parsing the query string would have to reimplement
// every one of these, which is how open redirectors get shipped.
func TestParseAuthorizeRequestRejects(t *testing.T) {
	ctx := context.Background()
	provider, _ := newSecureProvider(t)

	tests := []struct {
		name    string
		mutate  func(url.Values)
		wantErr error
	}{
		{
			name:    "missing client_id",
			mutate:  func(v url.Values) { v.Del("client_id") },
			wantErr: ErrInvalidRequest,
		},
		{
			name:    "unknown client",
			mutate:  func(v url.Values) { v.Set("client_id", "no-such-client") },
			wantErr: ErrInvalidClient,
		},
		{
			name:    "unregistered redirect_uri",
			mutate:  func(v url.Values) { v.Set("redirect_uri", "https://evil.test/callback") },
			wantErr: ErrInvalidRequest,
		},
		{
			name:    "missing response_type",
			mutate:  func(v url.Values) { v.Del("response_type") },
			wantErr: ErrInvalidRequest,
		},
		{
			name:    "implicit flow is not implemented",
			mutate:  func(v url.Values) { v.Set("response_type", "id_token") },
			wantErr: ErrUnsupportedResponseType,
		},
		{
			name:    "hybrid flow is not implemented",
			mutate:  func(v url.Values) { v.Set("response_type", "code id_token") },
			wantErr: ErrUnsupportedResponseType,
		},
		{
			name:    "missing PKCE challenge",
			mutate:  func(v url.Values) { v.Del("code_challenge") },
			wantErr: ErrInvalidRequest,
		},
		{
			name:    "plain PKCE method",
			mutate:  func(v url.Values) { v.Set("code_challenge_method", "plain") },
			wantErr: ErrInvalidRequest,
		},
		{
			name:    "unknown PKCE method",
			mutate:  func(v url.Values) { v.Set("code_challenge_method", "MD5") },
			wantErr: ErrInvalidRequest,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			values := authorizeValues()
			tc.mutate(values)

			_, err := provider.ParseAuthorizeRequest(ctx, values)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("error = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

// TestNonceReachesTheAuthorizationCode proves the nonce survives the round
// trip. Without it a relying party cannot bind an ID token to its request.
func TestNonceReachesTheAuthorizationCode(t *testing.T) {
	ctx := context.Background()
	provider, store := newSecureProvider(t)

	req, err := provider.ParseAuthorizeRequest(ctx, authorizeValues())
	if err != nil {
		t.Fatalf("ParseAuthorizeRequest: %v", err)
	}

	code, err := provider.GenerateAuthCodeFor(ctx, req, "user-1")
	if err != nil {
		t.Fatalf("GenerateAuthCodeFor: %v", err)
	}

	saved, err := store.GetAuthCode(ctx, code)
	if err != nil {
		t.Fatalf("GetAuthCode: %v", err)
	}
	if saved.Nonce != "request-nonce" {
		t.Errorf("stored nonce = %q, want request-nonce", saved.Nonce)
	}
}

// TestParseTokenRequestAcceptsBasicAuth covers RFC 6749 section 2.3.1,
// including the form-urlencoding of credentials that a naive implementation
// omits.
func TestParseTokenRequestAcceptsBasicAuth(t *testing.T) {
	ctx := context.Background()
	provider, _ := newSecureProvider(t)

	credentials := url.QueryEscape(testClientID) + ":" + url.QueryEscape(testClientSecret)
	header := "Basic " + base64.StdEncoding.EncodeToString([]byte(credentials))

	req, err := provider.ParseTokenRequest(ctx, url.Values{
		"grant_type":    {GrantRefreshToken},
		"refresh_token": {"some-token"},
	}, header)
	if err != nil {
		t.Fatalf("ParseTokenRequest: %v", err)
	}
	if req.Client.ID != testClientID {
		t.Errorf("Client.ID = %q, want %q", req.Client.ID, testClientID)
	}
}

func TestParseTokenRequestRejects(t *testing.T) {
	ctx := context.Background()
	provider, _ := newSecureProvider(t)

	tests := []struct {
		name    string
		values  url.Values
		header  string
		wantErr error
	}{
		{
			name:    "missing grant_type",
			values:  url.Values{"client_id": {testClientID}, "client_secret": {testClientSecret}},
			wantErr: ErrInvalidRequest,
		},
		{
			name: "unsupported grant",
			values: url.Values{
				"grant_type":    {"urn:ietf:params:oauth:grant-type:device_code"},
				"client_id":     {testClientID},
				"client_secret": {testClientSecret},
			},
			wantErr: ErrUnsupportedGrantType,
		},
		{
			name:    "no client credentials",
			values:  url.Values{"grant_type": {GrantRefreshToken}, "refresh_token": {"t"}},
			wantErr: ErrInvalidClient,
		},
		{
			name: "wrong secret",
			values: url.Values{
				"grant_type":    {GrantRefreshToken},
				"refresh_token": {"t"},
				"client_id":     {testClientID},
				"client_secret": {"wrong"},
			},
			wantErr: ErrInvalidClient,
		},
		{
			name:    "malformed authorization header",
			values:  url.Values{"grant_type": {GrantRefreshToken}, "refresh_token": {"t"}},
			header:  "Basic !!!not-base64!!!",
			wantErr: ErrInvalidClient,
		},
		{
			name:    "unsupported authorization scheme",
			values:  url.Values{"grant_type": {GrantRefreshToken}, "refresh_token": {"t"}},
			header:  "Bearer some-token",
			wantErr: ErrInvalidClient,
		},
		{
			name: "authorization code without a code",
			values: url.Values{
				"grant_type":    {GrantAuthorizationCode},
				"client_id":     {testClientID},
				"client_secret": {testClientSecret},
			},
			wantErr: ErrInvalidRequest,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := provider.ParseTokenRequest(ctx, tc.values, tc.header); !errors.Is(err, tc.wantErr) {
				t.Fatalf("error = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

// TestClientCredentialsGrant covers the machine-to-machine path.
func TestClientCredentialsGrant(t *testing.T) {
	ctx := context.Background()
	provider, _ := newSecureProvider(t)

	req, err := provider.ParseTokenRequest(ctx, url.Values{
		"grant_type":    {GrantClientCredentials},
		"client_id":     {testClientID},
		"client_secret": {testClientSecret},
	}, "")
	if err != nil {
		t.Fatalf("ParseTokenRequest: %v", err)
	}

	tokens, err := provider.ClientCredentials(ctx, req)
	if err != nil {
		t.Fatalf("ClientCredentials: %v", err)
	}
	if tokens.AccessToken == "" {
		t.Error("no access token was issued")
	}
	// The token authenticates the client, so there is no user to refresh for.
	if tokens.RefreshToken != "" {
		t.Error("the client credentials grant must not issue a refresh token")
	}
	if tokens.Sub != testClientID {
		t.Errorf("Sub = %q, want the client ID", tokens.Sub)
	}
}

// TestClientCredentialsRejectsPublicClient proves a client with no secret
// cannot use a grant whose entire purpose is authenticating with one.
func TestClientCredentialsRejectsPublicClient(t *testing.T) {
	ctx := context.Background()
	provider, store := newSecureProvider(t)

	store.clients["public-1"] = &Client{
		ID:                      "public-1",
		TokenEndpointAuthMethod: AuthMethodNone,
		RedirectURIs:            []string{testRedirectURI},
	}

	_, err := provider.ParseTokenRequest(ctx, url.Values{
		"grant_type": {GrantClientCredentials},
		"client_id":  {"public-1"},
	}, "")
	if !errors.Is(err, ErrUnauthorizedClient) {
		t.Fatalf("error = %v, want ErrUnauthorizedClient", err)
	}
}

// TestGrantTypeRestrictionEnforced proves Client.GrantTypes is honored. It was
// previously declared and never read.
func TestGrantTypeRestrictionEnforced(t *testing.T) {
	ctx := context.Background()
	provider, store := newSecureProvider(t)

	hasher := domain.NewBcryptHasher(bcrypt.MinCost)
	hash, err := hasher.Hash(testClientSecret)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	store.clients["limited"] = &Client{
		ID:           "limited",
		SecretHash:   hash,
		RedirectURIs: []string{testRedirectURI},
		GrantTypes:   []string{GrantAuthorizationCode},
	}

	_, err = provider.ParseTokenRequest(ctx, url.Values{
		"grant_type":    {GrantClientCredentials},
		"client_id":     {"limited"},
		"client_secret": {testClientSecret},
	}, "")
	if !errors.Is(err, ErrUnauthorizedClient) {
		t.Fatalf("error = %v, want ErrUnauthorizedClient", err)
	}
}

// TestScopeRestrictionEnforced proves a client cannot request a scope it was
// not granted.
func TestScopeRestrictionEnforced(t *testing.T) {
	ctx := context.Background()
	provider, store := newSecureProvider(t)

	store.clients[testClientID].Scopes = []string{"openid", "profile"}

	values := authorizeValues()
	values.Set("scope", "openid admin")

	if _, err := provider.ParseAuthorizeRequest(ctx, values); !errors.Is(err, ErrInvalidScope) {
		t.Fatalf("error = %v, want ErrInvalidScope", err)
	}
}

// TestRedirectURIOmittedWithOneRegistered covers the RFC 6749 allowance for
// omitting the parameter, and the case where it cannot apply.
func TestRedirectURIOmittedWithOneRegistered(t *testing.T) {
	ctx := context.Background()
	provider, store := newSecureProvider(t)

	values := authorizeValues()
	values.Del("redirect_uri")

	req, err := provider.ParseAuthorizeRequest(ctx, values)
	if err != nil {
		t.Fatalf("ParseAuthorizeRequest: %v", err)
	}
	if req.RedirectURI != testRedirectURI {
		t.Errorf("RedirectURI = %q, want the single registered URI", req.RedirectURI)
	}

	// With several registered there is no safe way to choose one.
	store.clients[testClientID].RedirectURIs = []string{
		testRedirectURI,
		"https://app.example.test/other",
	}
	if _, err := provider.ParseAuthorizeRequest(ctx, values); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("error = %v, want ErrInvalidRequest when several URIs are registered", err)
	}
}
