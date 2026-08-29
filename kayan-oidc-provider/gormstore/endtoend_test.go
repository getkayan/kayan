package gormstore

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"testing"
	"time"

	"github.com/getkayan/kayan/core/domain"
	"github.com/getkayan/kayan/core/keys"
	"github.com/getkayan/kayan/kayan-oidc-provider/oauth2"
	"github.com/getkayan/kayan/kayan-oidc-provider/oidc"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// This file exercises a whole sign-in rather than one method of it.
//
// Every other test in this module checks a single call in isolation, which is
// the right way to pin a security property but says nothing about whether the
// pieces fit together. A provider whose parts are each correct can still be
// unusable: the nonce reaching the ID token, the access token verifying against
// the published JWKS, the authorization code carrying auth_time to the token
// endpoint -- each of those is a seam between two components that no unit test
// crosses. One of them was in fact broken until recently, and unit tests were
// green throughout.
//
// It also runs against the real GORM store rather than an in-memory double, so
// a field the schema cannot hold shows up here.

const (
	e2eIssuer   = "https://issuer.example.test"
	e2eTokenURL = "https://issuer.example.test/oauth2/token"
	e2eClient   = "web-app"
	e2eSecret   = "web-app-secret"
	e2eRedirect = "https://app.example.test/callback"
	e2eSubject  = "user-42"
)

type e2eFixture struct {
	provider *oauth2.Provider
	server   *oidc.Server
	repo     *OAuth2Repository
	keys     *keys.StaticProvider
}

// newE2E wires a provider and an OIDC server the way a deployment would.
func newE2E(t *testing.T) *e2eFixture {
	t.Helper()

	repo := setupRepo(t)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	keyProvider := keys.NewStaticProvider(&keys.Key{
		KID: "kid-1", Method: jwt.SigningMethodRS256,
		Private: key, Public: &key.PublicKey,
	})

	hasher := domain.NewBcryptHasher(bcrypt.MinCost)
	hash, err := hasher.Hash(e2eSecret)
	if err != nil {
		t.Fatalf("hash secret: %v", err)
	}
	if err := repo.CreateClient(context.Background(), &oauth2.Client{
		ID:           e2eClient,
		SecretHash:   hash,
		RedirectURIs: []string{e2eRedirect},
		Scopes:       []string{"openid", "profile", "email"},
		GrantTypes:   []string{oauth2.GrantAuthorizationCode, oauth2.GrantRefreshToken},
	}); err != nil {
		t.Fatalf("CreateClient: %v", err)
	}

	provider := oauth2.NewProvider(repo, repo, repo, e2eIssuer, key, "kid-1",
		oauth2.WithKeyProvider(keyProvider),
		oauth2.WithClientSecretHasher(hasher),
		oauth2.WithTokenEndpointURL(e2eTokenURL),
		oauth2.WithPushedRequests(oauth2.NewMemoryPushedRequestStore()),
	)

	server := oidc.NewServer(e2eIssuer, key, "kid-1",
		oidc.WithServerKeyProvider(keyProvider),
		oidc.WithClientStore(repo),
		oidc.WithTokenIntrospector(provider),
		oidc.WithPushedRequestSupport(provider),
		oidc.WithClaimsSource(oidc.ClaimsSourceFunc(
			func(_ context.Context, identityID string, scopes []string) (map[string]any, error) {
				claims := map[string]any{}
				for _, scope := range scopes {
					if scope == "email" {
						claims["email"] = "user42@example.test"
					}
				}
				return claims, nil
			})),
	)

	return &e2eFixture{provider: provider, server: server, repo: repo, keys: keyProvider}
}

// pkce returns a verifier and its S256 challenge.
func pkce() (verifier, challenge string) {
	verifier = "a-verifier-long-enough-to-satisfy-the-rfc-7636-minimum"
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

// TestAuthorizationCodeSignInEndToEnd walks the flow a browser sign-in takes.
//
// Authorization request, consent, code, token exchange, ID token, and then the
// verification a relying party performs against the published key set. Each
// step uses only the public API, so this is the path an application actually
// depends on.
func TestAuthorizationCodeSignInEndToEnd(t *testing.T) {
	f := newE2E(t)
	ctx := context.Background()
	verifier, challenge := pkce()

	// 1. The relying party sends the browser to the authorization endpoint.
	authorizeReq, err := f.provider.ParseAuthorizeRequest(ctx, url.Values{
		"client_id":             {e2eClient},
		"redirect_uri":          {e2eRedirect},
		"response_type":         {oauth2.ResponseTypeCode},
		"scope":                 {"openid email"},
		"state":                 {"rp-state"},
		"nonce":                 {"rp-nonce"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"max_age":               {"3600"},
	})
	if err != nil {
		t.Fatalf("ParseAuthorizeRequest: %v", err)
	}

	// 2. The application authenticates the user however it likes, then hands
	//    back what happened.
	authTime := time.Now().Add(-2 * time.Minute).Truncate(time.Second)
	code, err := f.provider.GenerateAuthCodeForAuthentication(ctx, authorizeReq, e2eSubject,
		oauth2.AuthenticationInfo{
			AuthTime: authTime,
			ACR:      "urn:example:mfa",
			AMR:      []string{"pwd", "otp"},
		})
	if err != nil {
		t.Fatalf("GenerateAuthCodeForAuthentication: %v", err)
	}

	// 3. The relying party exchanges the code at the token endpoint.
	tokens, err := f.provider.Exchange(ctx, code, e2eClient, e2eSecret, e2eRedirect, verifier)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if tokens.AccessToken == "" || tokens.RefreshToken == "" {
		t.Fatal("Exchange returned an incomplete token response")
	}

	// The nonce has to survive the code. It was unreachable through this path
	// until recently: the code held it, Exchange consumed the code, and nothing
	// handed it back -- so no caller could populate the claim.
	if tokens.Authentication.Nonce != "rp-nonce" {
		t.Errorf("nonce = %q, want the value from the authorization request",
			tokens.Authentication.Nonce)
	}
	if !tokens.Authentication.AuthTime.Equal(authTime) {
		t.Errorf("auth_time = %v, want %v", tokens.Authentication.AuthTime, authTime)
	}

	// 4. The provider mints the ID token from what the exchange returned.
	maxAge := 3600
	idToken, err := f.server.IssueIDToken(ctx, oidc.IDTokenRequest{
		ClientID:      e2eClient,
		IdentityID:    e2eSubject,
		Scopes:        authorizeReq.Scopes,
		Nonce:         tokens.Authentication.Nonce,
		AuthTime:      tokens.Authentication.AuthTime,
		ACR:           tokens.Authentication.ACR,
		AMR:           tokens.Authentication.AMR,
		AccessToken:   tokens.AccessToken,
		MaxAgeSeconds: &maxAge,
	})
	if err != nil {
		t.Fatalf("IssueIDToken: %v", err)
	}

	// 5. The relying party verifies the ID token against the published JWKS,
	//    which is the only thing it is given to verify with.
	claims := verifyAgainstJWKS(t, ctx, f, idToken)

	for name, want := range map[string]any{
		"iss":   e2eIssuer,
		"sub":   e2eSubject,
		"aud":   e2eClient,
		"nonce": "rp-nonce",
		"acr":   "urn:example:mfa",
		"email": "user42@example.test",
	} {
		if got := claims[name]; got != want {
			t.Errorf("%s = %v, want %v", name, got, want)
		}
	}
	if got, ok := claims["auth_time"].(float64); !ok || int64(got) != authTime.Unix() {
		t.Errorf("auth_time = %v, want %d", claims["auth_time"], authTime.Unix())
	}
	if _, present := claims["at_hash"]; !present {
		t.Error("no at_hash: nothing binds the ID token to the access token issued beside it")
	}

	// 6. The access token works at UserInfo, and reports the same subject. A
	//    provider that answered UserInfo for a different subject than the ID
	//    token names would let a relying party mix two users' data.
	info, err := f.server.UserInfo(ctx, tokens.AccessToken)
	if err != nil {
		t.Fatalf("UserInfo: %v", err)
	}
	if info["sub"] != e2eSubject {
		t.Errorf("UserInfo sub = %v, want %v", info["sub"], e2eSubject)
	}

	// 7. The code is spent. Replaying it is the single most valuable thing an
	//    attacker can do with an intercepted redirect.
	if _, err := f.provider.Exchange(ctx, code, e2eClient, e2eSecret, e2eRedirect, verifier); err == nil {
		t.Error("the authorization code was redeemed twice")
	}
}

// TestRefreshRotatesAndDetectsReuse covers the other half of a session's life.
func TestRefreshRotatesAndDetectsReuse(t *testing.T) {
	f := newE2E(t)
	ctx := context.Background()
	verifier, challenge := pkce()

	req, err := f.provider.ParseAuthorizeRequest(ctx, url.Values{
		"client_id": {e2eClient}, "redirect_uri": {e2eRedirect},
		"response_type": {oauth2.ResponseTypeCode}, "scope": {"openid"},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"},
	})
	if err != nil {
		t.Fatalf("ParseAuthorizeRequest: %v", err)
	}
	code, err := f.provider.GenerateAuthCodeFor(ctx, req, e2eSubject)
	if err != nil {
		t.Fatalf("GenerateAuthCodeFor: %v", err)
	}
	first, err := f.provider.Exchange(ctx, code, e2eClient, e2eSecret, e2eRedirect, verifier)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}

	second, err := f.provider.Refresh(ctx, first.RefreshToken, e2eClient, e2eSecret)
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if second.RefreshToken == first.RefreshToken {
		t.Error("the refresh token was not rotated, so a captured one stays valid forever")
	}

	// Presenting the rotated-away token is the signal that it leaked.
	if _, err := f.provider.Refresh(ctx, first.RefreshToken, e2eClient, e2eSecret); err == nil {
		t.Error("a spent refresh token was accepted a second time")
	}
}

// TestPushedRequestSignInEndToEnd runs the same sign-in through PAR, which is
// the shape FAPI requires and a different code path into the same flow.
func TestPushedRequestSignInEndToEnd(t *testing.T) {
	f := newE2E(t)
	ctx := context.Background()
	verifier, challenge := pkce()

	basic := "Basic " + base64.StdEncoding.EncodeToString(
		[]byte(url.QueryEscape(e2eClient)+":"+url.QueryEscape(e2eSecret)))

	pushed, err := f.provider.PushAuthorizationRequest(ctx, url.Values{
		"redirect_uri":          {e2eRedirect},
		"response_type":         {oauth2.ResponseTypeCode},
		"scope":                 {"openid email"},
		"state":                 {"rp-state"},
		"nonce":                 {"rp-nonce"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}, basic)
	if err != nil {
		t.Fatalf("PushAuthorizationRequest: %v", err)
	}

	req, err := f.provider.ParseAuthorizeRequest(ctx, url.Values{
		"client_id":   {e2eClient},
		"request_uri": {pushed.URI},
	})
	if err != nil {
		t.Fatalf("ParseAuthorizeRequest via request_uri: %v", err)
	}
	if req.RedirectURI != e2eRedirect || req.Nonce != "rp-nonce" {
		t.Fatalf("the pushed parameters did not survive: %+v", req)
	}

	code, err := f.provider.GenerateAuthCodeFor(ctx, req, e2eSubject)
	if err != nil {
		t.Fatalf("GenerateAuthCodeFor: %v", err)
	}
	tokens, err := f.provider.Exchange(ctx, code, e2eClient, e2eSecret, e2eRedirect, verifier)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}

	idToken, err := f.server.IssueIDToken(ctx, oidc.IDTokenRequest{
		ClientID: e2eClient, IdentityID: e2eSubject, Scopes: req.Scopes,
		Nonce: tokens.Authentication.Nonce, AccessToken: tokens.AccessToken,
	})
	if err != nil {
		t.Fatalf("IssueIDToken: %v", err)
	}
	claims := verifyAgainstJWKS(t, ctx, f, idToken)
	if claims["nonce"] != "rp-nonce" {
		t.Errorf("nonce = %v, want it carried through PAR", claims["nonce"])
	}
}

// TestDiscoveryDescribesWhatTheProviderServes. A relying party configures
// itself from this document; anything it advertises has to be real.
func TestDiscoveryDescribesWhatTheProviderServes(t *testing.T) {
	f := newE2E(t)

	doc, err := f.server.BuildDiscovery(context.Background(), oidc.DiscoveryOptions{
		Endpoints: oidc.Endpoints{
			Authorization:              e2eIssuer + "/authorize",
			Token:                      e2eTokenURL,
			JWKS:                       e2eIssuer + "/jwks",
			UserInfo:                   e2eIssuer + "/userinfo",
			PushedAuthorizationRequest: e2eIssuer + "/par",
		},
	})
	if err != nil {
		t.Fatalf("BuildDiscovery: %v", err)
	}

	if doc.Issuer != e2eIssuer {
		t.Errorf("issuer = %q", doc.Issuer)
	}
	if len(doc.IDTokenSigningAlgValuesSupported) == 0 {
		t.Error("no signing algorithms advertised, so a relying party cannot verify anything")
	}
	// PAR is configured on this provider, so it must be advertised; the
	// endpoint is omitted when the provider cannot serve it.
	if doc.PushedAuthorizationRequestEndpoint == "" {
		t.Error("PAR is enabled but not advertised")
	}
}

// verifyAgainstJWKS validates an ID token the way a relying party does: against
// the published key set, selected by kid, with no access to the private key.
func verifyAgainstJWKS(t *testing.T, ctx context.Context, f *e2eFixture, raw string) jwt.MapClaims {
	t.Helper()

	published, err := f.provider.JWKS(ctx)
	if err != nil {
		t.Fatalf("JWKS: %v", err)
	}
	encoded, err := json.Marshal(published)
	if err != nil {
		t.Fatalf("marshal JWKS: %v", err)
	}
	// Round-tripped through JSON on purpose: this is the document a relying
	// party fetches, not the struct the provider happens to hold.
	set, err := keys.ParseJWKS(encoded)
	if err != nil {
		t.Fatalf("ParseJWKS: %v", err)
	}

	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(raw, claims, func(tok *jwt.Token) (any, error) {
		kid, _ := tok.Header["kid"].(string)
		jwk, found := set.Find(kid)
		if !found {
			t.Fatalf("the published key set has no key for kid %q", kid)
		}
		return jwk.PublicKey()
	}, jwt.WithValidMethods([]string{"RS256"}))
	if err != nil || !token.Valid {
		t.Fatalf("the ID token does not verify against the published JWKS: %v", err)
	}
	return claims
}
