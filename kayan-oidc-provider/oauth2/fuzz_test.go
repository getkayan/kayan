package oauth2

import (
	"context"
	"net/url"
	"testing"
)

// FuzzParseAuthorizeRequest drives the authorization parser with arbitrary
// parameters.
//
// The parser runs before authentication, on input taken straight from a query
// string, so it must never panic and must never return a request whose
// redirect URI was not registered — that combination is what an open
// redirector is.
func FuzzParseAuthorizeRequest(f *testing.F) {
	f.Add(testClientID, testRedirectURI, "code", "openid", "S256", "challenge")
	f.Add("", "", "", "", "", "")
	f.Add(testClientID, "https://evil.test", "code", "openid", "S256", "c")
	f.Add(testClientID, testRedirectURI, "id_token", "openid", "plain", "c")
	f.Add(testClientID, testRedirectURI+"\x00", "code", "openid", "S256", "c")
	f.Add(testClientID, "javascript:alert(1)", "code", "openid", "S256", "c")

	provider, _ := newFuzzProvider(f)
	ctx := context.Background()

	f.Fuzz(func(t *testing.T, clientID, redirectURI, responseType, scope, method, challenge string) {
		values := url.Values{
			"client_id":             {clientID},
			"redirect_uri":          {redirectURI},
			"response_type":         {responseType},
			"scope":                 {scope},
			"code_challenge_method": {method},
			"code_challenge":        {challenge},
		}

		req, err := provider.ParseAuthorizeRequest(ctx, values)
		if err != nil {
			return
		}

		// A request that parsed must carry a registered redirect URI.
		if !req.Client.AllowsRedirectURI(req.RedirectURI) {
			t.Fatalf("parser accepted an unregistered redirect_uri %q", req.RedirectURI)
		}
		// It must also carry a supported response type.
		if len(req.ResponseType) != 1 || req.ResponseType[0] != ResponseTypeCode {
			t.Fatalf("parser accepted response_type %v", req.ResponseType)
		}
		// And a resolved PKCE method, never an empty one that a later stage
		// might read as "plain".
		if req.CodeChallenge != "" && req.CodeChallengeMethod == "" {
			t.Fatal("parser returned a challenge with no method")
		}
	})
}

// FuzzParseTokenRequest drives the token parser, including the Authorization
// header, which is attacker-controlled and base64-decoded.
func FuzzParseTokenRequest(f *testing.F) {
	f.Add("authorization_code", testClientID, testClientSecret, "code-1", "")
	f.Add("refresh_token", testClientID, testClientSecret, "", "Basic")
	f.Add("", "", "", "", "")
	f.Add("client_credentials", testClientID, testClientSecret, "", "Basic !!!")
	f.Add("refresh_token", testClientID, testClientSecret, "", "Basic AAAA")

	provider, _ := newFuzzProvider(f)
	ctx := context.Background()

	f.Fuzz(func(t *testing.T, grantType, clientID, clientSecret, code, authorization string) {
		values := url.Values{
			"grant_type":    {grantType},
			"client_id":     {clientID},
			"client_secret": {clientSecret},
			"code":          {code},
			"refresh_token": {code},
		}

		req, err := provider.ParseTokenRequest(ctx, values, authorization)
		if err != nil {
			return
		}

		// Anything that parsed must have an authenticated client attached.
		if req.Client == nil {
			t.Fatal("parser returned a request with no client")
		}
		if !req.Client.AllowsGrantType(req.GrantType) {
			t.Fatalf("parser accepted grant %q for a client that may not use it", req.GrantType)
		}
	})
}

// FuzzVerifyPKCE checks the code verifier comparison.
func FuzzVerifyPKCE(f *testing.F) {
	f.Add("challenge", "S256", "verifier")
	f.Add("", "", "")
	f.Add("abc", "plain", "abc")
	f.Add("abc", "", "abc")

	provider, _ := newFuzzProvider(f)

	f.Fuzz(func(t *testing.T, challenge, method, verifier string) {
		if provider.verifyPKCE(challenge, method, verifier) {
			// A verification that succeeded must have used S256, since "plain"
			// is disabled on this provider. Anything else means the comparison
			// degraded to a plaintext match.
			if normalizeChallengeMethod(method) != challengeMethodS256 {
				t.Fatalf("PKCE verified with method %q on a provider that only allows S256", method)
			}
			if challenge != challengeFor(verifier) {
				t.Fatalf("PKCE verified a challenge that is not the SHA-256 of the verifier")
			}
		}
	})
}

// newFuzzProvider builds a provider for fuzzing.
//
// It takes testing.TB rather than fabricating a *testing.T, so a setup failure
// is reported against the fuzz target instead of being swallowed.
func newFuzzProvider(tb testing.TB) (*Provider, *securityStore) {
	tb.Helper()
	return newSecureProvider(tb)
}
