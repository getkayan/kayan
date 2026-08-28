package oauth2

import (
	"context"
	"errors"
	"testing"
	"time"
)

func intPtr(n int) *int { return &n }

// TestMaxAgeIsParsed covers the parameter reaching the request at all. An
// unparsed max_age is silently "no constraint", which is the failure the rest
// of these tests are about.
func TestMaxAgeIsParsed(t *testing.T) {
	provider, _ := newSecureProvider(t)

	values := authorizeValues()
	values.Set("max_age", "300")
	values.Set("acr_values", "urn:mace:incommon:iap:silver urn:example:mfa")

	req, err := provider.ParseAuthorizeRequest(context.Background(), values)
	if err != nil {
		t.Fatalf("ParseAuthorizeRequest: %v", err)
	}
	if req.MaxAge == nil || *req.MaxAge != 300 {
		t.Errorf("MaxAge = %v, want 300", req.MaxAge)
	}
	if len(req.ACRValues) != 2 {
		t.Errorf("ACRValues = %v, want two entries", req.ACRValues)
	}
}

// TestMaxAgeZeroIsNotAbsent. max_age=0 asks for reauthentication now, which is
// exactly what a step-up sends. An int rather than a pointer would collapse it
// into "not requested" and answer the strongest possible demand by ignoring it.
func TestMaxAgeZeroIsNotAbsent(t *testing.T) {
	provider, _ := newSecureProvider(t)

	values := authorizeValues()
	values.Set("max_age", "0")

	req, err := provider.ParseAuthorizeRequest(context.Background(), values)
	if err != nil {
		t.Fatalf("ParseAuthorizeRequest: %v", err)
	}
	if req.MaxAge == nil {
		t.Fatal("max_age=0 was read as absent")
	}
	if *req.MaxAge != 0 {
		t.Errorf("MaxAge = %d, want 0", *req.MaxAge)
	}
	if !req.Requested() {
		t.Error("max_age=0 did not register as a constraint")
	}
}

// TestMalformedMaxAgeIsRefused. Ignoring an unreadable value turns
// "reauthenticate if the session is older than five minutes" into "reuse
// whatever session exists", and the relying party that sent it cannot tell.
func TestMalformedMaxAgeIsRefused(t *testing.T) {
	provider, _ := newSecureProvider(t)

	for _, raw := range []string{"soon", "-1", "5 minutes", "3.5"} {
		values := authorizeValues()
		values.Set("max_age", raw)

		if _, err := provider.ParseAuthorizeRequest(context.Background(), values); err == nil {
			t.Errorf("max_age %q was accepted", raw)
		}
	}
}

// TestNeedsReauthentication is the decision a caller makes before reusing a
// session. An unknown last-authentication time counts as needing one: the
// request asked a question about authentication age, and "we do not know" does
// not answer it.
func TestNeedsReauthentication(t *testing.T) {
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)

	cases := []struct {
		name     string
		maxAge   *int
		lastAuth time.Time
		want     bool
	}{
		{"no max_age", nil, now.Add(-24 * time.Hour), false},
		{"fresh enough", intPtr(300), now.Add(-time.Minute), false},
		{"too old", intPtr(300), now.Add(-time.Hour), true},
		{"exactly at the limit", intPtr(300), now.Add(-300 * time.Second), false},
		{"max_age zero with any age", intPtr(0), now.Add(-time.Second), true},
		{"unknown last authentication", intPtr(300), time.Time{}, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			requirements := AuthenticationRequirements{MaxAge: tc.maxAge}
			if got := requirements.NeedsReauthentication(tc.lastAuth, now); got != tc.want {
				t.Errorf("NeedsReauthentication = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestAuthCodeRefusesMaxAgeWithoutAuthTime is the central test.
//
// The relying party asked for an authentication no older than N seconds. If
// the authorization endpoint issues a code without recording when the user
// actually authenticated, the resulting ID token carries no auth_time -- which
// OIDC Core section 3.1.3.6 forbids for a max_age request -- and the relying
// party has nothing to check. The demand is answered by whatever session
// happened to exist, and nothing anywhere says so.
func TestAuthCodeRefusesMaxAgeWithoutAuthTime(t *testing.T) {
	provider, _ := newSecureProvider(t)

	values := authorizeValues()
	values.Set("max_age", "300")
	req, err := provider.ParseAuthorizeRequest(context.Background(), values)
	if err != nil {
		t.Fatalf("ParseAuthorizeRequest: %v", err)
	}

	code, err := provider.GenerateAuthCodeFor(context.Background(), req, "user-1")
	if err == nil {
		t.Fatal("a code was issued for a max_age request with no authentication time")
	}
	if code != "" {
		t.Errorf("a code was returned alongside the error: %q", code)
	}
}

// TestAuthCodeRefusesAnAlreadyStaleAuthentication. Recording an authentication
// that already fails max_age is the same silent answer with a timestamp
// attached.
func TestAuthCodeRefusesAnAlreadyStaleAuthentication(t *testing.T) {
	provider, _ := newSecureProvider(t)

	values := authorizeValues()
	values.Set("max_age", "300")
	req, err := provider.ParseAuthorizeRequest(context.Background(), values)
	if err != nil {
		t.Fatalf("ParseAuthorizeRequest: %v", err)
	}

	_, err = provider.GenerateAuthCodeForAuthentication(context.Background(), req, "user-1",
		AuthenticationInfo{AuthTime: time.Now().Add(-time.Hour)})
	if err == nil {
		t.Fatal("a code was issued from a session already older than the requested max_age")
	}
}

// TestFreshAuthenticationIssuesACode keeps the checks above from being a
// blanket refusal.
func TestFreshAuthenticationIssuesACode(t *testing.T) {
	provider, store := newSecureProvider(t)
	ctx := context.Background()

	values := authorizeValues()
	values.Set("max_age", "300")
	req, err := provider.ParseAuthorizeRequest(ctx, values)
	if err != nil {
		t.Fatalf("ParseAuthorizeRequest: %v", err)
	}

	authTime := time.Now().Add(-time.Minute)
	code, err := provider.GenerateAuthCodeForAuthentication(ctx, req, "user-1", AuthenticationInfo{
		AuthTime: authTime,
		ACR:      "urn:example:mfa",
		AMR:      []string{"pwd", "otp"},
	})
	if err != nil {
		t.Fatalf("GenerateAuthCodeForAuthentication: %v", err)
	}

	stored, err := store.GetAuthCode(ctx, code)
	if err != nil {
		t.Fatalf("GetAuthCode: %v", err)
	}
	if stored.AuthTime.IsZero() {
		t.Error("the code records no authentication time")
	}
	if stored.ACR != "urn:example:mfa" {
		t.Errorf("ACR = %q", stored.ACR)
	}
	if len(stored.AMR) != 2 {
		t.Errorf("AMR = %v", stored.AMR)
	}
	if stored.MaxAgeSeconds == nil || *stored.MaxAgeSeconds != 300 {
		t.Errorf("MaxAgeSeconds = %v, want 300; without it the token endpoint "+
			"cannot tell max_age was requested", stored.MaxAgeSeconds)
	}
}

// TestExchangeCarriesTheAuthenticationBack covers a gap that made the nonce
// binding unreachable.
//
// The authorization code holds the nonce, Exchange consumes and deletes that
// code, and nothing handed the value back -- so a caller following the
// ordinary flow could not populate the nonce claim at all, and the ID-token
// replay defence was implemented in the issuer and unusable from outside.
func TestExchangeCarriesTheAuthenticationBack(t *testing.T) {
	provider, _ := newSecureProvider(t)
	ctx := context.Background()

	values := authorizeValues()
	values.Set("max_age", "3600")
	req, err := provider.ParseAuthorizeRequest(ctx, values)
	if err != nil {
		t.Fatalf("ParseAuthorizeRequest: %v", err)
	}

	authTime := time.Now().Add(-time.Minute).Truncate(time.Second)
	code, err := provider.GenerateAuthCodeForAuthentication(ctx, req, "user-1", AuthenticationInfo{
		AuthTime: authTime,
		ACR:      "urn:example:mfa",
		AMR:      []string{"pwd", "otp"},
	})
	if err != nil {
		t.Fatalf("GenerateAuthCodeForAuthentication: %v", err)
	}

	resp, err := provider.Exchange(ctx, code, testClientID, testClientSecret, testRedirectURI, "verifier")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}

	if resp.Authentication.Nonce != "request-nonce" {
		t.Errorf("Nonce = %q, want the value from the authorization request",
			resp.Authentication.Nonce)
	}
	if !resp.Authentication.AuthTime.Equal(authTime) {
		t.Errorf("AuthTime = %v, want %v", resp.Authentication.AuthTime, authTime)
	}
	if resp.Authentication.ACR != "urn:example:mfa" {
		t.Errorf("ACR = %q", resp.Authentication.ACR)
	}
	if len(resp.Authentication.AMR) != 2 {
		t.Errorf("AMR = %v", resp.Authentication.AMR)
	}
}

// TestExchangeRefusesACodeWhoseAuthenticationWentStale.
//
// Codes live for ten minutes. A max_age of sixty seconds against an
// authentication that was fresh when the code was issued can be stale by the
// time it is redeemed, and the relying party would receive a token claiming an
// authentication age it explicitly refused.
func TestExchangeRefusesACodeWhoseAuthenticationWentStale(t *testing.T) {
	provider, store := newSecureProvider(t)
	ctx := context.Background()

	values := authorizeValues()
	values.Set("max_age", "60")
	req, err := provider.ParseAuthorizeRequest(ctx, values)
	if err != nil {
		t.Fatalf("ParseAuthorizeRequest: %v", err)
	}

	code, err := provider.GenerateAuthCodeForAuthentication(ctx, req, "user-1",
		AuthenticationInfo{AuthTime: time.Now()})
	if err != nil {
		t.Fatalf("GenerateAuthCodeForAuthentication: %v", err)
	}

	// Age the recorded authentication past the limit, as wall-clock time
	// would between issue and redemption.
	stored, err := store.GetAuthCode(ctx, code)
	if err != nil {
		t.Fatalf("GetAuthCode: %v", err)
	}
	stored.AuthTime = time.Now().Add(-10 * time.Minute)
	if err := store.SaveAuthCode(ctx, stored); err != nil {
		t.Fatalf("SaveAuthCode: %v", err)
	}

	resp, err := provider.Exchange(ctx, code, testClientID, testClientSecret, testRedirectURI, "verifier")
	if err == nil {
		t.Fatal("a token was issued against an authentication older than the requested max_age")
	}
	if resp != nil {
		t.Error("a token response was returned alongside the error")
	}
	var oerr *Error
	if !errors.As(err, &oerr) || oerr.Code != "invalid_grant" {
		t.Errorf("error = %v, want invalid_grant", err)
	}
}

// TestNoMaxAgeNeedsNoAuthTime keeps the requirement scoped. A request that
// asked nothing about authentication age must keep working for deployments
// that do not track it.
func TestNoMaxAgeNeedsNoAuthTime(t *testing.T) {
	provider, _ := newSecureProvider(t)
	ctx := context.Background()

	req, err := provider.ParseAuthorizeRequest(ctx, authorizeValues())
	if err != nil {
		t.Fatalf("ParseAuthorizeRequest: %v", err)
	}
	if _, err := provider.GenerateAuthCodeFor(ctx, req, "user-1"); err != nil {
		t.Fatalf("an ordinary request was refused for lacking an authentication time: %v", err)
	}
}
