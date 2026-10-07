package oauth2

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/getkayan/kayan/core/keys"
	"github.com/golang-jwt/jwt/v5"
)

// idTokenShaped signs claims the way oidc.Server.IssueIDToken does: same key
// provider, no typ header. Every claim Introspect reads is present.
func idTokenShaped(t *testing.T, kp keys.Provider, claims jwt.MapClaims) string {
	t.Helper()
	signed, err := keys.NewJWTSigner(kp).Sign(context.Background(), claims, nil)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signed
}

func liveClaims(issuer string) jwt.MapClaims {
	now := time.Now()
	return jwt.MapClaims{
		"iss":   issuer,
		"sub":   "alice",
		"aud":   testClientID,
		"exp":   now.Add(time.Hour).Unix(),
		"iat":   now.Unix(),
		"jti":   "id-token-jti",
		"nonce": "n-0S6_WzA2Mj",
	}
}

// TestIntrospectRefusesAnIDToken. Access tokens and ID tokens share signing
// keys and claims. Without the typ check any relying party holding a user's ID
// token could present it as a bearer token -- at UserInfo, or to any resource
// server that introspects -- and have it accepted as that user.
func TestIntrospectRefusesAnIDToken(t *testing.T) {
	kp, _, _ := newRotatingKeys(t)
	provider, _ := newSecureProvider(t, WithKeyProvider(kp))

	got, err := provider.Introspect(context.Background(), idTokenShaped(t, kp, liveClaims("https://issuer.example.test")))
	if err != nil {
		t.Fatalf("Introspect: %v", err)
	}
	if got.Active {
		t.Fatalf("an ID token introspected as an active access token (sub=%q)", got.Sub)
	}
}

func TestIntrospectAcceptsTheMediaTypeForm(t *testing.T) {
	kp, _, _ := newRotatingKeys(t)
	provider, _ := newSecureProvider(t, WithKeyProvider(kp))

	signed, err := keys.NewJWTSigner(kp).Sign(context.Background(), liveClaims("https://issuer.example.test"),
		map[string]any{"typ": "Application/AT+JWT"})
	if err != nil {
		t.Fatal(err)
	}
	got, err := provider.Introspect(context.Background(), signed)
	if err != nil || !got.Active {
		t.Fatalf("media-type typ refused: active=%v err=%v", got != nil && got.Active, err)
	}
}

// TestIntrospectRefusesAnotherIssuer. A deployment that shares a key set
// between providers must not have one accept the other's tokens.
func TestIntrospectRefusesAnotherIssuer(t *testing.T) {
	kp, _, _ := newRotatingKeys(t)
	provider, _ := newSecureProvider(t, WithKeyProvider(kp))

	signed, err := keys.NewJWTSigner(kp).Sign(context.Background(), liveClaims("https://other-issuer.example.test"),
		map[string]any{"typ": AccessTokenType})
	if err != nil {
		t.Fatal(err)
	}
	got, err := provider.Introspect(context.Background(), signed)
	if err != nil {
		t.Fatalf("Introspect: %v", err)
	}
	if got.Active {
		t.Fatal("a token from another issuer introspected as active")
	}
}

func TestIssuedAccessTokensCarryTheType(t *testing.T) {
	for name, opts := range map[string][]ProviderOption{
		"construction key": nil,
		"key provider":     {WithKeyProvider(func() keys.Provider { kp, _, _ := newRotatingKeys(t); return kp }())},
	} {
		provider, _ := newSecureProvider(t, opts...)
		token, err := provider.GenerateAccessToken(testClientID, "alice", []string{"openid"})
		if err != nil {
			t.Fatal(err)
		}
		parsed, _, err := jwt.NewParser().ParseUnverified(token, jwt.MapClaims{})
		if err != nil {
			t.Fatal(err)
		}
		if parsed.Header["typ"] != AccessTokenType {
			t.Errorf("%s: typ = %v, want %q", name, parsed.Header["typ"], AccessTokenType)
		}
		got, err := provider.Introspect(context.Background(), token)
		if err != nil || !got.Active {
			t.Errorf("%s: freshly issued token not active: err=%v", name, err)
		}
	}
}

type failingRevocationStore struct{}

func (failingRevocationStore) RevokeToken(context.Context, string, time.Time) error { return nil }
func (failingRevocationStore) IsRevoked(context.Context, string) (bool, error) {
	return false, errors.New("store unavailable")
}

// TestIntrospectFailsClosedWhenRevocationIsUnknown. Reading a store error as
// "not revoked" reactivates every revoked token for as long as the store is
// down.
func TestIntrospectFailsClosedWhenRevocationIsUnknown(t *testing.T) {
	provider, _ := newSecureProvider(t, WithRevocationStore(failingRevocationStore{}))
	token, err := provider.GenerateAccessToken(testClientID, "alice", []string{"openid"})
	if err != nil {
		t.Fatal(err)
	}

	got, err := provider.Introspect(context.Background(), token)
	if !errors.Is(err, ErrServerError) {
		t.Fatalf("err = %v, want server_error", err)
	}
	if got != nil && got.Active {
		t.Fatal("token reported active while its revocation status was unknown")
	}
}
