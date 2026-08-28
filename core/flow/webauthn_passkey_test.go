package flow

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/getkayan/kayan/core/identity"
	"github.com/go-webauthn/webauthn/protocol"
)

// passkeyStrategy builds a strategy configured for discoverable credentials.
func passkeyStrategy(t *testing.T, hooks WebAuthnHooks) *WebAuthnStrategy {
	t.Helper()
	selection := PasskeyAuthenticatorSelection()
	strategy, err := NewWebAuthnStrategy(nil, WebAuthnConfig{
		RPDisplayName:          "Test App",
		RPID:                   "localhost",
		RPOrigins:              []string{"http://localhost:8080"},
		AuthenticatorSelection: &selection,
		Hooks:                  hooks,
	}, func() any { return &identity.Identity{} }, NewMemoryWebAuthnSessionStore())
	if err != nil {
		t.Fatalf("NewWebAuthnStrategy: %v", err)
	}
	return strategy
}

// TestDiscoverableLoginRefusesWithoutALoader is the fail-closed case.
//
// A discoverable ceremony carries no identifier, so there is nothing to fall
// back to. The only other shape available -- trusting whichever credential the
// assertion happens to name -- authenticates whoever presents one.
func TestDiscoverableLoginRefusesWithoutALoader(t *testing.T) {
	strategy := passkeyStrategy(t, WebAuthnHooks{})

	options, sessionID, err := strategy.BeginDiscoverableLogin(context.Background())
	if err == nil {
		t.Fatal("a discoverable ceremony started with no way to resolve the user handle")
	}
	if options != nil || sessionID != "" {
		t.Error("a ceremony was returned alongside the error")
	}
	if !errors.Is(err, ErrNoDiscoverableUserLoader) {
		t.Errorf("error = %v, want ErrNoDiscoverableUserLoader", err)
	}
}

// TestDiscoverableCeremonyIsUsernameless. The whole point is that the
// assertion request names no credentials: the authenticator picks one and says
// which user it belongs to. An allowCredentials list would defeat that, since
// building one needs a username.
func TestDiscoverableCeremonyIsUsernameless(t *testing.T) {
	strategy := passkeyStrategy(t, WebAuthnHooks{
		DiscoverableUserLoader: func(context.Context, []byte, []byte) (any, error) { return nil, nil },
	})

	options, sessionID, err := strategy.BeginDiscoverableLogin(context.Background())
	if err != nil {
		t.Fatalf("BeginDiscoverableLogin: %v", err)
	}
	if sessionID == "" {
		t.Fatal("no session id was returned")
	}
	if len(options.Response.AllowedCredentials) != 0 {
		t.Errorf("the ceremony named %d allowed credentials; a usernameless "+
			"request cannot know any", len(options.Response.AllowedCredentials))
	}

	stored, err := strategy.sessionStore.GetSession(context.Background(), sessionID)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if !stored.Discoverable {
		t.Error("the session is not marked discoverable, so the finish path cannot " +
			"tell it apart from an identifier-based one")
	}
	// The library refuses to validate a discoverable assertion against a
	// session that names a user, and an empty UserID is what marks it.
	if len(stored.UserID) != 0 {
		t.Errorf("UserID = %q, want it empty for a discoverable session", stored.UserID)
	}
}

// TestDiscoverableLoginRequiresUserVerification.
//
// A usernameless sign-in without user verification proves possession of an
// authenticator and nothing about who is holding it -- one factor, when the
// reason to adopt passkeys is that they are two.
func TestDiscoverableLoginRequiresUserVerification(t *testing.T) {
	strategy := passkeyStrategy(t, WebAuthnHooks{
		DiscoverableUserLoader: func(context.Context, []byte, []byte) (any, error) { return nil, nil },
	})

	options, sessionID, err := strategy.BeginDiscoverableLogin(context.Background())
	if err != nil {
		t.Fatalf("BeginDiscoverableLogin: %v", err)
	}
	if options.Response.UserVerification != protocol.VerificationRequired {
		t.Errorf("UserVerification = %q, want %q",
			options.Response.UserVerification, protocol.VerificationRequired)
	}

	stored, err := strategy.sessionStore.GetSession(context.Background(), sessionID)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	// The stored value is what the finish path enforces. A ceremony that asked
	// for verification but recorded "preferred" would accept an assertion
	// without it.
	if stored.UserVerification != string(protocol.VerificationRequired) {
		t.Errorf("stored UserVerification = %q, want %q",
			stored.UserVerification, protocol.VerificationRequired)
	}
}

// TestDiscoverableUserVerificationIsOverridable keeps the default from being a
// mandate, which the library's second rule forbids.
func TestDiscoverableUserVerificationIsOverridable(t *testing.T) {
	selection := PasskeyAuthenticatorSelection()
	strategy, err := NewWebAuthnStrategy(nil, WebAuthnConfig{
		RPDisplayName:                "Test App",
		RPID:                         "localhost",
		RPOrigins:                    []string{"http://localhost:8080"},
		AuthenticatorSelection:       &selection,
		DiscoverableUserVerification: protocol.VerificationPreferred,
		Hooks: WebAuthnHooks{
			DiscoverableUserLoader: func(context.Context, []byte, []byte) (any, error) { return nil, nil },
		},
	}, func() any { return &identity.Identity{} }, NewMemoryWebAuthnSessionStore())
	if err != nil {
		t.Fatalf("NewWebAuthnStrategy: %v", err)
	}

	options, _, err := strategy.BeginDiscoverableLogin(context.Background())
	if err != nil {
		t.Fatalf("BeginDiscoverableLogin: %v", err)
	}
	if options.Response.UserVerification != protocol.VerificationPreferred {
		t.Errorf("UserVerification = %q, want the configured override",
			options.Response.UserVerification)
	}
}

// TestIdentifierSessionCannotFinishAsDiscoverable is the central test.
//
// An identifier-based session names a user and constrains which credentials
// the assertion may use. Finishing it through the discoverable path discards
// both, so the assertion nominates its own subject: present any credential
// with any user handle and the ceremony resolves whoever that handle names.
func TestIdentifierSessionCannotFinishAsDiscoverable(t *testing.T) {
	strategy := passkeyStrategy(t, WebAuthnHooks{
		DiscoverableUserLoader: func(context.Context, []byte, []byte) (any, error) {
			t.Error("the loader was consulted for a session that was not discoverable")
			return nil, nil
		},
	})
	ctx := context.Background()

	// A session as the identifier-based ceremony would have written it.
	if err := strategy.sessionStore.SaveSession(ctx, "session-1", &WebAuthnSessionData{
		Challenge:        "challenge",
		UserID:           []byte("victim"),
		AllowedCredIDs:   [][]byte{[]byte("victim-credential")},
		UserVerification: string(protocol.VerificationRequired),
		ExpiresAt:        strategy.clock.Now().Add(time.Minute),
	}); err != nil {
		t.Fatalf("SaveSession: %v", err)
	}

	_, err := strategy.FinishDiscoverableLogin(ctx, "session-1",
		&protocol.ParsedCredentialAssertionData{})
	if err == nil {
		t.Fatal("an identifier-based session was completed as a discoverable login")
	}
	if !strings.Contains(err.Error(), "not begun as a discoverable login") {
		t.Errorf("error = %v, want it to name the session-kind mismatch", err)
	}
}

// TestDiscoverableSessionIsSingleUse. The challenge is a nonce; leaving it live
// after a failed attempt makes it retryable, which is the one property it has.
func TestDiscoverableSessionIsSingleUse(t *testing.T) {
	strategy := passkeyStrategy(t, WebAuthnHooks{
		DiscoverableUserLoader: func(context.Context, []byte, []byte) (any, error) { return nil, nil },
	})
	ctx := context.Background()

	_, sessionID, err := strategy.BeginDiscoverableLogin(ctx)
	if err != nil {
		t.Fatalf("BeginDiscoverableLogin: %v", err)
	}

	// Fails, because the assertion is empty. The session must be gone anyway.
	_, _ = strategy.FinishDiscoverableLogin(ctx, sessionID, &protocol.ParsedCredentialAssertionData{})

	if _, err := strategy.sessionStore.GetSession(ctx, sessionID); err == nil {
		t.Error("the challenge survived a failed attempt and can be retried")
	}
}

// TestPasskeySelectionAsksForBothHalves.
//
// Without a resident key the credential cannot be found without a username, so
// there is no usernameless sign-in. Without user verification the ceremony is
// one factor. A helper that supplied only one of them would produce something
// that looks like a passkey and is not.
func TestPasskeySelectionAsksForBothHalves(t *testing.T) {
	selection := PasskeyAuthenticatorSelection()

	if selection.ResidentKey != protocol.ResidentKeyRequirementRequired {
		t.Errorf("ResidentKey = %q, want required", selection.ResidentKey)
	}
	if selection.RequireResidentKey == nil || !*selection.RequireResidentKey {
		t.Error("RequireResidentKey is not set; older authenticators read that field, " +
			"not ResidentKey, and would create a non-discoverable credential")
	}
	if selection.UserVerification != protocol.VerificationRequired {
		t.Errorf("UserVerification = %q, want required", selection.UserVerification)
	}
}

// TestUserHandleMismatchIsRefused is the central security test for passkeys.
//
// The user handle is the only thing naming a subject in a discoverable
// ceremony. A loader that returns some other identity -- from a stale index,
// or a lookup keyed on the credential id alone after that credential was
// reassigned -- would authenticate the wrong person, and the signature would
// verify perfectly because it is a real signature over a real challenge from a
// real authenticator. Nothing else in the ceremony compares the two.
func TestUserHandleMismatchIsRefused(t *testing.T) {
	attacker := &identity.Identity{ID: "attacker"}
	strategy := passkeyStrategy(t, WebAuthnHooks{
		DiscoverableUserLoader: func(context.Context, []byte, []byte) (any, error) {
			return attacker, nil
		},
	})

	var resolved any
	handler := strategy.discoverableUserHandler(context.Background(),
		strategy.getHooks().DiscoverableUserLoader, &resolved)

	user, err := handler([]byte("credential-id"), []byte("victim"))
	if err == nil {
		t.Fatal("a loader returning a different identity than the asserted handle was accepted")
	}
	if user != nil {
		t.Error("a user was returned alongside the error")
	}
	if resolved != nil {
		t.Error("the mismatched identity was recorded as resolved")
	}
	if !errors.Is(err, ErrUserHandleMismatch) {
		t.Errorf("error = %v, want ErrUserHandleMismatch", err)
	}
}

// TestMatchingUserHandleResolves keeps the check from being a blanket refusal.
func TestMatchingUserHandleResolves(t *testing.T) {
	owner := &identity.Identity{ID: "alice"}
	strategy := passkeyStrategy(t, WebAuthnHooks{
		DiscoverableUserLoader: func(context.Context, []byte, []byte) (any, error) {
			return owner, nil
		},
	})

	var resolved any
	handler := strategy.discoverableUserHandler(context.Background(),
		strategy.getHooks().DiscoverableUserLoader, &resolved)

	user, err := handler([]byte("credential-id"), []byte("alice"))
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if user == nil {
		t.Fatal("no user was returned for a matching handle")
	}
	if resolved != any(owner) {
		t.Error("the resolved identity is not the one the loader returned")
	}
}

// TestUnknownHandleIsRefused. A loader reporting a miss as (nil, nil) is an
// easy thing to write, and dereferencing it would panic inside a ceremony
// reachable by anyone who can reach the login endpoint.
func TestUnknownHandleIsRefused(t *testing.T) {
	strategy := passkeyStrategy(t, WebAuthnHooks{
		DiscoverableUserLoader: func(context.Context, []byte, []byte) (any, error) {
			return nil, nil
		},
	})

	var resolved any
	handler := strategy.discoverableUserHandler(context.Background(),
		strategy.getHooks().DiscoverableUserLoader, &resolved)

	if _, err := handler([]byte("credential-id"), []byte("nobody")); !errors.Is(err, ErrUnknownDiscoverableCredential) {
		t.Errorf("error = %v, want ErrUnknownDiscoverableCredential", err)
	}
}
