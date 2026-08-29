package flow

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/getkayan/kayan/core/identity"
	"github.com/getkayan/kayan/core/session"
	"github.com/golang-jwt/jwt/v5"
)

// The most ordinary thing an application built on this library does: register
// a user, sign them in, hold a session, use it, refresh it, and sign out.
//
// Nothing tested that. core/flow's tests stop at Authenticate returning an
// identity and core/session's start at Create being handed one, so the handoff
// between them -- the point where a login becomes a session -- was never
// crossed by a test. A caller wiring the two together for the first time was
// the first thing exercising it.

const (
	e2eEmail    = "ada@example.test"
	e2ePassword = "correct-horse-battery-staple"
)

// newSessionE2E returns a login manager, a registration manager, and a session
// strategy wired the way an application wires them.
func newSessionE2E(t *testing.T) (*RegistrationManager, *LoginManager, *session.JWTStrategy) {
	t.Helper()

	repo := &mockRepo{
		identities: map[string]any{},
		creds:      map[string]*identity.Credential{},
	}
	factory := func() any { return &identity.Identity{} }
	hasher := NewBcryptHasher(4)

	registration := NewRegistrationManager(repo, factory)
	registration.RegisterStrategy(NewPasswordStrategy(repo, hasher, "email", factory))

	login := NewLoginManager(repo, factory)
	login.RegisterStrategy(NewPasswordStrategy(repo, hasher, "email", factory))

	sessions := session.NewJWTStrategy(session.JWTConfig{
		SigningMethod:        jwt.SigningMethodHS256,
		SigningKey:           []byte("a-signing-key-of-sufficient-length-for-hs256"),
		VerifyingKey:         []byte("a-signing-key-of-sufficient-length-for-hs256"),
		Expiry:               time.Hour,
		RefreshSigningMethod: jwt.SigningMethodHS256,
		RefreshSigningKey:    []byte("a-different-refresh-key-of-sufficient-length"),
		RefreshVerifyingKey:  []byte("a-different-refresh-key-of-sufficient-length"),
		RefreshExpiry:        24 * time.Hour,
	})
	sessions.WithRevocationStore(session.NewMemoryRevocationStore())

	return registration, login, sessions
}

// TestPasswordSignInToSessionEndToEnd walks register, sign in, hold a session,
// use it, refresh it, and sign out.
func TestPasswordSignInToSessionEndToEnd(t *testing.T) {
	registration, login, sessions := newSessionE2E(t)
	ctx := context.Background()

	// 1. Register.
	traits := identity.JSON(`{"email":"` + e2eEmail + `"}`)
	created, err := registration.Submit(ctx, "password", traits, e2ePassword)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	registered, ok := created.(FlowIdentity)
	if !ok {
		t.Fatalf("registration returned %T, which is not a FlowIdentity", created)
	}

	// 2. Sign in with the password just set. This is the seam: registration
	//    hashed a credential, and authentication has to find and verify it.
	authenticated, err := login.Authenticate(ctx, "password", e2eEmail, e2ePassword)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	signedIn, ok := authenticated.(FlowIdentity)
	if !ok {
		t.Fatalf("authentication returned %T", authenticated)
	}
	if signedIn.GetID() != registered.GetID() {
		t.Fatalf("signed in as %v, registered %v", signedIn.GetID(), registered.GetID())
	}

	// 3. Turn the login into a session.
	created2, err := sessions.Create(ctx, "session-1", signedIn.GetID())
	if err != nil {
		t.Fatalf("Create session: %v", err)
	}
	if created2.ID == "" || created2.RefreshToken == "" {
		t.Fatal("session created without both tokens")
	}

	// 4. The access token validates and names the same subject. A session that
	//    validated to a different identity than signed in is the worst
	//    available outcome for this handoff.
	validated, err := sessions.Validate(ctx, created2.ID)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if validated.IdentityID != signedIn.GetID() {
		t.Errorf("session identity = %v, want %v", validated.IdentityID, signedIn.GetID())
	}

	// 5. Refresh rotates.
	refreshed, err := sessions.Refresh(ctx, created2.RefreshToken)
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if refreshed.ID == created2.ID {
		t.Error("refresh returned the same access token")
	}
	if _, err := sessions.Validate(ctx, refreshed.ID); err != nil {
		t.Errorf("the refreshed token does not validate: %v", err)
	}

	// 6. Sign out. The point of a logout is that the token stops working;
	//    without a revocation store this reported success and the token stayed
	//    valid, which is the failure this step exists to catch.
	if err := sessions.Delete(ctx, refreshed.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := sessions.Validate(ctx, refreshed.ID); err == nil {
		t.Error("the session validated after logout")
	}
}

// TestWrongPasswordNeverReachesASession. The obvious failure to guard: a
// rejected login must not produce an identity a caller could hand to Create.
func TestWrongPasswordNeverReachesASession(t *testing.T) {
	registration, login, _ := newSessionE2E(t)
	ctx := context.Background()

	if _, err := registration.Submit(ctx, "password",
		identity.JSON(`{"email":"`+e2eEmail+`"}`), e2ePassword); err != nil {
		t.Fatalf("Submit: %v", err)
	}

	ident, err := login.Authenticate(ctx, "password", e2eEmail, "not-the-password")
	if err == nil {
		t.Fatal("a wrong password authenticated")
	}
	if ident != nil {
		t.Error("an identity was returned alongside the error; a caller reading only " +
			"the identity would mint a session for it")
	}
}

// TestUnknownUserIsRejectedLikeAWrongPassword. The two must be
// indistinguishable to the caller, or the login endpoint enumerates accounts.
func TestUnknownUserIsRejectedLikeAWrongPassword(t *testing.T) {
	registration, login, _ := newSessionE2E(t)
	ctx := context.Background()

	if _, err := registration.Submit(ctx, "password",
		identity.JSON(`{"email":"`+e2eEmail+`"}`), e2ePassword); err != nil {
		t.Fatalf("Submit: %v", err)
	}

	_, wrongPassword := login.Authenticate(ctx, "password", e2eEmail, "not-the-password")
	_, noSuchUser := login.Authenticate(ctx, "password", "nobody@example.test", e2ePassword)

	if wrongPassword == nil || noSuchUser == nil {
		t.Fatal("one of the two bad logins succeeded")
	}
	if wrongPassword.Error() != noSuchUser.Error() {
		t.Errorf("a wrong password reports %q and an unknown user reports %q; the "+
			"difference tells an attacker which addresses have accounts",
			wrongPassword, noSuchUser)
	}
}

// TestSessionTokenIsNotTheRefreshToken. They are separate credentials with
// separate lifetimes; presenting one where the other belongs must fail.
func TestSessionTokenIsNotTheRefreshToken(t *testing.T) {
	_, _, sessions := newSessionE2E(t)
	ctx := context.Background()

	created, err := sessions.Create(ctx, "session-1", "user-1")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if _, err := sessions.Validate(ctx, created.RefreshToken); err == nil {
		t.Error("a refresh token was accepted as an access token")
	}
	if _, err := sessions.Refresh(ctx, created.ID); err == nil {
		t.Error("an access token was accepted as a refresh token")
	}
	if strings.TrimSpace(created.ID) == strings.TrimSpace(created.RefreshToken) {
		t.Error("the two tokens are identical")
	}
}
