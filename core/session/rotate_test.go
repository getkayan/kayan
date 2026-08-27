package session

import (
	"context"
	"testing"
	"time"
)

// TestRotateInvalidatesTheOldSession covers session fixation and the
// privilege-upgrade case that shares its shape.
//
// Create takes a caller-supplied session id and never invalidates anything, so
// nothing in the library ended the identifier a request arrived with. Two
// concrete failures follow.
//
// Fixation: an attacker who can plant a session identifier in a victim's
// browser -- a URL parameter, a cookie set on a shared subdomain -- and gets
// the victim to authenticate under it holds a live authenticated session,
// because the identifier the victim logged in with is the one the attacker
// chose.
//
// Privilege upgrade: a partial session issued after the first factor stays
// valid after the second one completes, so the pre-MFA token can be replayed
// against the step-up endpoint.
//
// Rotate is the operation both need: mint a new session, end the old one, and
// fail if the old one survives.
func TestRotateInvalidatesTheOldSession(t *testing.T) {
	store := NewMemoryRevocationStore()
	strategy := NewHS256Strategy(testSigningSecret, time.Hour).WithRevocationStore(store)
	manager := NewManager(strategy)
	ctx := context.Background()

	before, err := manager.Create(ctx, "pre-auth-session", "user-1")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	after, err := manager.Rotate(ctx, before.ID, "post-auth-session", "user-1")
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	if after.ID == before.ID {
		t.Fatal("Rotate reused the identifier it was asked to replace")
	}
	if _, err := manager.Validate(ctx, before.ID); err == nil {
		t.Error("the pre-rotation session still validates; an attacker who planted " +
			"that identifier keeps an authenticated session")
	}
	if _, err := manager.Validate(ctx, after.ID); err != nil {
		t.Errorf("the rotated session does not validate: %v", err)
	}
}

// TestRotateReportsAFailedRevocation keeps the failure loud. If the old
// session cannot be ended, the new one must not be handed out as though the
// rotation succeeded -- that is the fixation window staying open while the
// caller believes it closed.
func TestRotateReportsAFailedRevocation(t *testing.T) {
	// No revocation store, so JWTStrategy.Delete cannot end anything.
	manager := NewManager(NewHS256Strategy(testSigningSecret, time.Hour))
	ctx := context.Background()

	before, err := manager.Create(ctx, "pre-auth-session", "user-1")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if _, err := manager.Rotate(ctx, before.ID, "post-auth-session", "user-1"); err == nil {
		t.Error("Rotate reported success although the old session could not be revoked")
	}
}

// TestRotateFromNoPriorSession covers the ordinary login, where there is no
// pre-existing identifier to replace. Rotate must still mint the session
// rather than refuse.
func TestRotateFromNoPriorSession(t *testing.T) {
	store := NewMemoryRevocationStore()
	manager := NewManager(NewHS256Strategy(testSigningSecret, time.Hour).WithRevocationStore(store))
	ctx := context.Background()

	created, err := manager.Rotate(ctx, nil, "fresh-session", "user-1")
	if err != nil {
		t.Fatalf("Rotate with no prior session: %v", err)
	}
	if _, err := manager.Validate(ctx, created.ID); err != nil {
		t.Errorf("the new session does not validate: %v", err)
	}
}

// TestRotateIgnoresAnUnknownPriorSession keeps a stale or forged identifier
// from blocking a legitimate login. A session id the strategy does not
// recognise is already not a live session, so there is nothing to end.
func TestRotateIgnoresAnUnknownPriorSession(t *testing.T) {
	store := NewMemoryRevocationStore()
	manager := NewManager(NewHS256Strategy(testSigningSecret, time.Hour).WithRevocationStore(store))
	ctx := context.Background()

	created, err := manager.Rotate(ctx, "not-a-real-token", "fresh-session", "user-1")
	if err != nil {
		t.Fatalf("Rotate with an unrecognised prior session: %v", err)
	}
	if _, err := manager.Validate(ctx, created.ID); err != nil {
		t.Errorf("the new session does not validate: %v", err)
	}
}

// TestRotateNotifiesLogout keeps the notifiers consistent with Delete: a
// relying party that tracks sessions must learn the old one ended.
func TestRotateNotifiesLogout(t *testing.T) {
	store := NewMemoryRevocationStore()
	manager := NewManager(NewHS256Strategy(testSigningSecret, time.Hour).WithRevocationStore(store))
	notifier := &recordingNotifier{}
	manager.AddLogoutNotifier(notifier)
	ctx := context.Background()

	before, err := manager.Create(ctx, "pre-auth-session", "user-1")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := manager.Rotate(ctx, before.ID, "post-auth-session", "user-1"); err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	if len(notifier.identities) != 1 || notifier.identities[0] != "user-1" {
		t.Errorf("logout notifications = %v, want [user-1]", notifier.identities)
	}
}

type recordingNotifier struct {
	identities []string
}

func (n *recordingNotifier) NotifyLogout(_ string, identityID string) error {
	n.identities = append(n.identities, identityID)
	return nil
}
