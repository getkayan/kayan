package session

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/getkayan/kayan/core/identity"
)

// TestJWTRevokeAllEndsEverySession covers what a password reset needs.
//
// Nothing could terminate a user's other sessions. domain.SessionStorage had
// no bulk operation, and JWT revocation was per-token, so a compromised
// account could not be recovered: the attacker's session survived the victim's
// password reset, which is the one action every user believes ends it.
//
// For JWTs the sessions cannot be enumerated -- they are bearer tokens the
// server never stored -- so revocation is an identity-level epoch. Anything
// issued before the cutoff stops verifying.
func TestJWTRevokeAllEndsEverySession(t *testing.T) {
	store := NewMemoryRevocationStore()
	strategy := NewHS256Strategy(testSigningSecret, time.Hour).WithRevocationStore(store)
	ctx := context.Background()

	var sessions []*identity.Session
	for _, id := range []string{"session-1", "session-2", "session-3"} {
		created, err := strategy.Create(ctx, id, "user-1")
		if err != nil {
			t.Fatalf("Create %s: %v", id, err)
		}
		sessions = append(sessions, created)
	}

	// A session belonging to somebody else must survive.
	other, err := strategy.Create(ctx, "session-other", "user-2")
	if err != nil {
		t.Fatalf("Create for user-2: %v", err)
	}

	if err := strategy.RevokeAll(ctx, "user-1"); err != nil {
		t.Fatalf("RevokeAll: %v", err)
	}

	for i, s := range sessions {
		if _, err := strategy.Validate(ctx, s.ID); err == nil {
			t.Errorf("session %d still validates after RevokeAll", i+1)
		}
		if _, err := strategy.Refresh(ctx, s.RefreshToken); err == nil {
			t.Errorf("session %d still refreshes after RevokeAll", i+1)
		}
	}

	if _, err := strategy.Validate(ctx, other.ID); err != nil {
		t.Errorf("RevokeAll ended another identity's session: %v", err)
	}
}

// TestJWTRevokeAllDoesNotBlockNewLogins keeps the epoch usable: revoking every
// current session must not lock the account out permanently.
//
// The cutoff is the start of the second in which RevokeAll ran, because "iat"
// is a whole number of seconds and cannot distinguish a token minted just
// before the call from one minted just after. Signing back in during that same
// second is therefore refused -- deliberately, since the alternative is leaving
// an attacker's session alive to avoid inconveniencing a retry. From the next
// second on, logging in works.
func TestJWTRevokeAllDoesNotBlockNewLogins(t *testing.T) {
	store := NewMemoryRevocationStore()
	strategy := NewHS256Strategy(testSigningSecret, time.Hour).WithRevocationStore(store)
	ctx := context.Background()

	if _, err := strategy.Create(ctx, "session-1", "user-1"); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := strategy.RevokeAll(ctx, "user-1"); err != nil {
		t.Fatalf("RevokeAll: %v", err)
	}

	// Cross the second boundary the cutoff sits on, which is what a real user
	// signing back in does many times over.
	time.Sleep(1100 * time.Millisecond)

	fresh, err := strategy.Create(ctx, "session-2", "user-1")
	if err != nil {
		t.Fatalf("Create after RevokeAll: %v", err)
	}
	if _, err := strategy.Validate(ctx, fresh.ID); err != nil {
		t.Errorf("a session created after the cutoff does not validate: %v", err)
	}
	if _, err := strategy.Refresh(ctx, fresh.RefreshToken); err != nil {
		t.Errorf("a session created after the cutoff cannot refresh: %v", err)
	}
}

// TestJWTRevokeAllCoversTheRevocationSecond pins the deliberate over-reach: a
// session minted in the same second as the revocation is ended. Losing this
// would silently reopen a window an attacker can hit by re-authenticating the
// instant a reset lands.
func TestJWTRevokeAllCoversTheRevocationSecond(t *testing.T) {
	store := NewMemoryRevocationStore()
	strategy := NewHS256Strategy(testSigningSecret, time.Hour).WithRevocationStore(store)
	ctx := context.Background()

	if err := strategy.RevokeAll(ctx, "user-1"); err != nil {
		t.Fatalf("RevokeAll: %v", err)
	}
	sameSecond, err := strategy.Create(ctx, "session-2", "user-1")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := strategy.Validate(ctx, sameSecond.ID); err == nil {
		t.Error("a session minted in the revocation second survived RevokeAll")
	}
}

// TestJWTRevokeAllRequiresAStore keeps the honesty rule from Delete: an
// operation that cannot be performed must say so rather than report success.
func TestJWTRevokeAllRequiresAStore(t *testing.T) {
	strategy := NewHS256Strategy(testSigningSecret, time.Hour)
	if err := strategy.RevokeAll(context.Background(), "user-1"); err == nil {
		t.Error("RevokeAll reported success with no revocation store configured")
	}
}

// TestDatabaseRevokeAllDeletesRows covers the stored-session strategy, where
// the sessions are enumerable and can simply be removed.
func TestDatabaseRevokeAllDeletesRows(t *testing.T) {
	repo := newFakeSessionRepo()
	strategy := NewDatabaseStrategy(repo)
	ctx := context.Background()

	for _, id := range []string{"s1", "s2"} {
		if _, err := strategy.Create(ctx, id, "user-1"); err != nil {
			t.Fatalf("Create %s: %v", id, err)
		}
	}
	if _, err := strategy.Create(ctx, "s3", "user-2"); err != nil {
		t.Fatalf("Create s3: %v", err)
	}

	if err := strategy.RevokeAll(ctx, "user-1"); err != nil {
		t.Fatalf("RevokeAll: %v", err)
	}

	for _, id := range []string{"s1", "s2"} {
		if _, err := strategy.Validate(ctx, id); err == nil {
			t.Errorf("session %s survived RevokeAll", id)
		}
	}
	if _, err := strategy.Validate(ctx, "s3"); err != nil {
		t.Errorf("RevokeAll removed another identity's session: %v", err)
	}
}

// fakeSessionRepo is an in-memory domain.SessionStorage with the bulk
// operation, so the strategy can be exercised without a database.
type fakeSessionRepo struct {
	sessions map[string]*identity.Session
}

func newFakeSessionRepo() *fakeSessionRepo {
	return &fakeSessionRepo{sessions: make(map[string]*identity.Session)}
}

func (r *fakeSessionRepo) CreateSession(_ context.Context, s *identity.Session) error {
	r.sessions[s.ID] = s
	return nil
}

func (r *fakeSessionRepo) GetSession(_ context.Context, id any) (*identity.Session, error) {
	s, ok := r.sessions[id.(string)]
	if !ok {
		return nil, errors.New("session not found")
	}
	return s, nil
}

func (r *fakeSessionRepo) GetSessionByRefreshToken(_ context.Context, token string) (*identity.Session, error) {
	for _, s := range r.sessions {
		if s.RefreshToken == token {
			return s, nil
		}
	}
	return nil, errors.New("session not found")
}

func (r *fakeSessionRepo) DeleteSession(_ context.Context, id any) error {
	delete(r.sessions, id.(string))
	return nil
}

func (r *fakeSessionRepo) DeleteSessionsByIdentity(_ context.Context, identityID any) error {
	want := identityID.(string)
	for id, s := range r.sessions {
		if s.IdentityID == want {
			delete(r.sessions, id)
		}
	}
	return nil
}

// Compile-time assertions that the shipped strategies expose RevokeAll with
// the shape core/flow's SessionRevoker expects. core/flow cannot import this
// package, so the two sides are pinned here.
var (
	_ interface {
		RevokeAll(ctx context.Context, identityID any) error
	} = (*JWTStrategy)(nil)
	_ interface {
		RevokeAll(ctx context.Context, identityID any) error
	} = (*DatabaseStrategy)(nil)
	_ IdentityRevocationStore = (*MemoryRevocationStore)(nil)
)
