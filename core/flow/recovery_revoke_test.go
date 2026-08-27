package flow

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/getkayan/kayan/core/domain"
	"github.com/getkayan/kayan/core/identity"
)

// recordingRevoker captures the identities whose sessions were ended.
type recordingRevoker struct {
	revoked []string
	err     error
}

func (r *recordingRevoker) RevokeAll(_ context.Context, identityID any) error {
	if r.err != nil {
		return r.err
	}
	r.revoked = append(r.revoked, identityID.(string))
	return nil
}

func newRecoveryFixture(t *testing.T) (*mockRepo, *mockTokenStore) {
	t.Helper()

	repo := &mockRepo{
		identities: make(map[string]any),
		creds:      make(map[string]*identity.Credential),
	}
	ident := &identity.Identity{ID: "user-1"}
	ident.SetTraits(identity.JSON(`{"email": "victim@example.test"}`))
	repo.identities["user-1"] = ident
	repo.creds["victim@example.test:password"] = &identity.Credential{
		ID: "cred-1", IdentityID: "user-1", Type: "password",
		Identifier: "victim@example.test", Secret: "old-hash",
	}

	store := &mockTokenStore{tokens: make(map[string]*domain.AuthToken)}
	_ = store.SaveToken(context.Background(), &domain.AuthToken{
		Token: "reset-token", IdentityID: "user-1", Type: "recovery",
		ExpiresAt: time.Now().Add(time.Hour),
	})
	return repo, store
}

// TestPasswordResetEndsOtherSessions is the reason bulk revocation exists.
//
// A password reset that leaves existing sessions alive does not recover a
// compromised account: the attacker holding a stolen session keeps it, and the
// victim believes the reset locked them out. Ending every session is the
// action users assume "reset your password" performs.
func TestPasswordResetEndsOtherSessions(t *testing.T) {
	repo, store := newRecoveryFixture(t)
	revoker := &recordingRevoker{}

	manager := NewRecoveryManager(repo, store, NewBcryptHasher(4),
		WithRecoverySessionRevoker(revoker))

	if err := manager.ResetPassword(context.Background(), "reset-token", "a-new-password"); err != nil {
		t.Fatalf("ResetPassword: %v", err)
	}

	if len(revoker.revoked) != 1 || revoker.revoked[0] != "user-1" {
		t.Errorf("sessions revoked for %v, want [user-1]; a reset left existing sessions alive",
			revoker.revoked)
	}
}

// TestPasswordResetReportsRevocationFailure keeps the failure loud.
//
// If the sessions cannot be ended, the reset has not achieved what the user
// asked for. Reporting success would tell somebody recovering a compromised
// account that they are safe while the attacker is still signed in.
func TestPasswordResetReportsRevocationFailure(t *testing.T) {
	repo, store := newRecoveryFixture(t)
	revokeErr := errors.New("revocation store unavailable")
	revoker := &recordingRevoker{err: revokeErr}

	manager := NewRecoveryManager(repo, store, NewBcryptHasher(4),
		WithRecoverySessionRevoker(revoker))

	err := manager.ResetPassword(context.Background(), "reset-token", "a-new-password")
	if err == nil {
		t.Fatal("ResetPassword reported success although the sessions were not revoked")
	}
	if !errors.Is(err, revokeErr) {
		t.Errorf("error = %v, want it to wrap the revocation failure", err)
	}
}

// TestPasswordResetWorksWithoutARevoker keeps revocation optional: a caller
// who has not wired a session layer still gets a working reset.
func TestPasswordResetWorksWithoutARevoker(t *testing.T) {
	repo, store := newRecoveryFixture(t)

	manager := NewRecoveryManager(repo, store, NewBcryptHasher(4))

	if err := manager.ResetPassword(context.Background(), "reset-token", "a-new-password"); err != nil {
		t.Fatalf("ResetPassword: %v", err)
	}
}
