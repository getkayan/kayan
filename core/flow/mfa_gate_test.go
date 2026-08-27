package flow

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/getkayan/kayan/core/audit"
	"github.com/getkayan/kayan/core/events"
	"github.com/getkayan/kayan/core/identity"
)

// enrolledLoginManager returns a manager whose only user has MFA enabled and a
// correct password, so Authenticate reaches the MFA gate.
func enrolledLoginManager(t *testing.T) (*LoginManager, string) {
	t.Helper()

	repo := &mockRepo{
		identities: make(map[string]any),
		creds:      make(map[string]*identity.Credential),
	}
	factory := func() any { return &identity.Identity{} }

	manager := NewLoginManager(repo, factory)
	hasher := NewBcryptHasher(4)
	strategy := NewPasswordStrategy(repo, hasher, "email", factory)
	manager.RegisterStrategy(strategy)

	const password = "correct-horse-battery-staple"
	hash, err := hasher.Hash(password)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}

	ident := &identity.Identity{ID: "user-1", MFAEnabled: true, MFASecret: "totp-secret"}
	ident.SetTraits(identity.JSON(`{"email": "mfa@example.test"}`))
	repo.identities["user-1"] = ident
	repo.creds["mfa@example.test:password"] = &identity.Credential{
		ID: "cred-1", IdentityID: "user-1", Type: "password",
		Identifier: "mfa@example.test", Secret: hash,
	}

	return manager, password
}

// TestMFARequiredReturnsNoIdentity covers an MFA bypass the API invited.
//
// Authenticate returned (ident, ErrMFARequired): a fully populated identity
// alongside a non-nil error. A caller writing the idiomatic `ident, err :=`
// and checking err is safe, but `ident, _ :=` -- or a check of `ident != nil`
// -- yielded a usable identity from which a session could be minted without
// the second factor ever being presented.
//
// The first factor succeeding is not authentication when a second is required,
// so there is nothing safe to hand back.
func TestMFARequiredReturnsNoIdentity(t *testing.T) {
	manager, password := enrolledLoginManager(t)

	ident, err := manager.Authenticate(context.Background(), "password", "mfa@example.test", password)
	if !errors.Is(err, ErrMFARequired) {
		t.Fatalf("error = %v, want ErrMFARequired", err)
	}
	if ident != nil {
		t.Errorf("Authenticate returned a usable identity (%T) alongside ErrMFARequired; "+
			"a caller ignoring the error can mint a session with no second factor", ident)
	}
}

// TestSuccessIsNotAuditedWhenAPostHookFails covers an audit trail that records
// a login which did not happen.
//
// The success audit record and the login-success domain event were emitted
// before the post-hooks ran. A post-hook returning an error makes Authenticate
// return a denial, but by then the audit store and every subscriber had
// already been told the login succeeded. The MFA path above returns before the
// success block and was always correct; this one was not.
func TestSuccessIsNotAuditedWhenAPostHookFails(t *testing.T) {
	repo := &mockRepo{
		identities: make(map[string]any),
		creds:      make(map[string]*identity.Credential),
	}
	factory := func() any { return &identity.Identity{} }

	sink := &recordingAuditStore{}
	manager := NewLoginManager(repo, factory,
		WithLoginAudit(sink, func(context.Context, error) {}))

	hasher := NewBcryptHasher(4)
	strategy := NewPasswordStrategy(repo, hasher, "email", factory)
	manager.RegisterStrategy(strategy)

	const password = "correct-horse-battery-staple"
	hash, err := hasher.Hash(password)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	ident := &identity.Identity{ID: "user-1"}
	ident.SetTraits(identity.JSON(`{"email": "hooked@example.test"}`))
	repo.identities["user-1"] = ident
	repo.creds["hooked@example.test:password"] = &identity.Credential{
		ID: "cred-1", IdentityID: "user-1", Type: "password",
		Identifier: "hooked@example.test", Secret: hash,
	}

	hookErr := errors.New("post-hook refused the login")
	manager.AddPostHook(func(context.Context, any) error { return hookErr })

	got, err := manager.Authenticate(context.Background(), "password", "hooked@example.test", password)
	if !errors.Is(err, hookErr) {
		t.Fatalf("error = %v, want the post-hook error", err)
	}
	if got != nil {
		t.Errorf("a denied login returned an identity (%T)", got)
	}

	for _, event := range sink.events() {
		if event.Type == string(events.TopicLoginSuccess) {
			t.Errorf("a login denied by a post-hook was audited as %q/%q",
				event.Type, event.Status)
		}
	}
}

// recordingAuditStore captures events so a test can assert what was written.
type recordingAuditStore struct {
	mu      sync.Mutex
	records []audit.AuditEvent
}

func (s *recordingAuditStore) SaveEvent(_ context.Context, event *audit.AuditEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records = append(s.records, *event)
	return nil
}

func (*recordingAuditStore) Query(context.Context, audit.Filter) ([]audit.AuditEvent, error) {
	return nil, nil
}
func (*recordingAuditStore) Count(context.Context, audit.Filter) (int64, error) { return 0, nil }
func (*recordingAuditStore) Export(context.Context, audit.Filter, audit.ExportFormat) (io.Reader, error) {
	return nil, nil
}
func (*recordingAuditStore) Purge(context.Context, time.Time) (int64, error) { return 0, nil }

func (s *recordingAuditStore) events() []audit.AuditEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]audit.AuditEvent, len(s.records))
	copy(out, s.records)
	return out
}
