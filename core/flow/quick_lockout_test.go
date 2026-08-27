package flow

import (
	"context"
	"testing"

	"github.com/getkayan/kayan/core/identity"
)

// TestPasswordAuthLocksOutByDefault covers an unthrottled login endpoint.
//
// PasswordAuth is the advertised one-line setup, and it registered the raw
// password strategy: no lockout, no rate limiting, and no QuickOption to add
// either. Following the documented happy path produced an endpoint that
// accepted unlimited password guesses.
//
// Brute-force protection is not a tuning knob to be discovered later. It is
// the default, and the options exist to adjust it.
func TestPasswordAuthLocksOutByDefault(t *testing.T) {
	repo := &mockRepo{
		identities: make(map[string]any),
		creds:      make(map[string]*identity.Credential),
	}
	factory := func() any { return &identity.Identity{} }

	reg, login := PasswordAuth(repo, factory, "email", WithHasherCost(4))

	const password = "correct-horse-battery-staple"
	traits := identity.JSON(`{"email": "victim@example.test"}`)
	if _, err := reg.Submit(context.Background(), "password", traits, password); err != nil {
		t.Fatalf("register: %v", err)
	}

	ctx := context.Background()
	var accepted int
	for i := 0; i < defaultQuickMaxFailures+3; i++ {
		if _, err := login.Authenticate(ctx, "password", "victim@example.test", "wrong-guess"); err == nil {
			accepted++
		}
	}
	if accepted > 0 {
		t.Fatalf("%d wrong passwords were accepted", accepted)
	}

	// Once locked, the correct password must be refused too. A lockout that
	// still admits the right password protects nothing: an attacker who
	// guesses it on attempt one thousand is in.
	if _, err := login.Authenticate(ctx, "password", "victim@example.test", password); err == nil {
		t.Error("the account accepted its password after exceeding the failure limit; " +
			"PasswordAuth registered an unthrottled strategy")
	}
}

// TestPasswordAuthLockoutIsTunable keeps the default from becoming a mandate.
func TestPasswordAuthLockoutIsTunable(t *testing.T) {
	repo := &mockRepo{
		identities: make(map[string]any),
		creds:      make(map[string]*identity.Credential),
	}
	factory := func() any { return &identity.Identity{} }

	reg, login := PasswordAuth(repo, factory, "email",
		WithHasherCost(4), WithLockout(LockoutConfig{MaxFailures: 2}))

	const password = "correct-horse-battery-staple"
	traits := identity.JSON(`{"email": "tuned@example.test"}`)
	if _, err := reg.Submit(context.Background(), "password", traits, password); err != nil {
		t.Fatalf("register: %v", err)
	}

	ctx := context.Background()
	for i := 0; i < 2; i++ {
		_, _ = login.Authenticate(ctx, "password", "tuned@example.test", "wrong-guess")
	}
	if _, err := login.Authenticate(ctx, "password", "tuned@example.test", password); err == nil {
		t.Error("a two-failure limit did not lock the account")
	}
}

// TestPasswordAuthLockoutCanBeDisabled keeps the escape hatch explicit. A
// caller who wraps the strategy themselves, or genuinely wants none, must be
// able to say so -- but has to say it.
func TestPasswordAuthLockoutCanBeDisabled(t *testing.T) {
	repo := &mockRepo{
		identities: make(map[string]any),
		creds:      make(map[string]*identity.Credential),
	}
	factory := func() any { return &identity.Identity{} }

	reg, login := PasswordAuth(repo, factory, "email",
		WithHasherCost(4), WithoutLockout())

	const password = "correct-horse-battery-staple"
	traits := identity.JSON(`{"email": "open@example.test"}`)
	if _, err := reg.Submit(context.Background(), "password", traits, password); err != nil {
		t.Fatalf("register: %v", err)
	}

	ctx := context.Background()
	for i := 0; i < defaultQuickMaxFailures+3; i++ {
		_, _ = login.Authenticate(ctx, "password", "open@example.test", "wrong-guess")
	}
	if _, err := login.Authenticate(ctx, "password", "open@example.test", password); err != nil {
		t.Errorf("lockout was disabled but the account still locked: %v", err)
	}
}
