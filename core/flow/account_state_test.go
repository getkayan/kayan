package flow

import (
	"context"
	"errors"
	"testing"

	"github.com/getkayan/kayan/core/identity"
)

func TestLockedIdentityCannotAuthenticateWithValidPassword(t *testing.T) {
	repo := &mockRepo{identities: map[string]any{}, creds: map[string]*identity.Credential{}}
	reg, login := PasswordAuth(repo, func() any { return &identity.Identity{} }, "email", WithHasherCost(4))
	ctx := context.Background()
	created, err := reg.Submit(ctx, "password", identity.JSON(`{"email":"locked@example.test"}`), "correct horse battery staple")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	user := created.(*identity.Identity)
	user.State = "locked"
	if err := repo.UpdateIdentity(ctx, user); err != nil {
		t.Fatalf("lock identity: %v", err)
	}

	got, err := login.Authenticate(ctx, "password", "locked@example.test", "correct horse battery staple")
	if !errors.Is(err, ErrAccountInactive) {
		t.Fatalf("error = %v, want ErrAccountInactive", err)
	}
	if got != nil {
		t.Fatalf("locked account returned identity %#v", got)
	}
}

func TestEmptyAndActiveIdentityStatesRemainAuthenticatable(t *testing.T) {
	for _, state := range []string{"", "active"} {
		t.Run("state="+state, func(t *testing.T) {
			repo := &mockRepo{identities: map[string]any{}, creds: map[string]*identity.Credential{}}
			reg, login := PasswordAuth(repo, func() any { return &identity.Identity{} }, "email", WithHasherCost(4))
			ctx := context.Background()
			created, err := reg.Submit(ctx, "password", identity.JSON(`{"email":"active@example.test"}`), "correct horse battery staple")
			if err != nil {
				t.Fatalf("register: %v", err)
			}
			user := created.(*identity.Identity)
			user.State = state
			if err := repo.UpdateIdentity(ctx, user); err != nil {
				t.Fatalf("set state: %v", err)
			}
			if _, err := login.Authenticate(ctx, "password", "active@example.test", "correct horse battery staple"); err != nil {
				t.Fatalf("Authenticate: %v", err)
			}
		})
	}
}
