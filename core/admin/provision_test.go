package admin

import (
	"context"
	"errors"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

type provisioningUserStore struct {
	created    *User
	credential *PasswordCredential
	roles      []string
	createOnly bool
}

func (*provisioningUserStore) List(context.Context, ListOptions) (*UserListResult, error) {
	return &UserListResult{}, nil
}
func (*provisioningUserStore) Get(context.Context, any) (*User, error) { return nil, ErrNotFound }
func (*provisioningUserStore) GetByEmail(context.Context, string) (*User, error) {
	return nil, ErrNotFound
}
func (s *provisioningUserStore) Create(_ context.Context, user *User) error {
	s.created = user
	s.createOnly = true
	return nil
}
func (*provisioningUserStore) Update(context.Context, *User) error               { return nil }
func (*provisioningUserStore) Delete(context.Context, any) error                 { return nil }
func (*provisioningUserStore) UpdateState(context.Context, any, UserState) error { return nil }
func (s *provisioningUserStore) Provision(_ context.Context, user *User, credential *PasswordCredential, roles []string) error {
	s.created = user
	s.credential = credential
	s.roles = append([]string(nil), roles...)
	return nil
}

type userStoreWithoutProvisioning struct{ provisioningUserStore }

// Hide Provision by forwarding only the base UserStore surface.
type baseUserStore struct{ inner *userStoreWithoutProvisioning }

func (s baseUserStore) List(ctx context.Context, opts ListOptions) (*UserListResult, error) {
	return s.inner.List(ctx, opts)
}
func (s baseUserStore) Get(ctx context.Context, id any) (*User, error) {
	return s.inner.Get(ctx, id)
}
func (s baseUserStore) GetByEmail(ctx context.Context, email string) (*User, error) {
	return s.inner.GetByEmail(ctx, email)
}
func (s baseUserStore) Create(ctx context.Context, user *User) error {
	return s.inner.Create(ctx, user)
}
func (s baseUserStore) Update(ctx context.Context, user *User) error {
	return s.inner.Update(ctx, user)
}
func (s baseUserStore) Delete(ctx context.Context, id any) error {
	return s.inner.Delete(ctx, id)
}
func (s baseUserStore) UpdateState(ctx context.Context, id any, state UserState) error {
	return s.inner.UpdateState(ctx, id, state)
}

func TestCreateUserProvisionsPasswordAndRolesAtomically(t *testing.T) {
	store := &provisioningUserStore{}
	manager := NewManager(WithUserStore(store), WithIDGenerator(func() any { return "user-1" }))

	user, err := manager.CreateUser(context.Background(), &Caller{IsSuperAdmin: true}, CreateUserInput{
		Email: "admin@example.test", Password: "correct horse battery staple", Roles: []string{"operator"},
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if user.ID != "user-1" || store.created != user {
		t.Fatalf("created user = %#v, want generated user", store.created)
	}
	if store.createOnly {
		t.Fatal("Create was called separately; password and roles were not atomic")
	}
	if store.credential == nil || store.credential.Identifier != "admin@example.test" {
		t.Fatalf("credential = %#v", store.credential)
	}
	if store.credential.SecretHash == "correct horse battery staple" {
		t.Fatal("store received the plaintext password")
	}
	if bcrypt.CompareHashAndPassword([]byte(store.credential.SecretHash), []byte("correct horse battery staple")) != nil {
		t.Fatal("stored password hash does not verify")
	}
	if len(store.roles) != 1 || store.roles[0] != "operator" {
		t.Fatalf("roles = %v", store.roles)
	}
}

func TestCreateUserRefusesToDropPasswordOrRoles(t *testing.T) {
	inner := &userStoreWithoutProvisioning{}
	manager := NewManager(WithUserStore(baseUserStore{inner: inner}))

	_, err := manager.CreateUser(context.Background(), &Caller{IsSuperAdmin: true}, CreateUserInput{
		Email: "admin@example.test", Password: "secret", Roles: []string{"operator"},
	})
	if !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("error = %v, want ErrNotConfigured", err)
	}
	if inner.created != nil {
		t.Fatal("user was partially created despite unsupported provisioning")
	}
}

func TestCreateUserWithoutCredentialUsesBaseStore(t *testing.T) {
	inner := &userStoreWithoutProvisioning{}
	manager := NewManager(WithUserStore(baseUserStore{inner: inner}))

	if _, err := manager.CreateUser(context.Background(), &Caller{IsSuperAdmin: true}, CreateUserInput{
		Email: "invited@example.test",
	}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if inner.created == nil || !inner.createOnly {
		t.Fatal("base Create was not used for a credential-free user")
	}
}
