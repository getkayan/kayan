package flow

import (
	"context"
	"testing"

	"github.com/getkayan/kayan/core/identity"
	"github.com/google/uuid"
)

func BenchmarkBcryptHash(b *testing.B) {
	hasher := NewBcryptHasher(10)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hasher.Hash("benchmark-password-123")
	}
}

func BenchmarkBcryptCompare(b *testing.B) {
	hasher := NewBcryptHasher(10)
	hashed, _ := hasher.Hash("benchmark-password-123")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hasher.Compare("benchmark-password-123", hashed)
	}
}

func BenchmarkRegistration(b *testing.B) {
	repo := &mockRepo{
		identities: make(map[string]any),
		creds:      make(map[string]*identity.Credential),
	}
	factory := func() any { return &identity.Identity{} }
	mgr := NewRegistrationManager(repo, factory)
	hasher := NewBcryptHasher(4) // Low cost for benchmark speed
	pwStrategy := NewPasswordStrategy(repo, hasher, "email", factory)
	pwStrategy.SetIDGenerator(func() any { return uuid.New() })
	mgr.RegisterStrategy(pwStrategy)

	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		traits := identity.JSON(`{"email": "bench@example.com"}`)
		mgr.Submit(ctx, "password", traits, "password123")
	}
}

func BenchmarkLogin(b *testing.B) {
	repo := &mockRepo{
		identities: make(map[string]any),
		creds:      make(map[string]*identity.Credential),
	}
	factory := func() any { return &identity.Identity{} }
	regMgr := NewRegistrationManager(repo, factory)
	logMgr := NewLoginManager(repo, factory)
	hasher := NewBcryptHasher(4) // Low cost for benchmark speed
	pwStrategy := NewPasswordStrategy(repo, hasher, "email", factory)
	pwStrategy.SetIDGenerator(func() any { return uuid.New() })
	regMgr.RegisterStrategy(pwStrategy)
	logMgr.RegisterStrategy(pwStrategy)

	ctx := context.Background()
	traits := identity.JSON(`{"email": "bench-login@example.com"}`)
	regMgr.Submit(ctx, "password", traits, "password123")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		logMgr.Authenticate(ctx, "password", "bench-login@example.com", "password123")
	}
}

func BenchmarkPasswordPolicyValidate(b *testing.B) {
	policy := PasswordPolicy{
		MinLength:        8,
		MaxLength:        128,
		RequireUppercase: true,
		RequireLowercase: true,
		RequireDigit:     true,
		RequireSpecial:   true,
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		policy.Validate("Str0ng!Pass")
	}
}
