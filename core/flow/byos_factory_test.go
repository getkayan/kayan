package flow

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/getkayan/kayan/core/domain"
	"github.com/getkayan/kayan/core/identity"
)

// factoryTestIdentity is a caller-defined identity type. BYOS means Kayan stores and
// loads this, not identity.Identity.
type factoryTestIdentity struct {
	ID     string
	Traits identity.JSON
}

func (c *factoryTestIdentity) GetID() any               { return c.ID }
func (c *factoryTestIdentity) GetTraits() identity.JSON { return c.Traits }

// factoryRecordingRepo records the factory each load was given. The shared
// mockRepo ignores the factory argument entirely, so it cannot distinguish a
// strategy that honours BYOS from one that hardcodes identity.Identity — which
// is why this bug survived.
type factoryRecordingRepo struct {
	*mockRepo
	loaded []any
}

func (r *factoryRecordingRepo) GetIdentity(ctx context.Context, factory func() any, id any) (any, error) {
	built := factory()
	r.loaded = append(r.loaded, built)
	return built, nil
}

// memTokenStore is the smallest TokenStore that satisfies these two strategies.
type memTokenStore struct {
	tokens map[string]*domain.AuthToken
}

func newMemTokenStore() *memTokenStore {
	return &memTokenStore{tokens: make(map[string]*domain.AuthToken)}
}

func (s *memTokenStore) SaveToken(ctx context.Context, t *domain.AuthToken) error {
	s.tokens[t.Token] = t
	return nil
}

func (s *memTokenStore) GetToken(ctx context.Context, token string) (*domain.AuthToken, error) {
	t, ok := s.tokens[token]
	if !ok {
		return nil, errors.New("token not found")
	}
	return t, nil
}

func (s *memTokenStore) ConsumeToken(ctx context.Context, token, tokenType string) (*domain.AuthToken, error) {
	t, ok := s.tokens[token]
	if !ok || t.Type != tokenType {
		return nil, errors.New("token not found")
	}
	delete(s.tokens, token)
	return t, nil
}

func (s *memTokenStore) DeleteToken(ctx context.Context, token string) error {
	delete(s.tokens, token)
	return nil
}

func (s *memTokenStore) DeleteExpiredTokens(ctx context.Context) error { return nil }

func newFactoryRecordingRepo() *factoryRecordingRepo {
	return &factoryRecordingRepo{
		mockRepo: &mockRepo{
			identities: make(map[string]any),
			creds:      make(map[string]*identity.Credential),
		},
	}
}

// TestMagicLinkHonoursTheIdentityFactory covers a BYOS violation: the strategy
// passed a hardcoded func() any { return &identity.Identity{} } to GetIdentity,
// so a caller with their own identity type either got a load failure or a type
// they could not use — on the authentication path, after the token had already
// been consumed.
func TestMagicLinkHonoursTheIdentityFactory(t *testing.T) {
	ctx := context.Background()
	repo := newFactoryRecordingRepo()
	store := newMemTokenStore()

	_ = store.SaveToken(ctx, &domain.AuthToken{
		Token:      "tok-1",
		IdentityID: "user-1",
		Type:       "magic_link",
		ExpiresAt:  time.Now().Add(time.Minute),
	})

	strategy := NewMagicLinkStrategy(repo, store,
		WithMagicLinkFactory(func() any { return &factoryTestIdentity{} }),
	)

	got, err := strategy.Authenticate(ctx, "", "tok-1")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if _, ok := got.(*factoryTestIdentity); !ok {
		t.Fatalf("got %T, want *factoryTestIdentity — the configured factory was ignored", got)
	}
}

// TestOTPHonoursTheIdentityFactory is the same defect in the OTP strategy.
func TestOTPHonoursTheIdentityFactory(t *testing.T) {
	ctx := context.Background()
	repo := newFactoryRecordingRepo()
	store := newMemTokenStore()

	_ = store.SaveToken(ctx, &domain.AuthToken{
		Token:      "123456",
		IdentityID: "user-1",
		Type:       "otp",
		ExpiresAt:  time.Now().Add(time.Minute),
	})

	strategy := NewOTPStrategy(repo, store, nil,
		WithOTPFactory(func() any { return &factoryTestIdentity{} }),
	)

	got, err := strategy.Authenticate(ctx, "", "123456")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if _, ok := got.(*factoryTestIdentity); !ok {
		t.Fatalf("got %T, want *factoryTestIdentity — the configured factory was ignored", got)
	}
}

// TestFactoryFallsBackToBuiltinIdentity pins the zero-configuration path, so
// callers who never pass a factory keep working.
func TestFactoryFallsBackToBuiltinIdentity(t *testing.T) {
	magic := NewMagicLinkStrategy(newFactoryRecordingRepo(), newMemTokenStore())
	if _, ok := magic.identityFactory()().(*identity.Identity); !ok {
		t.Error("magic link fallback did not produce *identity.Identity")
	}

	otp := NewOTPStrategy(newFactoryRecordingRepo(), newMemTokenStore(), nil)
	if _, ok := otp.identityFactory()().(*identity.Identity); !ok {
		t.Error("OTP fallback did not produce *identity.Identity")
	}
}
