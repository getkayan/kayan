package flow

import (
	"context"
	"testing"
	"time"

	"github.com/getkayan/kayan/core/domain"
	"github.com/getkayan/kayan/core/identity"
	"github.com/google/uuid"
)

type customIdentity struct {
	ID           string
	Email        string
	PasswordHash string
	Verified     bool
	VerifiedAt   *time.Time
	MFAEnabled   bool
	MFASecret    string
}

func (i *customIdentity) GetID() any { return i.ID }

func (i *customIdentity) SetID(id any) {
	i.ID = id.(uuid.UUID).String()
}

func (i *customIdentity) MFAConfig() (bool, string) {
	return i.MFAEnabled, i.MFASecret
}

func (i *customIdentity) IsVerified() bool {
	return i.Verified
}

func (i *customIdentity) MarkVerified(at time.Time) {
	i.Verified = true
	i.VerifiedAt = &at
}

func TestLoginSupportsBYOSIdentity(t *testing.T) {
	repo := &mockRepo{
		identities: make(map[string]any),
		creds:      make(map[string]*identity.Credential),
	}
	factory := func() any { return &customIdentity{} }

	regMgr := NewRegistrationManager(repo, factory)
	logMgr := NewLoginManager(repo, factory)

	pwStrategy := NewPasswordStrategy(repo, NewBcryptHasher(4), "", factory)
	pwStrategy.MapFields([]string{"Email"}, "PasswordHash")
	pwStrategy.SetIDGenerator(func() any { return uuid.New() })

	regMgr.RegisterStrategy(pwStrategy)
	logMgr.RegisterStrategy(pwStrategy)

	traits := identity.JSON(`{"Email":"byos@example.com"}`)
	password := "password123"

	identRaw, err := regMgr.Submit(context.Background(), "password", traits, password)
	if err != nil {
		t.Fatalf("failed to register custom identity: %v", err)
	}

	ident, ok := identRaw.(*customIdentity)
	if !ok {
		t.Fatalf("expected *customIdentity, got %T", identRaw)
	}

	loginRaw, err := logMgr.Authenticate(context.Background(), "password", "byos@example.com", password)
	if err != nil {
		t.Fatalf("failed to login custom identity: %v", err)
	}
	if _, ok := loginRaw.(*customIdentity); !ok {
		t.Fatalf("expected *customIdentity on login, got %T", loginRaw)
	}

	ident.MFAEnabled = true
	ident.MFASecret = "JBSWY3DPEHPK3PXP"
	if err := repo.UpdateIdentity(ident); err != nil {
		t.Fatalf("failed to update custom identity: %v", err)
	}

	res, err := logMgr.Authenticate(context.Background(), "password", "byos@example.com", password)
	if err != ErrMFARequired {
		t.Fatalf("expected ErrMFARequired, got %v", err)
	}
	if _, ok := res.(*customIdentity); !ok {
		t.Fatalf("expected *customIdentity during MFA challenge, got %T", res)
	}

	strategy := &TOTPStrategy{}
	key, err := base32Decode(ident.MFASecret)
	if err != nil {
		t.Fatalf("failed to decode TOTP secret: %v", err)
	}
	code := strategy.generateCode(key, uint64(time.Now().Unix()/30))

	valid, err := logMgr.VerifyMFA(context.Background(), ident, code)
	if err != nil {
		t.Fatalf("VerifyMFA failed: %v", err)
	}
	if !valid {
		t.Fatal("expected VerifyMFA to accept a valid code")
	}
}

func TestVerificationSupportsBYOSIdentity(t *testing.T) {
	repo := &mockRepo{
		identities: make(map[string]any),
		creds:      make(map[string]*identity.Credential),
	}
	tokenStore := &mockTokenStore{tokens: make(map[string]*domain.AuthToken)}

	ident := &customIdentity{ID: uuid.NewString(), Email: "verify@example.com"}
	if err := repo.CreateIdentity(ident); err != nil {
		t.Fatalf("failed to seed custom identity: %v", err)
	}

	manager := NewVerificationManager(repo, tokenStore, func() any { return &customIdentity{} })

	token, err := manager.Initiate(context.Background(), ident)
	if err != nil {
		t.Fatalf("failed to initiate verification: %v", err)
	}

	if err := manager.Verify(context.Background(), token.Token); err != nil {
		t.Fatalf("failed to verify identity: %v", err)
	}

	stored, err := repo.GetIdentity(func() any { return &customIdentity{} }, ident.ID)
	if err != nil {
		t.Fatalf("failed to reload custom identity: %v", err)
	}

	verified, ok := stored.(*customIdentity)
	if !ok {
		t.Fatalf("expected *customIdentity, got %T", stored)
	}
	if !verified.Verified || verified.VerifiedAt == nil {
		t.Fatal("expected custom identity to be marked verified")
	}
}
