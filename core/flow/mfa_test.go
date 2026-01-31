package flow

import (
	"context"
	"encoding/base32"
	"testing"
	"time"

	"github.com/getkayan/kayan/core/identity"
	"github.com/google/uuid"
)

func TestMFAFlow(t *testing.T) {
	// 1. Setup
	repo := &mockRepo{
		identities: make(map[string]any),
		creds:      make(map[string]*identity.Credential),
	}
	factory := func() any { return &identity.Identity{} }
	regMgr := NewRegistrationManager(repo, factory)
	logMgr := NewLoginManager(repo)
	logMgr.SetFactory(factory)

	pwStrategy := NewPasswordStrategy(repo, NewBcryptHasher(14), "email", factory)
	pwStrategy.SetIDGenerator(func() any { return uuid.New() })

	regMgr.RegisterStrategy(pwStrategy)
	logMgr.RegisterStrategy(pwStrategy)

	// 2. Register user
	traits := identity.JSON(`{"email": "mfa@example.com"}`)
	password := "securePass123"
	identRaw, err := regMgr.Submit(context.Background(), "password", traits, password)
	if err != nil {
		t.Fatalf("failed registration: %v", err)
	}
	ident := identRaw.(*identity.Identity)

	// 3. Enable MFA "Manually" (simulating an endpoint that updates the identity)
	// We need a valid base32 secret.
	// JBSWY3DPEHPK3PXP is "Hello!deadbeef" approx
	secret := "JBSWY3DPEHPK3PXP"
	ident.MFAEnabled = true
	ident.MFASecret = secret
	repo.UpdateIdentity(ident)

	// 4. Attempt Login - Should expect MFA Error
	res, err := logMgr.Authenticate(context.Background(), "password", "mfa@example.com", password)
	if err != ErrMFARequired {
		t.Errorf("Expected ErrMFARequired, got %v", err)
	}
	if res == nil {
		t.Error("Expected identity to be returned with error, got nil")
	}

	// 5. Generate Code
	// We use the same generation logic as the validater (TOTP logic)
	// In a real test we might just use the pquerna/otp library to generate the code
	// to ensure interoperability, but our internal strategy has a generator.
	strategy := &TOTPStrategy{}
	// Generate code for current time
	key, _ := base32Decode(secret) // Need helper or use internal
	code := strategy.generateCode(key, uint64(time.Now().Unix()/30))

	// 6. Verify Code
	ok, err := logMgr.VerifyMFA(context.Background(), ident, code)
	if err != nil {
		t.Errorf("VerifyMFA failed: %v", err)
	}
	if !ok {
		t.Error("VerifyMFA returned false")
	}

	// 7. Verify Invalid Code
	ok, _ = logMgr.VerifyMFA(context.Background(), ident, "000000")
	if ok {
		t.Error("VerifyMFA should fail with invalid code")
	}
}

func base32Decode(s string) ([]byte, error) {
	return base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s)
}
