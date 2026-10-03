package flow

import (
	"context"
	"encoding/base32"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/getkayan/kayan/core/identity"
	"github.com/google/uuid"
)

func TestMFAFlow(t *testing.T) {
	ctx := context.Background()
	// 1. Setup
	repo := &mockRepo{
		identities: make(map[string]any),
		creds:      make(map[string]*identity.Credential),
	}
	factory := func() any { return &identity.Identity{} }
	regMgr := NewRegistrationManager(repo, factory)
	logMgr := NewLoginManager(repo, factory, WithTOTPReplayGuard(newSpentSteps()))

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
	repo.UpdateIdentity(ctx, ident)

	// 4. Attempt Login - Should expect MFA Error
	res, err := logMgr.Authenticate(context.Background(), "password", "mfa@example.com", password)
	if !errors.Is(err, ErrMFARequired) {
		t.Errorf("Expected ErrMFARequired, got %v", err)
	}
	if res != nil {
		t.Errorf("Authenticate returned an identity alongside ErrMFARequired: %T", res)
	}
	// The pending identity travels on the error so it cannot be mistaken for
	// an authenticated one.
	pending, hasPending := MFAIdentityFrom(err)
	if !hasPending {
		t.Fatal("the MFA error carries no pending identity")
	}
	_ = pending

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

// spentSteps is a TOTPReplayGuard in memory: each identity's time steps, once.
type spentSteps struct {
	mu   sync.Mutex
	used map[string]bool
}

func newSpentSteps() *spentSteps { return &spentSteps{used: map[string]bool{}} }

func (g *spentSteps) MarkTOTPUsed(_ context.Context, identityID any, counter uint64) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	key := fmt.Sprintf("%v/%d", identityID, counter)
	if g.used[key] {
		return errors.New("time step already used")
	}
	g.used[key] = true
	return nil
}

// mfaIdent is the smallest identity VerifyMFA can be asked about.
type mfaIdent struct{ id, secret string }

func (i *mfaIdent) GetID() any                { return i.id }
func (i *mfaIdent) SetID(id any)              { i.id = fmt.Sprint(id) }
func (i *mfaIdent) MFAConfig() (bool, string) { return true, i.secret }

func currentCode(t *testing.T, secret string) string {
	t.Helper()
	key, err := base32Decode(secret)
	if err != nil {
		t.Fatal(err)
	}
	return (&TOTPStrategy{}).generateCode(key, uint64(time.Now().Unix()/30))
}

// A code accepted once is refused the second time: a second factor seen over
// a shoulder or through a phishing proxy must not be good for its whole
// 90-second window.
func TestVerifyMFARefusesAReplayedCode(t *testing.T) {
	ctx := context.Background()
	m := NewLoginManager(nil, nil, WithTOTPReplayGuard(newSpentSteps()))
	ident := &mfaIdent{id: "user-1", secret: "JBSWY3DPEHPK3PXP"}
	code := currentCode(t, ident.secret)

	ok, err := m.VerifyMFA(ctx, ident, code)
	if err != nil || !ok {
		t.Fatalf("first use: ok=%v err=%v; want accepted", ok, err)
	}
	ok, err = m.VerifyMFA(ctx, ident, code)
	if ok || !errors.Is(err, ErrTOTPReplay) {
		t.Fatalf("replay: ok=%v err=%v; want refused with ErrTOTPReplay", ok, err)
	}

	// Spent for that identity only: another identity with the same secret
	// and the same code is a different second factor.
	other := &mfaIdent{id: "user-2", secret: ident.secret}
	if ok, err := m.VerifyMFA(ctx, other, code); err != nil || !ok {
		t.Fatalf("another identity: ok=%v err=%v; want accepted", ok, err)
	}
}

// Without a replay guard VerifyMFA refuses, rather than verify a code it
// cannot stop being used again.
func TestVerifyMFANeedsAReplayGuard(t *testing.T) {
	m := NewLoginManager(nil, nil)
	ident := &mfaIdent{id: "user-1", secret: "JBSWY3DPEHPK3PXP"}
	ok, err := m.VerifyMFA(context.Background(), ident, currentCode(t, ident.secret))
	if ok || !errors.Is(err, ErrTOTPReplayGuardRequired) {
		t.Fatalf("ok=%v err=%v; want refused with ErrTOTPReplayGuardRequired", ok, err)
	}
}

// A wrong code is a plain no, and spends nothing.
func TestVerifyMFAWrongCodeSpendsNothing(t *testing.T) {
	guard := newSpentSteps()
	m := NewLoginManager(nil, nil, WithTOTPReplayGuard(guard))
	ident := &mfaIdent{id: "user-1", secret: "JBSWY3DPEHPK3PXP"}
	right := currentCode(t, ident.secret)
	wrong := "000000"
	if wrong == right {
		wrong = "111111"
	}
	ok, err := m.VerifyMFA(context.Background(), ident, wrong)
	if ok || err != nil {
		t.Fatalf("wrong code: ok=%v err=%v; want false, nil", ok, err)
	}
	if len(guard.used) != 0 {
		t.Fatalf("a wrong code spent %d time steps", len(guard.used))
	}
}
