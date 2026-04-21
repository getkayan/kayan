package mfa

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// --- Mock MFA Method ---

type mockMethod struct {
	id           string
	enrollConfig any
	verifyResult bool
}

func (m *mockMethod) ID() string { return m.id }

func (m *mockMethod) Enroll(ctx context.Context, identityID string) (*Enrollment, error) {
	return &Enrollment{
		ID:         uuid.New().String(),
		IdentityID: identityID,
		MethodID:   m.id,
		Status:     EnrollmentPending,
		Config:     m.enrollConfig,
		CreatedAt:  time.Now(),
	}, nil
}

func (m *mockMethod) Challenge(ctx context.Context, enrollment *Enrollment) (*Challenge, error) {
	return &Challenge{
		ID:           uuid.New().String(),
		EnrollmentID: enrollment.ID,
		MethodID:     m.id,
		ExpiresAt:    time.Now().Add(5 * time.Minute),
		Metadata:     map[string]string{"hint": "mock challenge"},
	}, nil
}

func (m *mockMethod) Verify(ctx context.Context, enrollment *Enrollment, challenge *Challenge, response string) (bool, error) {
	return m.verifyResult, nil
}

// --- Tests ---

func TestMFAManager_Enroll(t *testing.T) {
	store := NewMemoryStore()
	mgr := NewManager(store)
	mgr.RegisterMethod(&mockMethod{id: "totp", enrollConfig: "otpauth://totp/test", verifyResult: true})

	enrollment, err := mgr.Enroll(context.Background(), "user-1", "totp")
	if err != nil {
		t.Fatalf("enrollment failed: %v", err)
	}
	if enrollment.Status != EnrollmentPending {
		t.Errorf("expected pending status, got %q", enrollment.Status)
	}
	if enrollment.IdentityID != "user-1" {
		t.Errorf("expected identity 'user-1', got %q", enrollment.IdentityID)
	}
	if enrollment.MethodID != "totp" {
		t.Errorf("expected method 'totp', got %q", enrollment.MethodID)
	}
}

func TestMFAManager_Enroll_UnknownMethod(t *testing.T) {
	store := NewMemoryStore()
	mgr := NewManager(store)

	_, err := mgr.Enroll(context.Background(), "user-1", "unknown")
	if err == nil {
		t.Fatal("expected error for unknown method")
	}
}

func TestMFAManager_Enroll_MaxEnrollments(t *testing.T) {
	store := NewMemoryStore()
	mgr := NewManager(store, WithMaxEnrollments(1))
	mgr.RegisterMethod(&mockMethod{id: "totp", verifyResult: true})
	mgr.RegisterMethod(&mockMethod{id: "sms", verifyResult: true})

	_, err := mgr.Enroll(context.Background(), "user-1", "totp")
	if err != nil {
		t.Fatalf("first enrollment failed: %v", err)
	}

	_, err = mgr.Enroll(context.Background(), "user-1", "sms")
	if err == nil {
		t.Fatal("expected error for exceeding max enrollments")
	}
}

func TestMFAManager_ConfirmEnrollment(t *testing.T) {
	store := NewMemoryStore()
	mgr := NewManager(store)
	mgr.RegisterMethod(&mockMethod{id: "totp", verifyResult: true})

	enrollment, _ := mgr.Enroll(context.Background(), "user-1", "totp")

	err := mgr.ConfirmEnrollment(context.Background(), enrollment.ID, "123456")
	if err != nil {
		t.Fatalf("confirm failed: %v", err)
	}

	// Verify enrollment is now active
	updated, _ := store.GetEnrollment(context.Background(), enrollment.ID)
	if updated.Status != EnrollmentActive {
		t.Errorf("expected active status, got %q", updated.Status)
	}
}

func TestMFAManager_ConfirmEnrollment_InvalidCode(t *testing.T) {
	store := NewMemoryStore()
	mgr := NewManager(store)
	mgr.RegisterMethod(&mockMethod{id: "totp", verifyResult: false})

	enrollment, _ := mgr.Enroll(context.Background(), "user-1", "totp")

	err := mgr.ConfirmEnrollment(context.Background(), enrollment.ID, "wrong")
	if err == nil {
		t.Fatal("expected error for invalid code")
	}
}

func TestMFAManager_ChallengeAndVerify(t *testing.T) {
	store := NewMemoryStore()
	mgr := NewManager(store)
	mgr.RegisterMethod(&mockMethod{id: "totp", verifyResult: true})
	ctx := context.Background()

	// Enroll and confirm
	enrollment, _ := mgr.Enroll(ctx, "user-1", "totp")
	mgr.ConfirmEnrollment(ctx, enrollment.ID, "123456")

	// Challenge
	challenge, err := mgr.Challenge(ctx, "user-1")
	if err != nil {
		t.Fatalf("challenge failed: %v", err)
	}
	if challenge.MethodID != "totp" {
		t.Errorf("expected method 'totp', got %q", challenge.MethodID)
	}

	// Verify
	ok, err := mgr.Verify(ctx, challenge.ID, "654321")
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if !ok {
		t.Error("expected verification to succeed")
	}

	// Challenge should be consumed (replay should fail)
	_, err = mgr.Verify(ctx, challenge.ID, "654321")
	if err == nil {
		t.Fatal("expected error for replayed challenge")
	}
}

func TestMFAManager_Challenge_NoEnrollment(t *testing.T) {
	store := NewMemoryStore()
	mgr := NewManager(store)

	_, err := mgr.Challenge(context.Background(), "user-no-mfa")
	if err == nil {
		t.Fatal("expected error for no enrollment")
	}
}

func TestMFAManager_DisableMethod(t *testing.T) {
	store := NewMemoryStore()
	mgr := NewManager(store)
	mgr.RegisterMethod(&mockMethod{id: "totp", verifyResult: true})
	ctx := context.Background()

	enrollment, _ := mgr.Enroll(ctx, "user-1", "totp")
	mgr.ConfirmEnrollment(ctx, enrollment.ID, "123456")

	err := mgr.DisableMethod(ctx, enrollment.ID)
	if err != nil {
		t.Fatalf("disable failed: %v", err)
	}

	updated, _ := store.GetEnrollment(ctx, enrollment.ID)
	if updated.Status != EnrollmentDisabled {
		t.Errorf("expected disabled status, got %q", updated.Status)
	}
}

func TestMFAManager_RecoveryCodes(t *testing.T) {
	store := NewMemoryStore()
	mgr := NewManager(store)
	ctx := context.Background()

	// Generate codes
	codes, err := mgr.GenerateRecoveryCodes(ctx, "user-1", 5)
	if err != nil {
		t.Fatalf("generate failed: %v", err)
	}
	if len(codes) != 5 {
		t.Fatalf("expected 5 codes, got %d", len(codes))
	}

	storedCodes, err := store.GetRecoveryCodes(ctx, "user-1")
	if err != nil {
		t.Fatalf("stored recovery codes: %v", err)
	}
	if len(storedCodes) != len(codes) {
		t.Fatalf("expected %d stored codes, got %d", len(codes), len(storedCodes))
	}
	for i, stored := range storedCodes {
		if stored == codes[i] {
			t.Fatalf("expected stored recovery code %d to be hashed", i)
		}
		if err := bcrypt.CompareHashAndPassword([]byte(stored), []byte(normalizeRecoveryCode(codes[i]))); err != nil {
			t.Fatalf("expected stored recovery code %d to match bcrypt hash: %v", i, err)
		}
	}

	// Verify codes are in XXXX-XXXX format
	for _, code := range codes {
		parts := strings.Split(code, "-")
		if len(parts) != 2 {
			t.Errorf("invalid code format %q, expected XXXX-XXXX", code)
		}
		if len(parts[0]) != 4 || len(parts[1]) != 4 {
			t.Errorf("invalid code length in %q", code)
		}
	}

	// Verify a valid code
	ok, err := mgr.VerifyRecoveryCode(ctx, "user-1", codes[0])
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if !ok {
		t.Error("expected recovery code to be valid")
	}

	// Replay should fail (code consumed)
	ok, _ = mgr.VerifyRecoveryCode(ctx, "user-1", codes[0])
	if ok {
		t.Error("expected recovery code replay to fail")
	}

	// Verify remaining codes still work
	ok, _ = mgr.VerifyRecoveryCode(ctx, "user-1", codes[1])
	if !ok {
		t.Error("expected second recovery code to be valid")
	}
}

func TestMFAManager_RecoveryCodes_InvalidCode(t *testing.T) {
	store := NewMemoryStore()
	mgr := NewManager(store)
	ctx := context.Background()

	mgr.GenerateRecoveryCodes(ctx, "user-1", 5)

	ok, _ := mgr.VerifyRecoveryCode(ctx, "user-1", "ZZZZ-ZZZZ")
	if ok {
		t.Error("expected invalid recovery code to fail")
	}
}

func TestMFAManager_RecoveryCodes_LegacyPlaintextSupport(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()
	if err := store.SaveRecoveryCodes(ctx, "user-1", []string{"ABCD-EF12"}); err != nil {
		t.Fatalf("save legacy recovery code: %v", err)
	}

	mgr := NewManager(store)
	ok, err := mgr.VerifyRecoveryCode(ctx, "user-1", "abcd-ef12")
	if err != nil {
		t.Fatalf("verify legacy code: %v", err)
	}
	if !ok {
		t.Fatal("expected legacy plaintext recovery code to verify")
	}

	ok, err = mgr.VerifyRecoveryCode(ctx, "user-1", "ABCD-EF12")
	if err != nil {
		t.Fatalf("replay legacy code: %v", err)
	}
	if ok {
		t.Fatal("expected consumed legacy recovery code to fail on replay")
	}
}

func TestMFAManager_ListEnrollments(t *testing.T) {
	store := NewMemoryStore()
	mgr := NewManager(store)
	mgr.RegisterMethod(&mockMethod{id: "totp", verifyResult: true})
	mgr.RegisterMethod(&mockMethod{id: "sms", verifyResult: true})
	ctx := context.Background()

	mgr.Enroll(ctx, "user-1", "totp")
	mgr.Enroll(ctx, "user-1", "sms")

	enrollments, err := mgr.ListEnrollments(ctx, "user-1")
	if err != nil {
		t.Fatalf("list failed: %v", err)
	}
	if len(enrollments) != 2 {
		t.Errorf("expected 2 enrollments, got %d", len(enrollments))
	}
}

func TestMFAManager_DuplicateEnrollment(t *testing.T) {
	store := NewMemoryStore()
	mgr := NewManager(store)
	mgr.RegisterMethod(&mockMethod{id: "totp", verifyResult: true})
	ctx := context.Background()

	enrollment, _ := mgr.Enroll(ctx, "user-1", "totp")
	mgr.ConfirmEnrollment(ctx, enrollment.ID, "123456")

	// Try to enroll same method again
	_, err := mgr.Enroll(ctx, "user-1", "totp")
	if err == nil {
		t.Fatal("expected error for duplicate enrollment")
	}
}
