package gormstore

import (
	"context"
	"testing"
	"time"

	"github.com/getkayan/kayan/core/device"
	"github.com/getkayan/kayan/core/mfa"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

// newSharedDB opens a SQLite database that survives being closed and reopened
// by a second repository, which is how a restart is simulated.
func newSharedDB(t *testing.T) *gorm.DB {
	t.Helper()

	// A named in-memory database with a shared cache stays alive while any
	// connection holds it, so two repositories can see the same data.
	db, err := gorm.Open(sqlite.Open("file:mfa_test?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() {
		sql, err := db.DB()
		if err == nil {
			_ = sql.Close()
		}
	})
	return db
}

func newMFARepo(t *testing.T) *MFARepository {
	t.Helper()

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	repo := NewMFARepository(db)
	if err := repo.AutoMigrate(); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return repo
}

// TestEnrollmentsSurviveRestart is the reason this repository exists. With the
// in-memory store, every MFA enrollment is lost when the process restarts,
// locking out every user who had enrolled.
func TestEnrollmentsSurviveRestart(t *testing.T) {
	ctx := context.Background()
	db := newSharedDB(t)

	first := NewMFARepository(db)
	if err := first.AutoMigrate(); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	enrollment := &mfa.Enrollment{
		ID:         "enr-1",
		IdentityID: "user-1",
		MethodID:   "totp",
		Status:     mfa.EnrollmentActive,
		Config:     map[string]any{"secret_uri": "otpauth://totp/example"},
		CreatedAt:  time.Now().UTC().Truncate(time.Second),
	}
	if err := first.SaveEnrollment(ctx, enrollment); err != nil {
		t.Fatalf("SaveEnrollment: %v", err)
	}

	// A second repository over the same database stands in for a restart.
	second := NewMFARepository(db)

	stored, err := second.GetEnrollment(ctx, "enr-1")
	if err != nil {
		t.Fatalf("the enrollment did not survive: %v", err)
	}
	if stored.IdentityID != "user-1" || stored.MethodID != "totp" {
		t.Errorf("enrollment = %+v", stored)
	}
	if stored.Status != mfa.EnrollmentActive {
		t.Errorf("Status = %q, want active", stored.Status)
	}

	// The method-specific config must round-trip, or the enrolled factor is
	// unusable even though the record survived.
	config, ok := stored.Config.(map[string]any)
	if !ok {
		t.Fatalf("Config is %T, want a map", stored.Config)
	}
	if config["secret_uri"] != "otpauth://totp/example" {
		t.Errorf("secret_uri = %v", config["secret_uri"])
	}
}

func TestEnrollmentLifecycle(t *testing.T) {
	ctx := context.Background()
	repo := newMFARepo(t)

	for _, id := range []string{"enr-1", "enr-2"} {
		if err := repo.SaveEnrollment(ctx, &mfa.Enrollment{
			ID: id, IdentityID: "user-1", MethodID: "totp",
			Status: mfa.EnrollmentPending, CreatedAt: time.Now(),
		}); err != nil {
			t.Fatalf("SaveEnrollment: %v", err)
		}
	}

	found, err := repo.GetEnrollmentsByIdentity(ctx, "user-1")
	if err != nil {
		t.Fatalf("GetEnrollmentsByIdentity: %v", err)
	}
	if len(found) != 2 {
		t.Errorf("found %d enrollments, want 2", len(found))
	}

	if err := repo.UpdateEnrollment(ctx, &mfa.Enrollment{
		ID: "enr-1", IdentityID: "user-1", MethodID: "totp",
		Status: mfa.EnrollmentActive,
	}); err != nil {
		t.Fatalf("UpdateEnrollment: %v", err)
	}

	updated, err := repo.GetEnrollment(ctx, "enr-1")
	if err != nil {
		t.Fatalf("GetEnrollment: %v", err)
	}
	if updated.Status != mfa.EnrollmentActive {
		t.Errorf("Status = %q, want active", updated.Status)
	}

	if err := repo.DeleteEnrollment(ctx, "enr-1"); err != nil {
		t.Fatalf("DeleteEnrollment: %v", err)
	}
	if _, err := repo.GetEnrollment(ctx, "enr-1"); err == nil {
		t.Error("the enrollment is still readable after deletion")
	}
}

func TestUpdateEnrollmentRequiresAnExistingRecord(t *testing.T) {
	ctx := context.Background()
	repo := newMFARepo(t)

	// Update must not silently create, which would mask a caller bug.
	err := repo.UpdateEnrollment(ctx, &mfa.Enrollment{ID: "absent", Status: mfa.EnrollmentActive})
	if err == nil {
		t.Fatal("UpdateEnrollment created a record that did not exist")
	}
}

// TestExpiredChallengeIsNotReturned proves a challenge cannot be completed
// after its window closes.
func TestExpiredChallengeIsNotReturned(t *testing.T) {
	ctx := context.Background()
	repo := newMFARepo(t)

	if err := repo.SaveChallenge(ctx, &mfa.Challenge{
		ID: "chal-live", EnrollmentID: "enr-1", MethodID: "totp",
		ExpiresAt: time.Now().Add(time.Minute),
	}); err != nil {
		t.Fatalf("SaveChallenge: %v", err)
	}
	if err := repo.SaveChallenge(ctx, &mfa.Challenge{
		ID: "chal-dead", EnrollmentID: "enr-1", MethodID: "totp",
		ExpiresAt: time.Now().Add(-time.Minute),
	}); err != nil {
		t.Fatalf("SaveChallenge: %v", err)
	}

	if _, err := repo.GetChallenge(ctx, "chal-live"); err != nil {
		t.Errorf("a live challenge was rejected: %v", err)
	}
	if _, err := repo.GetChallenge(ctx, "chal-dead"); err == nil {
		t.Error("an expired challenge was returned")
	}
}

// TestRecoveryCodeIsSingleUse proves a code cannot be redeemed twice. Each one
// is a bearer credential that bypasses the second factor entirely.
func TestRecoveryCodeIsSingleUse(t *testing.T) {
	ctx := context.Background()
	repo := newMFARepo(t)

	// These are hashes; mfa.Manager bcrypts each code before it reaches here.
	hashes := []string{"$2a$04$hash-one", "$2a$04$hash-two"}
	if err := repo.SaveRecoveryCodes(ctx, "user-1", hashes); err != nil {
		t.Fatalf("SaveRecoveryCodes: %v", err)
	}

	if err := repo.ConsumeRecoveryCode(ctx, "user-1", hashes[0]); err != nil {
		t.Fatalf("first consumption failed: %v", err)
	}
	if err := repo.ConsumeRecoveryCode(ctx, "user-1", hashes[0]); err == nil {
		t.Fatal("a recovery code was consumed twice")
	}

	// The remaining code must still be available.
	remaining, err := repo.GetRecoveryCodes(ctx, "user-1")
	if err != nil {
		t.Fatalf("GetRecoveryCodes: %v", err)
	}
	if len(remaining) != 1 || remaining[0] != hashes[1] {
		t.Errorf("remaining codes = %v, want only the unconsumed one", remaining)
	}
}

// TestRegeneratingCodesInvalidatesTheOldSet proves the previous codes stop
// working, which is the whole point of regenerating them.
func TestRegeneratingCodesInvalidatesTheOldSet(t *testing.T) {
	ctx := context.Background()
	repo := newMFARepo(t)

	old := []string{"$2a$04$old-one", "$2a$04$old-two"}
	if err := repo.SaveRecoveryCodes(ctx, "user-1", old); err != nil {
		t.Fatalf("SaveRecoveryCodes: %v", err)
	}
	if err := repo.SaveRecoveryCodes(ctx, "user-1", []string{"$2a$04$new-one"}); err != nil {
		t.Fatalf("regenerate: %v", err)
	}

	if err := repo.ConsumeRecoveryCode(ctx, "user-1", old[0]); err == nil {
		t.Fatal("a code from the superseded set was accepted")
	}

	remaining, err := repo.GetRecoveryCodes(ctx, "user-1")
	if err != nil {
		t.Fatalf("GetRecoveryCodes: %v", err)
	}
	if len(remaining) != 1 {
		t.Errorf("%d codes remain, want 1", len(remaining))
	}
}

func TestConsumingAnUnknownCodeFails(t *testing.T) {
	ctx := context.Background()
	repo := newMFARepo(t)

	if err := repo.ConsumeRecoveryCode(ctx, "user-1", "$2a$04$never-issued"); err == nil {
		t.Fatal("an unknown recovery code was accepted")
	}
}

// --- devices ---

func newDeviceRepo(t *testing.T) *DeviceRepository {
	t.Helper()

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	repo := NewDeviceRepository(db)
	if err := repo.AutoMigrate(); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return repo
}

func TestDeviceLifecycle(t *testing.T) {
	ctx := context.Background()
	repo := newDeviceRepo(t)

	d := &device.Device{
		ID:          "dev-1",
		IdentityID:  "user-1",
		Name:        "Work Laptop",
		Fingerprint: "fp-1",
		TrustLevel:  device.TrustMedium,
		LastSeenAt:  time.Now(),
		CreatedAt:   time.Now(),
	}
	if err := repo.SaveDevice(ctx, d); err != nil {
		t.Fatalf("SaveDevice: %v", err)
	}

	byFingerprint, err := repo.GetDeviceByFingerprint(ctx, "user-1", "fp-1")
	if err != nil {
		t.Fatalf("GetDeviceByFingerprint: %v", err)
	}
	if byFingerprint.ID != "dev-1" {
		t.Errorf("ID = %q, want dev-1", byFingerprint.ID)
	}
	if byFingerprint.TrustLevel != device.TrustMedium {
		t.Errorf("TrustLevel = %q, want %q", byFingerprint.TrustLevel, device.TrustMedium)
	}

	d.TrustLevel = device.TrustHigh
	d.Verified = true
	if err := repo.UpdateDevice(ctx, d); err != nil {
		t.Fatalf("UpdateDevice: %v", err)
	}

	updated, err := repo.GetDevice(ctx, "dev-1")
	if err != nil {
		t.Fatalf("GetDevice: %v", err)
	}
	if updated.TrustLevel != device.TrustHigh || !updated.Verified {
		t.Errorf("device = %+v, want trusted and verified", updated)
	}
}

// TestDeleteDevicesByIdentityRemovesAll covers "sign out everywhere": leaving
// one device behind leaves an attacker's device trusted.
func TestDeleteDevicesByIdentityRemovesAll(t *testing.T) {
	ctx := context.Background()
	repo := newDeviceRepo(t)

	for _, id := range []string{"dev-1", "dev-2", "dev-3"} {
		if err := repo.SaveDevice(ctx, &device.Device{
			ID: id, IdentityID: "user-1", Fingerprint: "fp-" + id,
			TrustLevel: device.TrustLow, CreatedAt: time.Now(),
		}); err != nil {
			t.Fatalf("SaveDevice: %v", err)
		}
	}
	// Another user's device must survive.
	if err := repo.SaveDevice(ctx, &device.Device{
		ID: "other", IdentityID: "user-2", Fingerprint: "fp-other",
		TrustLevel: device.TrustLow, CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("SaveDevice: %v", err)
	}

	if err := repo.DeleteDevicesByIdentity(ctx, "user-1"); err != nil {
		t.Fatalf("DeleteDevicesByIdentity: %v", err)
	}

	remaining, err := repo.GetDevicesByIdentity(ctx, "user-1")
	if err != nil {
		t.Fatalf("GetDevicesByIdentity: %v", err)
	}
	if len(remaining) != 0 {
		t.Errorf("%d devices remain for user-1, want 0", len(remaining))
	}

	others, err := repo.GetDevicesByIdentity(ctx, "user-2")
	if err != nil {
		t.Fatalf("GetDevicesByIdentity: %v", err)
	}
	if len(others) != 1 {
		t.Error("another user's device was deleted")
	}
}

func TestUpdateDeviceRequiresAnExistingRecord(t *testing.T) {
	ctx := context.Background()
	repo := newDeviceRepo(t)

	err := repo.UpdateDevice(ctx, &device.Device{ID: "absent", IdentityID: "user-1"})
	if err == nil {
		t.Fatal("UpdateDevice created a record that did not exist")
	}
}
