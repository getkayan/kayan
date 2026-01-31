package flow

import (
	"context"
	"testing"
)

func TestNewWebAuthnStrategy(t *testing.T) {
	sessionStore := NewMemoryWebAuthnSessionStore()

	config := WebAuthnConfig{
		RPDisplayName: "Test App",
		RPID:          "localhost",
		RPOrigins:     []string{"http://localhost:8080"},
	}

	strategy, err := NewWebAuthnStrategy(nil, config, nil, sessionStore)
	if err != nil {
		t.Fatalf("Failed to create WebAuthn strategy: %v", err)
	}

	if strategy.ID() != "webauthn" {
		t.Errorf("Expected ID 'webauthn', got '%s'", strategy.ID())
	}
}

func TestMemoryWebAuthnSessionStore(t *testing.T) {
	store := NewMemoryWebAuthnSessionStore()
	ctx := context.Background()

	sessionData := &WebAuthnSessionData{
		Challenge:        "test-challenge",
		UserID:           []byte("user-123"),
		UserVerification: "preferred",
	}

	// Test SaveSession
	err := store.SaveSession(ctx, "session-1", sessionData)
	if err != nil {
		t.Fatalf("SaveSession failed: %v", err)
	}

	// Test GetSession
	retrieved, err := store.GetSession(ctx, "session-1")
	if err != nil {
		t.Fatalf("GetSession failed: %v", err)
	}

	if retrieved.Challenge != sessionData.Challenge {
		t.Errorf("Challenge mismatch: expected %s, got %s", sessionData.Challenge, retrieved.Challenge)
	}

	// Test GetSession for non-existent session
	_, err = store.GetSession(ctx, "non-existent")
	if err == nil {
		t.Error("Expected error for non-existent session")
	}

	// Test DeleteSession
	err = store.DeleteSession(ctx, "session-1")
	if err != nil {
		t.Fatalf("DeleteSession failed: %v", err)
	}

	_, err = store.GetSession(ctx, "session-1")
	if err == nil {
		t.Error("Expected error after deletion")
	}
}

func TestWebAuthnCredentialData(t *testing.T) {
	data := WebAuthnCredentialData{
		CredentialID:    []byte("cred-id"),
		PublicKey:       []byte("public-key"),
		AttestationType: "none",
		AAGUID:          []byte("aaguid"),
		SignCount:       0,
		CloneWarning:    false,
		BackupEligible:  true,
		BackupState:     false,
	}

	if string(data.CredentialID) != "cred-id" {
		t.Error("CredentialID mismatch")
	}

	if !data.BackupEligible {
		t.Error("BackupEligible should be true")
	}
}
