package flow

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
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

// TestMemoryWebAuthnSessionStoreIsConcurrencySafe covers a data race: the store
// guarded its map with nothing at all, so two users in overlapping ceremonies —
// the normal case for any deployment with more than one user — could crash the
// process with a concurrent map write. Run with -race.
func TestMemoryWebAuthnSessionStoreIsConcurrencySafe(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryWebAuthnSessionStore()

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := fmt.Sprintf("session-%d", i)
			data := &WebAuthnSessionData{
				Challenge: id,
				ExpiresAt: time.Now().Add(time.Minute),
			}
			if err := store.SaveSession(ctx, id, data); err != nil {
				t.Errorf("SaveSession: %v", err)
			}
			if _, err := store.GetSession(ctx, id); err != nil {
				t.Errorf("GetSession: %v", err)
			}
			if err := store.DeleteSession(ctx, id); err != nil {
				t.Errorf("DeleteSession: %v", err)
			}
		}(i)
	}
	wg.Wait()
}

// TestWebAuthnSetHooksIsConcurrencySafe covers the same class on the strategy:
// SetHooks wrote s.hooks with no lock while ceremonies read it.
func TestWebAuthnSetHooksIsConcurrencySafe(t *testing.T) {
	s := &WebAuthnStrategy{}

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.SetHooks(WebAuthnHooks{AllowClonedAuthenticators: true})
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = s.getHooks()
		}()
	}
	wg.Wait()
}

// TestWebAuthnCloneWarningRefusesByDefault documents the decision the clone
// branch encodes. A backwards signature counter is the only signal WebAuthn
// gives that a credential has been copied out of its authenticator; the code
// persisted that flag and then returned the identity anyway, so the one
// detection mechanism in the protocol recorded the break-in and let it through.
//
// The counter behaviour itself belongs to go-webauthn and is not re-tested
// here — what is pinned is that the refusal is the default and the escape
// hatch must be set explicitly.
func TestWebAuthnCloneWarningRefusesByDefault(t *testing.T) {
	if (WebAuthnHooks{}).AllowClonedAuthenticators {
		t.Fatal("clone warnings are ignored by default")
	}

	s := &WebAuthnStrategy{}
	if s.getHooks().AllowClonedAuthenticators {
		t.Error("a strategy built with no hooks allows cloned authenticators")
	}
}
