package session

import (
	"context"
	"testing"
	"time"
)

func TestSSOManager_CreateSession(t *testing.T) {
	store := NewMemorySSOStore()
	mgr := NewSSOManager(store)
	ctx := context.Background()

	session, err := mgr.CreateSession(ctx, "user-1", "app-web")
	if err != nil {
		t.Fatalf("create session failed: %v", err)
	}

	if session.IdentityID != "user-1" {
		t.Errorf("expected identity_id 'user-1', got %q", session.IdentityID)
	}
	if !session.Active {
		t.Error("new session should be active")
	}
	if len(session.AppSessions) != 1 {
		t.Fatalf("expected 1 app session, got %d", len(session.AppSessions))
	}
	if session.AppSessions[0].AppID != "app-web" {
		t.Errorf("expected app 'app-web', got %q", session.AppSessions[0].AppID)
	}
}

func TestSSOManager_CreateSession_Validation(t *testing.T) {
	store := NewMemorySSOStore()
	mgr := NewSSOManager(store)
	ctx := context.Background()

	_, err := mgr.CreateSession(ctx, "", "app-web")
	if err == nil {
		t.Fatal("expected error for empty identity ID")
	}

	_, err = mgr.CreateSession(ctx, "user-1", "")
	if err == nil {
		t.Fatal("expected error for empty app ID")
	}
}

func TestSSOManager_JoinSession(t *testing.T) {
	store := NewMemorySSOStore()
	mgr := NewSSOManager(store)
	ctx := context.Background()

	session, _ := mgr.CreateSession(ctx, "user-1", "app-web")

	// Join second app
	appSession, err := mgr.JoinSession(ctx, session.ID, "app-mobile")
	if err != nil {
		t.Fatalf("join session failed: %v", err)
	}
	if appSession.AppID != "app-mobile" {
		t.Errorf("expected app 'app-mobile', got %q", appSession.AppID)
	}

	// Verify SSO session now has 2 apps
	updated, _ := mgr.GetSession(ctx, session.ID)
	if len(updated.AppSessions) != 2 {
		t.Errorf("expected 2 app sessions, got %d", len(updated.AppSessions))
	}
}

func TestSSOManager_JoinSession_DuplicateApp(t *testing.T) {
	store := NewMemorySSOStore()
	mgr := NewSSOManager(store)
	ctx := context.Background()

	session, _ := mgr.CreateSession(ctx, "user-1", "app-web")

	// Join same app again — should return existing
	appSession, err := mgr.JoinSession(ctx, session.ID, "app-web")
	if err != nil {
		t.Fatalf("join duplicate failed: %v", err)
	}
	if appSession.AppID != "app-web" {
		t.Errorf("expected app 'app-web', got %q", appSession.AppID)
	}

	// Should still have only 1 app session
	updated, _ := mgr.GetSession(ctx, session.ID)
	if len(updated.AppSessions) != 1 {
		t.Errorf("expected 1 app session, got %d", len(updated.AppSessions))
	}
}

func TestSSOManager_GlobalLogout(t *testing.T) {
	store := NewMemorySSOStore()
	mgr := NewSSOManager(store)
	ctx := context.Background()

	session, _ := mgr.CreateSession(ctx, "user-1", "app-web")
	mgr.JoinSession(ctx, session.ID, "app-mobile")
	mgr.JoinSession(ctx, session.ID, "app-desktop")

	// Global logout
	apps, err := mgr.Logout(ctx, session.ID)
	if err != nil {
		t.Fatalf("logout failed: %v", err)
	}
	if len(apps) != 3 {
		t.Errorf("expected 3 apps returned, got %d", len(apps))
	}

	// Session should be inactive
	updated, _ := mgr.GetSession(ctx, session.ID)
	if updated.Active {
		t.Error("session should be inactive after logout")
	}
}

func TestSSOManager_LogoutApp(t *testing.T) {
	store := NewMemorySSOStore()
	mgr := NewSSOManager(store)
	ctx := context.Background()

	session, _ := mgr.CreateSession(ctx, "user-1", "app-web")
	mgr.JoinSession(ctx, session.ID, "app-mobile")

	// Logout single app
	err := mgr.LogoutApp(ctx, session.ID, "app-mobile")
	if err != nil {
		t.Fatalf("logout app failed: %v", err)
	}

	// SSO session should still be active with 1 app
	updated, _ := mgr.GetSession(ctx, session.ID)
	if !updated.Active {
		t.Error("session should still be active")
	}
	if len(updated.AppSessions) != 1 {
		t.Errorf("expected 1 app session, got %d", len(updated.AppSessions))
	}
}

func TestSSOManager_LogoutApp_LastApp(t *testing.T) {
	store := NewMemorySSOStore()
	mgr := NewSSOManager(store)
	ctx := context.Background()

	session, _ := mgr.CreateSession(ctx, "user-1", "app-web")

	// Logout the only app
	mgr.LogoutApp(ctx, session.ID, "app-web")

	// SSO session should be deactivated
	updated, _ := mgr.GetSession(ctx, session.ID)
	if updated.Active {
		t.Error("session should be inactive when last app leaves")
	}
}

func TestSSOManager_ExpiredSession(t *testing.T) {
	store := NewMemorySSOStore()
	mgr := NewSSOManager(store, WithSSOTTL(1*time.Millisecond))
	ctx := context.Background()

	session, _ := mgr.CreateSession(ctx, "user-1", "app-web")
	time.Sleep(5 * time.Millisecond)

	_, err := mgr.JoinSession(ctx, session.ID, "app-mobile")
	if err == nil {
		t.Fatal("expected error for expired session")
	}
}

func TestSSOManager_CreateSession_JoinsExisting(t *testing.T) {
	store := NewMemorySSOStore()
	mgr := NewSSOManager(store)
	ctx := context.Background()

	// Create first session
	session1, _ := mgr.CreateSession(ctx, "user-1", "app-web")

	// Create second session for same user — should join existing
	session2, err := mgr.CreateSession(ctx, "user-1", "app-mobile")
	if err != nil {
		t.Fatalf("create session for same user failed: %v", err)
	}

	if session1.ID != session2.ID {
		t.Error("expected same SSO session ID for same user")
	}
	if len(session2.AppSessions) != 2 {
		t.Errorf("expected 2 app sessions, got %d", len(session2.AppSessions))
	}
}
