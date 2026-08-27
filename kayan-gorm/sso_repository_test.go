package gormstore

import (
	"context"
	"testing"

	"github.com/getkayan/kayan/core/session"
)

func TestGORMSSORepositoryLifecycle(t *testing.T) {
	db := setupSQLiteDB(t)
	if err := db.AutoMigrate(&gormSSOSession{}, &gormAppSession{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	mgr := session.NewSSOManager(NewSSORepository(db))
	ctx := context.Background()

	created, err := mgr.CreateSession(ctx, "user-1", "web")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	joined, err := mgr.JoinSession(ctx, created.ID, "mobile")
	if err != nil || joined.AppID != "mobile" {
		t.Fatalf("JoinSession = %#v, %v", joined, err)
	}
	got, err := mgr.GetSessionByIdentity(ctx, "user-1")
	if err != nil || len(got.AppSessions) != 2 {
		t.Fatalf("GetSessionByIdentity = %#v, %v", got, err)
	}
	if err := mgr.LogoutApp(ctx, created.ID, "mobile"); err != nil {
		t.Fatalf("LogoutApp: %v", err)
	}
	apps, err := mgr.Logout(ctx, created.ID)
	if err != nil || len(apps) != 1 {
		t.Fatalf("Logout = %#v, %v", apps, err)
	}
	got, err = mgr.GetSession(ctx, created.ID)
	if err != nil || got.Active {
		t.Fatalf("session after logout = %#v, %v", got, err)
	}
}

func TestGORMSSORepositoryCreateJoinsExisting(t *testing.T) {
	db := setupSQLiteDB(t)
	if err := db.AutoMigrate(&gormSSOSession{}, &gormAppSession{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	mgr := session.NewSSOManager(NewSSORepository(db))
	ctx := context.Background()
	first, err := mgr.CreateSession(ctx, "user-1", "web")
	if err != nil {
		t.Fatalf("first CreateSession: %v", err)
	}
	second, err := mgr.CreateSession(ctx, "user-1", "mobile")
	if err != nil {
		t.Fatalf("second CreateSession: %v", err)
	}
	if second.ID != first.ID || len(second.AppSessions) != 2 {
		t.Fatalf("second session = %#v, want same ID with two apps", second)
	}
}
