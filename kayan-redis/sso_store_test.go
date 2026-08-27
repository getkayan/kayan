package redisstore

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/getkayan/kayan/core/session"
	"github.com/redis/go-redis/v9"
)

func newTestSSOStore(t *testing.T) (*RedisSSOStore, func()) {
	t.Helper()
	server, err := miniredis.Run()
	if err != nil {
		t.Fatalf("start miniredis: %v", err)
	}
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	return NewRedisSSOStore(client, "test"), func() {
		_ = client.Close()
		server.Close()
	}
}

func TestRedisSSOStoreLifecycle(t *testing.T) {
	store, closeStore := newTestSSOStore(t)
	defer closeStore()
	mgr := session.NewSSOManager(store)
	ctx := context.Background()

	created, err := mgr.CreateSession(ctx, "user-1", "web")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if _, err := mgr.JoinSession(ctx, created.ID, "mobile"); err != nil {
		t.Fatalf("JoinSession: %v", err)
	}
	got, err := mgr.GetSessionByIdentity(ctx, "user-1")
	if err != nil {
		t.Fatalf("GetSessionByIdentity: %v", err)
	}
	if len(got.AppSessions) != 2 {
		t.Fatalf("apps = %d, want 2", len(got.AppSessions))
	}
	apps, err := mgr.Logout(ctx, created.ID)
	if err != nil || len(apps) != 2 {
		t.Fatalf("Logout = %d apps, %v", len(apps), err)
	}
}

func TestRedisSSOStoreConcurrentJoins(t *testing.T) {
	store, closeStore := newTestSSOStore(t)
	defer closeStore()
	mgr := session.NewSSOManager(store)
	ctx := context.Background()
	created, err := mgr.CreateSession(ctx, "user-1", "app-0")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	const joins = 24
	var wg sync.WaitGroup
	errs := make(chan error, joins)
	for i := 1; i <= joins; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := mgr.JoinSession(ctx, created.ID, fmt.Sprintf("app-%d", i))
			errs <- err
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("JoinSession: %v", err)
		}
	}
	got, err := mgr.GetSession(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if len(got.AppSessions) != joins+1 {
		t.Fatalf("apps = %d, want %d", len(got.AppSessions), joins+1)
	}
}

func TestRedisSSOStoreRejectsExpiredJoin(t *testing.T) {
	store, closeStore := newTestSSOStore(t)
	defer closeStore()
	now := time.Now()
	candidate := &session.SSOSession{
		ID: "s1", IdentityID: "u1", Active: true,
		CreatedAt: now, ExpiresAt: now.Add(time.Minute),
		AppSessions: []session.AppSession{{AppID: "web", SessionID: "a1", CreatedAt: now}},
	}
	if _, err := store.CreateOrJoinSSOSession(context.Background(), candidate); err != nil {
		t.Fatalf("CreateOrJoinSSOSession: %v", err)
	}
	_, err := store.JoinSSOSession(context.Background(), "s1", session.AppSession{AppID: "late", CreatedAt: now.Add(2 * time.Minute)})
	if err == nil {
		t.Fatal("expected expired join error")
	}
}
