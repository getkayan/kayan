//go:build integration

package redisstore

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"

	"github.com/getkayan/kayan/core/session"
	"github.com/redis/go-redis/v9"
)

func TestRealRedisSSOLifecycle(t *testing.T) {
	addr := os.Getenv("KAYAN_TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("KAYAN_TEST_REDIS_ADDR is not set")
	}
	client := redis.NewClient(&redis.Options{Addr: addr})
	t.Cleanup(func() { _ = client.Close() })
	if err := client.Ping(context.Background()).Err(); err != nil {
		t.Fatalf("ping Redis: %v", err)
	}

	store := NewRedisSSOStore(client, "integration")
	mgr := session.NewSSOManager(store)
	created, err := mgr.CreateSession(context.Background(), "user-1", "web")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if _, err := mgr.JoinSession(context.Background(), created.ID, "mobile"); err != nil {
		t.Fatalf("JoinSession: %v", err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, err := mgr.JoinSession(context.Background(), created.ID, fmt.Sprintf("worker-%d", i)); err != nil {
				t.Errorf("concurrent JoinSession: %v", err)
			}
		}(i)
	}
	wg.Wait()
	got, err := mgr.GetSession(context.Background(), created.ID)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if len(got.AppSessions) != 18 {
		t.Fatalf("app sessions = %d, want 18", len(got.AppSessions))
	}
	apps, err := mgr.Logout(context.Background(), created.ID)
	if err != nil || len(apps) != 18 {
		t.Fatalf("Logout = %d apps, %v; want 18, nil", len(apps), err)
	}
}
