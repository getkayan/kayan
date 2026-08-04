package policy

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

// countingEngine records how many decisions actually reached the engine, so a
// test can tell a cache hit from a pass-through.
type countingEngine struct {
	mu      sync.Mutex
	calls   int
	allowed bool
}

func (e *countingEngine) Can(context.Context, any, string, any) (bool, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.calls++
	return e.allowed, nil
}

func (e *countingEngine) count() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.calls
}

// keyedUser states its own cache identity, which is what makes it cacheable.
type keyedUser struct {
	ID   string
	Role string
}

func (u *keyedUser) CacheKey() string { return "user:" + u.ID + ":" + u.Role }

// nestedUser has a pointer field. %v renders that field as an address, so a
// key derived from formatting would differ between two values that are
// logically identical — and could collide with a later allocation.
type nestedUser struct {
	ID    string
	Perms *permissions
}

type permissions struct{ Role string }

func TestCacheHitsForKeyedSubjects(t *testing.T) {
	ctx := context.Background()
	engine := &countingEngine{allowed: true}
	cache := NewCachingMiddleware(engine, time.Minute)

	user := &keyedUser{ID: "u1", Role: "admin"}

	for range 3 {
		allowed, err := cache.Can(ctx, user, "read", "doc:1")
		if err != nil {
			t.Fatalf("Can: %v", err)
		}
		if !allowed {
			t.Fatal("decision = denied, want allowed")
		}
	}

	if engine.count() != 1 {
		t.Errorf("engine called %d times, want 1 (later calls should hit the cache)", engine.count())
	}
}

// TestUncacheableSubjectPassesThrough is the core safety property: a value
// that cannot be keyed unambiguously must reach the engine every time rather
// than be served under a guessed key.
func TestUncacheableSubjectPassesThrough(t *testing.T) {
	ctx := context.Background()
	engine := &countingEngine{allowed: true}
	cache := NewCachingMiddleware(engine, time.Minute)

	user := &nestedUser{ID: "u1", Perms: &permissions{Role: "admin"}}

	for range 3 {
		if _, err := cache.Can(ctx, user, "read", "doc:1"); err != nil {
			t.Fatalf("Can: %v", err)
		}
	}

	if engine.count() != 3 {
		t.Errorf("engine called %d times, want 3 (an unkeyable subject must not be cached)", engine.count())
	}
}

// TestDistinctSubjectsDoNotShareEntries guards the decision that matters: one
// user must never receive another user's cached answer.
func TestDistinctSubjectsDoNotShareEntries(t *testing.T) {
	ctx := context.Background()

	// The engine allows admins and denies everyone else.
	engine := engineFunc(func(_ context.Context, subject any, _ string, _ any) (bool, error) {
		u, ok := subject.(*keyedUser)
		return ok && u.Role == "admin", nil
	})
	cache := NewCachingMiddleware(engine, time.Minute)

	admin := &keyedUser{ID: "u1", Role: "admin"}
	viewer := &keyedUser{ID: "u2", Role: "viewer"}

	if allowed, _ := cache.Can(ctx, admin, "delete", "doc:1"); !allowed {
		t.Fatal("admin was denied")
	}
	if allowed, _ := cache.Can(ctx, viewer, "delete", "doc:1"); allowed {
		t.Fatal("viewer received the admin's cached decision")
	}
}

// TestSameUserDifferentRoleIsNotShared covers privilege change: a subject
// whose role changed must not keep its earlier answer.
func TestSameUserDifferentRoleIsNotShared(t *testing.T) {
	ctx := context.Background()
	engine := engineFunc(func(_ context.Context, subject any, _ string, _ any) (bool, error) {
		u := subject.(*keyedUser)
		return u.Role == "admin", nil
	})
	cache := NewCachingMiddleware(engine, time.Minute)

	if allowed, _ := cache.Can(ctx, &keyedUser{ID: "u1", Role: "admin"}, "delete", "doc:1"); !allowed {
		t.Fatal("admin was denied")
	}
	// The role is part of CacheKey, so the demoted user gets a fresh decision.
	if allowed, _ := cache.Can(ctx, &keyedUser{ID: "u1", Role: "viewer"}, "delete", "doc:1"); allowed {
		t.Fatal("a demoted user kept the decision made while they were an admin")
	}
}

// TestKeyOperandsCannotBeConfused proves the key cannot be forged by shifting
// content across operand boundaries.
func TestKeyOperandsCannotBeConfused(t *testing.T) {
	cache := NewCachingMiddleware(&countingEngine{}, time.Minute)

	a, err := cache.generateKey("alice", "read:doc", "1")
	if err != nil {
		t.Fatalf("generateKey: %v", err)
	}
	b, err := cache.generateKey("alice", "read", "doc:1")
	if err != nil {
		t.Fatalf("generateKey: %v", err)
	}

	if a == b {
		t.Fatal("two different (subject, action, resource) triples produced the same key")
	}
}

func TestCacheRespectsTTL(t *testing.T) {
	ctx := context.Background()
	engine := &countingEngine{allowed: true}
	clock := &testClock{now: time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)}
	cache := NewCachingMiddleware(engine, time.Minute, WithCacheClock(clock))

	user := &keyedUser{ID: "u1", Role: "admin"}

	if _, err := cache.Can(ctx, user, "read", "doc:1"); err != nil {
		t.Fatalf("Can: %v", err)
	}

	clock.advance(59 * time.Second)
	if _, err := cache.Can(ctx, user, "read", "doc:1"); err != nil {
		t.Fatalf("Can: %v", err)
	}
	if engine.count() != 1 {
		t.Errorf("engine called %d times before the TTL elapsed, want 1", engine.count())
	}

	clock.advance(2 * time.Second)
	if _, err := cache.Can(ctx, user, "read", "doc:1"); err != nil {
		t.Fatalf("Can: %v", err)
	}
	if engine.count() != 2 {
		t.Errorf("engine called %d times after the TTL elapsed, want 2", engine.count())
	}
}

// TestCacheIsBounded proves the cache cannot grow without limit. Before this,
// a long-running process accumulated one entry per distinct decision forever.
func TestCacheIsBounded(t *testing.T) {
	ctx := context.Background()
	engine := &countingEngine{allowed: true}
	cache := NewCachingMiddleware(engine, time.Hour, WithMaxCacheEntries(64))

	for i := range 1_000 {
		user := &keyedUser{ID: fmt.Sprintf("u%d", i), Role: "viewer"}
		if _, err := cache.Can(ctx, user, "read", "doc:1"); err != nil {
			t.Fatalf("Can: %v", err)
		}
	}

	cache.mu.RLock()
	size := len(cache.cache)
	cache.mu.RUnlock()

	if size > 64 {
		t.Errorf("cache holds %d entries, want at most 64", size)
	}
}

func TestCacheIsRaceFree(t *testing.T) {
	ctx := context.Background()
	cache := NewCachingMiddleware(&countingEngine{allowed: true}, time.Minute, WithMaxCacheEntries(32))

	var wg sync.WaitGroup
	for i := range 64 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			user := &keyedUser{ID: fmt.Sprintf("u%d", i%8), Role: "viewer"}
			for range 16 {
				if _, err := cache.Can(ctx, user, "read", "doc:1"); err != nil {
					t.Errorf("Can: %v", err)
					return
				}
			}
		}(i)
	}
	wg.Wait()
}

// engineFunc adapts a function to Engine.
type engineFunc func(context.Context, any, string, any) (bool, error)

func (f engineFunc) Can(ctx context.Context, subject any, action string, resource any) (bool, error) {
	return f(ctx, subject, action, resource)
}

// testClock is a manually advanced clock.
type testClock struct {
	mu  sync.RWMutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.now
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}
