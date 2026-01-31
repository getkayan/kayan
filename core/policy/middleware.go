package policy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/getkayan/kayan/core/audit"
	"github.com/getkayan/kayan/core/identity"
)

// -- Audit Decorator --

type AuditMiddleware struct {
	next  Engine
	store audit.AuditStore
}

func NewAuditMiddleware(next Engine, store audit.AuditStore) *AuditMiddleware {
	return &AuditMiddleware{next: next, store: store}
}

func (m *AuditMiddleware) Can(ctx context.Context, subject any, action string, resource any) (bool, error) {
	allowed, err := m.next.Can(ctx, subject, action, resource)

	// Determine Actor ID
	actorID := "unknown"
	if s, ok := subject.(*identity.Identity); ok {
		actorID = s.ID
	} else if s, ok := subject.(string); ok {
		actorID = s
	}

	status := "denied"
	if allowed {
		status = "allowed"
	}
	if err != nil {
		status = "error"
	}

	// Async log to avoid blocking decision
	go func() {
		// Create a detached context for logging
		logCtx := context.Background()

		meta := map[string]any{
			"action":   action,
			"allowed":  allowed,
			"resource": fmt.Sprintf("%v", resource),
		}
		metaBytes, _ := json.Marshal(meta)

		m.store.SaveEvent(logCtx, &audit.AuditEvent{
			Type:      "policy.decision",
			ActorID:   actorID,
			Status:    status,
			Message:   fmt.Sprintf("Policy Check: %s", action),
			CreatedAt: time.Now(),
			Metadata:  identity.JSON(metaBytes),
		})
	}()

	return allowed, err
}

// -- Caching Decorator --

type cacheEntry struct {
	allowed   bool
	expiresAt time.Time
}

type CachingMiddleware struct {
	next Engine
	ttl  time.Duration
	mu   sync.RWMutex
	// Simple in-memory cache. In production, use Redis/Memcached interface.
	cache map[string]cacheEntry
}

func NewCachingMiddleware(next Engine, ttl time.Duration) *CachingMiddleware {
	return &CachingMiddleware{
		next:  next,
		ttl:   ttl,
		cache: make(map[string]cacheEntry),
	}
}

func (m *CachingMiddleware) Can(ctx context.Context, subject any, action string, resource any) (bool, error) {
	// 1. Generate Cache Key
	key := m.generateKey(subject, action, resource)

	// 2. Check Cache
	m.mu.RLock()
	entry, found := m.cache[key]
	m.mu.RUnlock()

	if found && time.Now().Before(entry.expiresAt) {
		return entry.allowed, nil
	}

	// 3. Compute Real Decision
	allowed, err := m.next.Can(ctx, subject, action, resource)
	if err != nil {
		return false, err
	}

	// 4. Cache Result
	m.mu.Lock()
	m.cache[key] = cacheEntry{
		allowed:   allowed,
		expiresAt: time.Now().Add(m.ttl),
	}
	m.mu.Unlock()

	return allowed, nil
}

func (m *CachingMiddleware) generateKey(subject any, action string, resource any) string {
	// Naive key generation.
	// Ideally subject and resource should implement a Key() string interface.
	// For now, we use Sprintf `%v` which is okay for basic struct pointers/IDs.
	// Hashing it for safety.
	raw := fmt.Sprintf("%v:%s:%v", subject, action, resource)
	hash := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(hash[:])
}

// Invalidate clears the cache.
func (m *CachingMiddleware) Invalidate() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cache = make(map[string]cacheEntry)
}
