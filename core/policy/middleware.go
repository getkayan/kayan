package policy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"time"

	"github.com/getkayan/kayan/core/audit"
	"github.com/getkayan/kayan/core/domain"
	"github.com/getkayan/kayan/core/identity"
)

// -- Audit Decorator --

type AuditMiddleware struct {
	next  Engine
	store audit.AuditStore

	async             bool
	dropWhenSaturated bool
	inflight          chan struct{}
	onError           func(error)
}

// DefaultAuditConcurrency bounds concurrent asynchronous audit writes.
const DefaultAuditConcurrency = 64

// AuditOption configures an [AuditMiddleware].
type AuditOption func(*AuditMiddleware)

// WithAsyncAudit records decisions on a background goroutine so the
// authorization check does not wait for the store.
//
// Concurrency is bounded by WithAuditConcurrency. Call [AuditMiddleware.Wait]
// during shutdown to flush records still in flight.
func WithAsyncAudit() AuditOption {
	return func(m *AuditMiddleware) { m.async = true }
}

// WithAuditConcurrency bounds concurrent asynchronous writes. Defaults to
// [DefaultAuditConcurrency].
func WithAuditConcurrency(n int) AuditOption {
	return func(m *AuditMiddleware) {
		if n > 0 {
			m.inflight = make(chan struct{}, n)
		}
	}
}

// WithAuditErrorHandler reports audit write failures.
//
// Without one, failures are invisible: the decision still returns, but nothing
// records that it happened.
func WithAuditErrorHandler(fn func(error)) AuditOption {
	return func(m *AuditMiddleware) { m.onError = fn }
}

// WithAuditDropWhenSaturated drops audit records instead of blocking when the
// concurrency bound is reached.
//
// The default is to record inline, which slows the request but keeps the trail
// complete. Choose this only where losing records is acceptable.
func WithAuditDropWhenSaturated() AuditOption {
	return func(m *AuditMiddleware) { m.dropWhenSaturated = true }
}

func NewAuditMiddleware(next Engine, store audit.AuditStore, opts ...AuditOption) *AuditMiddleware {
	m := &AuditMiddleware{next: next, store: store}
	for _, opt := range opts {
		opt(m)
	}
	if m.inflight == nil {
		m.inflight = make(chan struct{}, DefaultAuditConcurrency)
	}
	return m
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

	meta := map[string]any{
		"action":   action,
		"allowed":  allowed,
		"resource": fmt.Sprintf("%v", resource),
	}
	metaBytes, _ := json.Marshal(meta)

	event := &audit.AuditEvent{
		Type:      "policy.decision",
		ActorID:   actorID,
		Status:    status,
		Message:   fmt.Sprintf("Policy Check: %s", action),
		CreatedAt: time.Now(),
		Metadata:  identity.JSON(metaBytes),
	}

	if m.async {
		// Record without blocking the decision. The write is bounded by a
		// semaphore: an unbounded `go` per authorization check would spawn one
		// goroutine per request under load, and every in-flight record is lost
		// at shutdown. When the bound is reached the write happens inline
		// instead, so records are dropped only if the caller asks for that.
		select {
		case m.inflight <- struct{}{}:
			go func() {
				defer func() { <-m.inflight }()
				m.record(context.WithoutCancel(ctx), event)
			}()
			return allowed, err
		default:
			if m.dropWhenSaturated {
				return allowed, err
			}
		}
	}

	m.record(ctx, event)
	return allowed, err
}

// record persists one decision, reporting failures through the error handler.
//
// An audit trail that silently drops writes is not an audit trail, so the
// error is surfaced rather than discarded.
func (m *AuditMiddleware) record(ctx context.Context, event *audit.AuditEvent) {
	if err := m.store.SaveEvent(ctx, event); err != nil && m.onError != nil {
		m.onError(err)
	}
}

// Wait blocks until in-flight asynchronous audit writes have finished.
//
// Call it during shutdown; without it, records still in flight are lost when
// the process exits.
func (m *AuditMiddleware) Wait(ctx context.Context) error {
	for range cap(m.inflight) {
		select {
		case m.inflight <- struct{}{}:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	for range cap(m.inflight) {
		<-m.inflight
	}
	return nil
}

// -- Caching Decorator --

type cacheEntry struct {
	allowed   bool
	expiresAt time.Time
}

// DefaultMaxCacheEntries bounds the decision cache when no limit is given.
const DefaultMaxCacheEntries = 10_000

// CachingMiddleware caches authorization decisions for a bounded time.
//
// Only subjects and resources that can be keyed unambiguously are cached —
// see [CacheKeyer]. Anything else passes straight through, because a cache hit
// under the wrong key is a wrong authorization decision.
//
// The cache is in-process. Deployments with several replicas either accept
// per-replica caching or wrap a shared cache in their own [Engine].
type CachingMiddleware struct {
	next       Engine
	ttl        time.Duration
	maxEntries int
	clock      domain.Clock
	mu         sync.RWMutex
	cache      map[string]cacheEntry
}

// CachingOption configures a [CachingMiddleware].
type CachingOption func(*CachingMiddleware)

// WithMaxCacheEntries bounds the number of cached decisions. Defaults to
// [DefaultMaxCacheEntries]. A value of zero or less disables the bound, which
// lets the cache grow without limit.
func WithMaxCacheEntries(n int) CachingOption {
	return func(m *CachingMiddleware) { m.maxEntries = n }
}

// WithCacheClock sets the clock used for expiry. Defaults to
// [domain.SystemClock].
func WithCacheClock(c domain.Clock) CachingOption {
	return func(m *CachingMiddleware) { m.clock = c }
}

func NewCachingMiddleware(next Engine, ttl time.Duration, opts ...CachingOption) *CachingMiddleware {
	m := &CachingMiddleware{
		next:       next,
		ttl:        ttl,
		maxEntries: DefaultMaxCacheEntries,
		clock:      domain.SystemClock,
		cache:      make(map[string]cacheEntry),
	}
	for _, opt := range opts {
		opt(m)
	}
	m.clock = domain.ClockOrDefault(m.clock)
	return m
}

func (m *CachingMiddleware) Can(ctx context.Context, subject any, action string, resource any) (bool, error) {
	key, err := m.generateKey(subject, action, resource)
	if err != nil {
		// The value cannot be keyed unambiguously. Pass the decision through
		// rather than risk serving it under a key that belongs to something
		// else — a wrong cache hit here is a wrong authorization decision.
		return m.next.Can(ctx, subject, action, resource)
	}

	m.mu.RLock()
	entry, found := m.cache[key]
	m.mu.RUnlock()

	if found && m.clock.Now().Before(entry.expiresAt) {
		return entry.allowed, nil
	}

	allowed, err := m.next.Can(ctx, subject, action, resource)
	if err != nil {
		return false, err
	}

	m.mu.Lock()
	m.evictLocked()
	m.cache[key] = cacheEntry{
		allowed:   allowed,
		expiresAt: m.clock.Now().Add(m.ttl),
	}
	m.mu.Unlock()

	return allowed, nil
}

// evictLocked keeps the cache bounded. The caller must hold m.mu.
//
// Expired entries are dropped first. If that is not enough, entries are
// removed until the cache is back under the limit — a decision cache is a
// performance aid, so dropping an arbitrary entry is safe, whereas growing
// without bound is not.
func (m *CachingMiddleware) evictLocked() {
	if m.maxEntries <= 0 || len(m.cache) < m.maxEntries {
		return
	}

	now := m.clock.Now()
	for key, entry := range m.cache {
		if !now.Before(entry.expiresAt) {
			delete(m.cache, key)
		}
	}

	for key := range m.cache {
		if len(m.cache) < m.maxEntries {
			break
		}
		delete(m.cache, key)
	}
}

// CacheKeyer lets a subject or resource state its own cache identity.
//
// Implement it on any type used with [CachingMiddleware]. The returned string
// must identify everything the authorization decision depends on, and must be
// stable for the same logical entity across requests.
//
//	func (u *User) CacheKey() string { return "user:" + u.ID + ":" + u.Role }
type CacheKeyer interface {
	CacheKey() string
}

// errNotCacheable reports that a decision cannot be keyed safely.
var errNotCacheable = errors.New("policy: value is not cacheable")

// cacheKeyFor renders one operand of the cache key.
//
// Deriving a key with fmt is not safe in general. %v prints a struct pointer's
// fields, but stops at one level: a nested pointer field renders as its
// address, which changes between requests for the same logical subject and can
// be reused by a later allocation. The field separator is also a space, so
// {A:"a b", B:"c"} and {A:"a", B:"b c"} render identically.
//
// Rather than guess, only values that can be keyed unambiguously are accepted:
// a CacheKeyer, or a string-like scalar. Anything else is reported as
// uncacheable and the caller passes the decision through.
func cacheKeyFor(v any) (string, error) {
	switch t := v.(type) {
	case nil:
		return "nil", nil
	case CacheKeyer:
		return "k:" + t.CacheKey(), nil
	case string:
		return "s:" + t, nil
	case fmt.Stringer:
		return "S:" + t.String(), nil
	}

	// Scalars render unambiguously and cannot hide a pointer.
	switch reflect.ValueOf(v).Kind() {
	case reflect.Bool,
		reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
		reflect.Float32, reflect.Float64:
		return fmt.Sprintf("v:%v", v), nil
	}

	return "", fmt.Errorf("%w: %T does not implement policy.CacheKeyer", errNotCacheable, v)
}

// generateKey builds the cache key, or reports that the decision must not be
// cached.
//
// Operands are length-prefixed so that no combination of values can produce
// the key of a different combination.
func (m *CachingMiddleware) generateKey(subject any, action string, resource any) (string, error) {
	subjectKey, err := cacheKeyFor(subject)
	if err != nil {
		return "", err
	}
	resourceKey, err := cacheKeyFor(resource)
	if err != nil {
		return "", err
	}

	h := sha256.New()
	for _, part := range []string{subjectKey, action, resourceKey} {
		_, _ = fmt.Fprintf(h, "%d:%s", len(part), part)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Invalidate clears the cache.
func (m *CachingMiddleware) Invalidate() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cache = make(map[string]cacheEntry)
}
