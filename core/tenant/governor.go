package tenant

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Errors reported by tenant resource governance.
var (
	ErrInvalidLimits         = errors.New("tenant: invalid resource limits")
	ErrInvalidOperation      = errors.New("tenant: invalid governed operation")
	ErrRateLimitExceeded     = errors.New("tenant: rate limit exceeded")
	ErrConcurrencyExceeded   = errors.New("tenant: concurrency limit exceeded")
	ErrGovernanceUnavailable = errors.New("tenant: resource governance unavailable")
	ErrConcurrencyLeaseLost  = errors.New("tenant: concurrency lease lost")
)

// ResourceLimits bounds one class of work for a tenant or for the deployment.
// A zero limit disables that dimension. Negative values are invalid.
type ResourceLimits struct {
	RateLimit        int
	RateWindow       time.Duration
	ConcurrencyLimit int
	LeaseTTL         time.Duration
}

// Validate checks that every enabled limit has the duration needed to enforce it.
func (l ResourceLimits) Validate() error {
	if l.RateLimit < 0 || l.ConcurrencyLimit < 0 || l.RateWindow < 0 || l.LeaseTTL < 0 {
		return ErrInvalidLimits
	}
	if l.RateLimit > 0 && l.RateWindow < time.Millisecond {
		return fmt.Errorf("%w: rate window must be at least one millisecond", ErrInvalidLimits)
	}
	if l.ConcurrencyLimit > 0 && l.LeaseTTL < time.Millisecond {
		return fmt.Errorf("%w: lease TTL must be at least one millisecond", ErrInvalidLimits)
	}
	return nil
}

// LimitProvider resolves limits for a tenant and a stable operation name.
// Implementations can use tenant plans, feature flags, or application policy.
type LimitProvider interface {
	Limits(ctx context.Context, tenantID, operation string) (ResourceLimits, error)
}

// LimitProviderFunc adapts a function to LimitProvider.
type LimitProviderFunc func(ctx context.Context, tenantID, operation string) (ResourceLimits, error)

// Limits implements LimitProvider.
func (f LimitProviderFunc) Limits(ctx context.Context, tenantID, operation string) (ResourceLimits, error) {
	return f(ctx, tenantID, operation)
}

// FixedLimits applies the same limits to every operation and tenant presented
// to the provider.
type FixedLimits ResourceLimits

// Limits implements LimitProvider.
func (l FixedLimits) Limits(context.Context, string, string) (ResourceLimits, error) {
	return ResourceLimits(l), nil
}

// GovernanceRateLimiter counts admission attempts in a time window.
// The key is opaque and contains no raw tenant identifier.
type GovernanceRateLimiter interface {
	Allow(ctx context.Context, key string, limit int, window time.Duration) (allowed bool, remaining int, err error)
}

// ConcurrencyLease identifies one expiring capacity reservation.
// Callers should treat Key and Token as opaque.
type ConcurrencyLease struct {
	Key       string
	Token     string
	ExpiresAt time.Time
}

// ConcurrencyLimiter reserves distributed or local in-flight capacity.
// Release must remove only the lease carrying the matching token.
type ConcurrencyLimiter interface {
	Acquire(ctx context.Context, key string, limit int, ttl time.Duration) (lease ConcurrencyLease, allowed bool, retryAfter time.Duration, err error)
	Renew(ctx context.Context, lease ConcurrencyLease, ttl time.Duration) (renewed ConcurrencyLease, ok bool, err error)
	Release(ctx context.Context, lease ConcurrencyLease) error
}

// GovernanceScope identifies which budget made an admission decision.
type GovernanceScope string

const (
	GovernanceScopeTenant GovernanceScope = "tenant"
	GovernanceScopeGlobal GovernanceScope = "global"
)

// GovernanceKind identifies the constrained resource dimension.
type GovernanceKind string

const (
	GovernanceKindNone        GovernanceKind = "none"
	GovernanceKindRate        GovernanceKind = "rate"
	GovernanceKindConcurrency GovernanceKind = "concurrency"
)

// GovernanceDecision describes one final admission decision. TenantID and
// Operation are suitable for audit hooks, but metric backends should consider
// their cardinality before using them as labels.
type GovernanceDecision struct {
	TenantID   string
	Operation  string
	Scope      GovernanceScope
	Kind       GovernanceKind
	Allowed    bool
	Remaining  int
	RetryAfter time.Duration
	Err        error
}

// GovernanceUsage describes an admitted operation when its permit is released.
type GovernanceUsage struct {
	TenantID  string
	Operation string
	Duration  time.Duration
}

// GovernorHooks connects admission decisions to audit and observability code.
// Hooks are informational and cannot override enforcement.
type GovernorHooks struct {
	OnDecision func(ctx context.Context, decision GovernanceDecision)
	OnRelease  func(ctx context.Context, usage GovernanceUsage)
}

// LimitError reports a rejected admission without exposing an internal key.
type LimitError struct {
	Kind       GovernanceKind
	Scope      GovernanceScope
	Operation  string
	RetryAfter time.Duration
}

// Error implements error.
func (e *LimitError) Error() string {
	return fmt.Sprintf("tenant: %s %s limit exceeded for %q", e.Scope, e.Kind, e.Operation)
}

// Unwrap makes errors.Is work with ErrRateLimitExceeded and
// ErrConcurrencyExceeded.
func (e *LimitError) Unwrap() error {
	if e.Kind == GovernanceKindRate {
		return ErrRateLimitExceeded
	}
	return ErrConcurrencyExceeded
}

// GovernorOption configures a Governor.
type GovernorOption func(*Governor)

// WithGlobalLimitProvider adds a deployment-wide budget after each tenant's
// own budget. Tenant rejection therefore cannot consume global concurrency.
func WithGlobalLimitProvider(provider LimitProvider) GovernorOption {
	return func(g *Governor) { g.global = provider }
}

// WithGovernorHooks installs informational decision and usage hooks.
func WithGovernorHooks(hooks GovernorHooks) GovernorOption {
	return func(g *Governor) { g.hooks = hooks }
}

// Governor admits work against per-tenant and optional global resource limits.
// It is transport-independent: HTTP, RPC, jobs, and message consumers all use
// the same Acquire and Release lifecycle.
type Governor struct {
	rate        GovernanceRateLimiter
	concurrency ConcurrencyLimiter
	tenant      LimitProvider
	global      LimitProvider
	hooks       GovernorHooks
	now         func() time.Time
}

// NewGovernor creates a resource governor. A provider is required; limiter
// implementations may be nil only when their corresponding limits remain zero.
func NewGovernor(rate GovernanceRateLimiter, concurrency ConcurrencyLimiter, provider LimitProvider, opts ...GovernorOption) (*Governor, error) {
	if provider == nil {
		return nil, fmt.Errorf("%w: tenant limit provider is required", ErrInvalidLimits)
	}
	g := &Governor{rate: rate, concurrency: concurrency, tenant: provider, now: time.Now}
	for _, opt := range opts {
		if opt != nil {
			opt(g)
		}
	}
	return g, nil
}

type heldLease struct {
	lease ConcurrencyLease
	ttl   time.Duration
}

// Permit represents admitted work. Release it as soon as the operation ends.
// For work that may outlive its lease TTL, call Renew periodically and cancel
// the work if renewal fails.
type Permit struct {
	limiter   ConcurrencyLimiter
	hooks     GovernorHooks
	tenantID  string
	operation string
	startedAt time.Time
	now       func() time.Time

	mu       sync.Mutex
	released bool
	leases   []heldLease
}

// Acquire admits an operation for the tenant in ctx. It fails closed when the
// tenant, policy, or required limiter is unavailable.
func (g *Governor) Acquire(ctx context.Context, operation string) (*Permit, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	tenantID, ok := RequireID(ctx)
	if !ok || tenantID == "" {
		return nil, ErrNoTenant
	}
	if !validOperation(operation) {
		return nil, ErrInvalidOperation
	}

	tenantLimits, err := g.loadLimits(ctx, g.tenant, tenantID, operation)
	if err != nil {
		return nil, g.failed(ctx, tenantID, operation, GovernanceScopeTenant, GovernanceKindNone, err)
	}
	globalLimits := ResourceLimits{}
	if g.global != nil {
		globalLimits, err = g.loadLimits(ctx, g.global, "", operation)
		if err != nil {
			return nil, g.failed(ctx, tenantID, operation, GovernanceScopeGlobal, GovernanceKindNone, err)
		}
	}

	permit := &Permit{
		limiter: g.concurrency, hooks: g.hooks, tenantID: tenantID,
		operation: operation, startedAt: g.now(), now: g.now,
	}
	if err := g.apply(ctx, permit, GovernanceScopeTenant, tenantID, operation, tenantLimits); err != nil {
		return nil, err
	}
	if err := g.apply(ctx, permit, GovernanceScopeGlobal, "", operation, globalLimits); err != nil {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if cleanupErr := permit.releaseLeases(cleanup); cleanupErr != nil {
			return nil, errors.Join(err, fmt.Errorf("%w: rollback admission: %w", ErrGovernanceUnavailable, cleanupErr))
		}
		return nil, err
	}

	g.notify(ctx, GovernanceDecision{
		TenantID: tenantID, Operation: operation, Scope: GovernanceScopeTenant,
		Kind: GovernanceKindNone, Allowed: true,
	})
	return permit, nil
}

func (g *Governor) loadLimits(ctx context.Context, provider LimitProvider, tenantID, operation string) (ResourceLimits, error) {
	limits, err := provider.Limits(ctx, tenantID, operation)
	if err != nil {
		return ResourceLimits{}, fmt.Errorf("%w: resolve limits: %w", ErrGovernanceUnavailable, err)
	}
	if err := limits.Validate(); err != nil {
		return ResourceLimits{}, err
	}
	return limits, nil
}

func (g *Governor) apply(ctx context.Context, permit *Permit, scope GovernanceScope, tenantID, operation string, limits ResourceLimits) error {
	key := governanceKey(scope, tenantID, operation)
	if limits.RateLimit > 0 {
		if g.rate == nil {
			return g.failed(ctx, permit.tenantID, operation, scope, GovernanceKindRate,
				fmt.Errorf("%w: rate limiter is not configured", ErrGovernanceUnavailable))
		}
		allowed, remaining, err := g.rate.Allow(ctx, key, limits.RateLimit, limits.RateWindow)
		if err != nil {
			return g.failed(ctx, permit.tenantID, operation, scope, GovernanceKindRate,
				fmt.Errorf("%w: rate limiter: %w", ErrGovernanceUnavailable, err))
		}
		if !allowed {
			limitErr := &LimitError{Kind: GovernanceKindRate, Scope: scope, Operation: operation, RetryAfter: limits.RateWindow}
			g.notify(ctx, GovernanceDecision{TenantID: permit.tenantID, Operation: operation, Scope: scope,
				Kind: GovernanceKindRate, Allowed: false, Remaining: remaining, RetryAfter: limits.RateWindow, Err: limitErr})
			return limitErr
		}
	}

	if limits.ConcurrencyLimit > 0 {
		if g.concurrency == nil {
			return g.failed(ctx, permit.tenantID, operation, scope, GovernanceKindConcurrency,
				fmt.Errorf("%w: concurrency limiter is not configured", ErrGovernanceUnavailable))
		}
		lease, allowed, retryAfter, err := g.concurrency.Acquire(ctx, key, limits.ConcurrencyLimit, limits.LeaseTTL)
		if err != nil {
			return g.failed(ctx, permit.tenantID, operation, scope, GovernanceKindConcurrency,
				fmt.Errorf("%w: concurrency limiter: %w", ErrGovernanceUnavailable, err))
		}
		if !allowed {
			limitErr := &LimitError{Kind: GovernanceKindConcurrency, Scope: scope, Operation: operation, RetryAfter: retryAfter}
			g.notify(ctx, GovernanceDecision{TenantID: permit.tenantID, Operation: operation, Scope: scope,
				Kind: GovernanceKindConcurrency, Allowed: false, RetryAfter: retryAfter, Err: limitErr})
			return limitErr
		}
		permit.leases = append(permit.leases, heldLease{lease: lease, ttl: limits.LeaseTTL})
	}
	return nil
}

func (g *Governor) failed(ctx context.Context, tenantID, operation string, scope GovernanceScope, kind GovernanceKind, err error) error {
	g.notify(ctx, GovernanceDecision{TenantID: tenantID, Operation: operation, Scope: scope, Kind: kind, Allowed: false, Err: err})
	return err
}

func (g *Governor) notify(ctx context.Context, decision GovernanceDecision) {
	if g.hooks.OnDecision != nil {
		g.hooks.OnDecision(ctx, decision)
	}
}

// Release returns every concurrency reservation. It is idempotent. A failed
// backend release is safe because each lease also expires at its TTL.
func (p *Permit) Release(ctx context.Context) error {
	p.mu.Lock()
	if p.released {
		p.mu.Unlock()
		return nil
	}
	p.released = true
	p.mu.Unlock()

	err := p.releaseLeases(ctx)
	if p.hooks.OnRelease != nil {
		p.hooks.OnRelease(ctx, GovernanceUsage{
			TenantID: p.tenantID, Operation: p.operation, Duration: p.now().Sub(p.startedAt),
		})
	}
	return err
}

func (p *Permit) releaseLeases(ctx context.Context) error {
	var errs []error
	for i := len(p.leases) - 1; i >= 0; i-- {
		if err := p.limiter.Release(ctx, p.leases[i].lease); err != nil {
			errs = append(errs, fmt.Errorf("release %s lease: %w", p.leases[i].lease.Key, err))
		}
	}
	return errors.Join(errs...)
}

// Renew extends all concurrency reservations. A missing lease means capacity
// was lost and the caller must stop the governed work.
func (p *Permit) Renew(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.released {
		return ErrConcurrencyLeaseLost
	}
	for i := range p.leases {
		renewed, ok, err := p.limiter.Renew(ctx, p.leases[i].lease, p.leases[i].ttl)
		if err != nil {
			return fmt.Errorf("%w: renew concurrency lease: %w", ErrGovernanceUnavailable, err)
		}
		if !ok {
			return ErrConcurrencyLeaseLost
		}
		p.leases[i].lease = renewed
	}
	return nil
}

func validOperation(operation string) bool {
	if operation == "" || len(operation) > 128 {
		return false
	}
	for _, r := range operation {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '.' || r == ':' || r == '_' || r == '-' {
			continue
		}
		return false
	}
	return true
}

func governanceKey(scope GovernanceScope, tenantID, operation string) string {
	digest := sha256.Sum256([]byte(string(scope) + "\x00" + tenantID + "\x00" + operation))
	return "governance:" + string(scope) + ":" + hex.EncodeToString(digest[:])
}

// MemoryGovernanceRateLimiter is a fixed-window limiter for tests and
// single-instance deployments.
type MemoryGovernanceRateLimiter struct {
	mu      sync.Mutex
	entries map[string]memoryRateEntry
	now     func() time.Time
}

type memoryRateEntry struct {
	count   int
	resetAt time.Time
}

// NewMemoryGovernanceRateLimiter creates an in-process rate limiter.
func NewMemoryGovernanceRateLimiter() *MemoryGovernanceRateLimiter {
	return &MemoryGovernanceRateLimiter{entries: make(map[string]memoryRateEntry), now: time.Now}
}

// Allow implements GovernanceRateLimiter.
func (m *MemoryGovernanceRateLimiter) Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, int, error) {
	if err := ctx.Err(); err != nil {
		return false, 0, err
	}
	if limit <= 0 || window <= 0 {
		return false, 0, ErrInvalidLimits
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	entry, ok := m.entries[key]
	if !ok || !now.Before(entry.resetAt) {
		m.entries[key] = memoryRateEntry{count: 1, resetAt: now.Add(window)}
		return true, limit - 1, nil
	}
	if entry.count >= limit {
		return false, 0, nil
	}
	entry.count++
	m.entries[key] = entry
	return true, limit - entry.count, nil
}

// MemoryConcurrencyLimiter is an expiring in-process concurrency limiter for
// tests and single-instance deployments.
type MemoryConcurrencyLimiter struct {
	mu     sync.Mutex
	leases map[string]map[string]time.Time
	now    func() time.Time
}

// NewMemoryConcurrencyLimiter creates an in-process concurrency limiter.
func NewMemoryConcurrencyLimiter() *MemoryConcurrencyLimiter {
	return &MemoryConcurrencyLimiter{leases: make(map[string]map[string]time.Time), now: time.Now}
}

// Acquire implements ConcurrencyLimiter.
func (m *MemoryConcurrencyLimiter) Acquire(ctx context.Context, key string, limit int, ttl time.Duration) (ConcurrencyLease, bool, time.Duration, error) {
	if err := ctx.Err(); err != nil {
		return ConcurrencyLease{}, false, 0, err
	}
	if limit <= 0 || ttl <= 0 {
		return ConcurrencyLease{}, false, 0, ErrInvalidLimits
	}
	token, err := randomLeaseToken()
	if err != nil {
		return ConcurrencyLease{}, false, 0, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	items := m.leases[key]
	if items == nil {
		items = make(map[string]time.Time)
		m.leases[key] = items
	}
	var earliest time.Time
	for existing, expiry := range items {
		if !now.Before(expiry) {
			delete(items, existing)
			continue
		}
		if earliest.IsZero() || expiry.Before(earliest) {
			earliest = expiry
		}
	}
	if len(items) >= limit {
		return ConcurrencyLease{}, false, maxDuration(earliest.Sub(now), 0), nil
	}
	expiresAt := now.Add(ttl)
	items[token] = expiresAt
	return ConcurrencyLease{Key: key, Token: token, ExpiresAt: expiresAt}, true, 0, nil
}

// Renew implements ConcurrencyLimiter.
func (m *MemoryConcurrencyLimiter) Renew(ctx context.Context, lease ConcurrencyLease, ttl time.Duration) (ConcurrencyLease, bool, error) {
	if err := ctx.Err(); err != nil {
		return ConcurrencyLease{}, false, err
	}
	if ttl <= 0 {
		return ConcurrencyLease{}, false, ErrInvalidLimits
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	items := m.leases[lease.Key]
	expiry, ok := items[lease.Token]
	if !ok || !now.Before(expiry) {
		delete(items, lease.Token)
		if len(items) == 0 {
			delete(m.leases, lease.Key)
		}
		return ConcurrencyLease{}, false, nil
	}
	lease.ExpiresAt = now.Add(ttl)
	items[lease.Token] = lease.ExpiresAt
	return lease, true, nil
}

// Release implements ConcurrencyLimiter.
func (m *MemoryConcurrencyLimiter) Release(ctx context.Context, lease ConcurrencyLease) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	items := m.leases[lease.Key]
	delete(items, lease.Token)
	if len(items) == 0 {
		delete(m.leases, lease.Key)
	}
	return nil
}

func randomLeaseToken() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("tenant: generate concurrency lease: %w", err)
	}
	return hex.EncodeToString(raw), nil
}

func maxDuration(value, minimum time.Duration) time.Duration {
	if value < minimum {
		return minimum
	}
	return value
}
