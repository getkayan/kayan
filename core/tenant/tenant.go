// Package tenant provides multi-tenancy support for Kayan IAM.
//
// This package enables SaaS applications to isolate identities, sessions, and
// configuration per tenant. It supports multiple resolution strategies including
// domain-based, path-based, and header-based tenant identification.
//
// # Features
//
//   - Tenant isolation for identities and sessions
//   - Per-tenant configuration (password policies, session TTL, etc.)
//   - Multiple resolution strategies (domain, subdomain, path, header)
//   - TenantAware interface for automatic scoping
//   - Lifecycle hooks for tenant operations
//   - Context-based tenant propagation
//
// # Resolution Strategies
//
// Tenants can be resolved from incoming requests via:
//   - Domain: tenant1.example.com → tenant1
//   - Path: example.com/tenant1/* → tenant1
//   - Header: X-Tenant-ID: tenant1
//   - Custom: Implement the Resolver interface
//
// # Example Usage
//
//	// Store tenant in context
//	ctx = tenant.WithTenant(ctx, t)
//
//	// Retrieve tenant from context
//	t := tenant.FromContext(ctx)
//
//	// Get tenant settings
//	settings := t.Settings
//
// # TenantAware Interface
//
// Implement TenantAware on your identity model for automatic scoping:
//
//	type User struct {
//	    TenantID string
//	}
//	func (u *User) GetTenantID() string { return u.TenantID }
//	func (u *User) SetTenantID(id string) { u.TenantID = id }
package tenant

import (
	"context"
	"encoding/json"
	"net/http"
	"time"
)

// Tenant represents an isolated organizational unit.
// Developers can embed this in their own struct or use it directly.
type Tenant struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Domain    string          `json:"domain,omitempty"`   // For domain-based resolution
	Slug      string          `json:"slug,omitempty"`     // URL-friendly identifier
	Settings  json.RawMessage `json:"settings,omitempty"` // Flexible settings storage
	Metadata  json.RawMessage `json:"metadata,omitempty"` // Custom metadata
	Active    bool            `json:"active"`
	CreatedAt time.Time       `json:"created_at"`
	UpdatedAt time.Time       `json:"updated_at"`
}

// TenantSettings provides common tenant configuration options.
// Developers can extend this or use their own settings struct.
type TenantSettings struct {
	// Authentication settings
	AllowedStrategies []string      `json:"allowed_strategies,omitempty"` // e.g., ["password", "oidc", "saml"]
	SessionTTL        time.Duration `json:"session_ttl,omitempty"`
	MFARequired       bool          `json:"mfa_required,omitempty"`

	// Password policy (nil = use defaults)
	PasswordPolicy *PasswordPolicy `json:"password_policy,omitempty"`

	// Rate limiting overrides (nil = use global)
	RateLimitOverride *RateLimitConfig `json:"rate_limit_override,omitempty"`

	// Branding
	LogoURL      string `json:"logo_url,omitempty"`
	PrimaryColor string `json:"primary_color,omitempty"`

	// Custom settings for developer extension
	Custom json.RawMessage `json:"custom,omitempty"`
}

// PasswordPolicy defines password requirements per tenant.
type PasswordPolicy struct {
	MinLength        int  `json:"min_length"`
	RequireUppercase bool `json:"require_uppercase"`
	RequireLowercase bool `json:"require_lowercase"`
	RequireNumbers   bool `json:"require_numbers"`
	RequireSymbols   bool `json:"require_symbols"`
	MaxAgeDays       int  `json:"max_age_days"`  // 0 = no expiry
	HistoryCount     int  `json:"history_count"` // Prevent reuse of N previous passwords
}

// RateLimitConfig per-tenant rate limit settings.
type RateLimitConfig struct {
	LoginLimit  int           `json:"login_limit"`
	LoginWindow time.Duration `json:"login_window"`
}

// ---- Context Keys & Helpers ----

type contextKey struct{ name string }

var (
	tenantContextKey   = &contextKey{"tenant"}
	tenantIDContextKey = &contextKey{"tenant_id"}
)

// WithTenant adds a tenant to the context.
func WithTenant(ctx context.Context, t *Tenant) context.Context {
	ctx = context.WithValue(ctx, tenantContextKey, t)
	if t != nil {
		ctx = context.WithValue(ctx, tenantIDContextKey, t.ID)
	}
	return ctx
}

// FromContext extracts the tenant from context.
func FromContext(ctx context.Context) *Tenant {
	if t, ok := ctx.Value(tenantContextKey).(*Tenant); ok {
		return t
	}
	return nil
}

// IDFromContext extracts just the tenant ID from context.
func IDFromContext(ctx context.Context) string {
	if id, ok := ctx.Value(tenantIDContextKey).(string); ok {
		return id
	}
	return ""
}

// WithTenantID adds just a tenant ID to context (lightweight option).
func WithTenantID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, tenantIDContextKey, id)
}

// ---- TenantAware Interface ----

// TenantAware is an optional interface for models that support multi-tenancy.
// Implement this on your identity/user struct to enable automatic tenant scoping.
type TenantAware interface {
	GetTenantID() string
	SetTenantID(string)
}

// ---- Storage Interface ----

// Store defines the interface for tenant persistence.
// Implement this to use your own storage backend.
type Store interface {
	// Create persists a new tenant.
	Create(ctx context.Context, tenant *Tenant) error

	// Get retrieves a tenant by ID.
	Get(ctx context.Context, id string) (*Tenant, error)

	// GetByDomain retrieves a tenant by domain (for domain-based resolution).
	GetByDomain(ctx context.Context, domain string) (*Tenant, error)

	// GetBySlug retrieves a tenant by slug (for path-based resolution).
	GetBySlug(ctx context.Context, slug string) (*Tenant, error)

	// Update updates an existing tenant.
	Update(ctx context.Context, tenant *Tenant) error

	// Delete removes a tenant (soft delete recommended).
	Delete(ctx context.Context, id string) error

	// List returns all tenants with optional filtering.
	List(ctx context.Context, filter ListFilter) ([]*Tenant, error)
}

// ListFilter for tenant queries.
type ListFilter struct {
	Active *bool
	Limit  int
	Offset int
}

// ResolveInfo carries transport-agnostic data used for tenant resolution.
// HTTP callers can construct it with ResolveInfoFromRequest.
type ResolveInfo struct {
	Host       string
	Path       string
	Method     string
	RemoteAddr string
	Headers    map[string][]string
	Query      map[string][]string
	Attributes map[string]any
}

// ResolveInfoFromRequest builds ResolveInfo from an HTTP request.
func ResolveInfoFromRequest(r *http.Request) ResolveInfo {
	if r == nil {
		return ResolveInfo{}
	}

	info := ResolveInfo{
		Host:       r.Host,
		Method:     r.Method,
		RemoteAddr: r.RemoteAddr,
		Headers:    make(map[string][]string, len(r.Header)),
		Query:      make(map[string][]string),
	}
	if r.URL != nil {
		info.Path = r.URL.Path
		for key, values := range r.URL.Query() {
			info.Query[key] = append([]string(nil), values...)
		}
	}
	for key, values := range r.Header {
		info.Headers[key] = append([]string(nil), values...)
	}

	return info
}

// HeaderValue returns the first matching header value.
func (i ResolveInfo) HeaderValue(name string) string {
	for key, values := range i.Headers {
		if http.CanonicalHeaderKey(key) != http.CanonicalHeaderKey(name) {
			continue
		}
		if len(values) > 0 {
			return values[0]
		}
		return ""
	}
	return ""
}

// QueryValue returns the first matching query value.
func (i ResolveInfo) QueryValue(name string) string {
	values, ok := i.Query[name]
	if !ok || len(values) == 0 {
		return ""
	}
	return values[0]
}

// ---- Resolver Interface ----

// Resolver extracts tenant identity from incoming transport data.
// Implement custom resolvers for different multi-tenancy patterns.
type Resolver interface {
	// Resolve extracts the tenant identifier from the resolution input.
	// Returns empty string if no tenant can be determined.
	Resolve(ctx context.Context, info ResolveInfo) (string, error)
}

// ResolverFunc is an adapter to allow ordinary functions as Resolvers.
type ResolverFunc func(ctx context.Context, info ResolveInfo) (string, error)

func (f ResolverFunc) Resolve(ctx context.Context, info ResolveInfo) (string, error) {
	return f(ctx, info)
}

// ---- Hooks ----

// Hooks provides extension points for tenant lifecycle events.
type Hooks struct {
	// BeforeCreate is called before creating a tenant.
	// Return error to prevent creation.
	BeforeCreate func(ctx context.Context, tenant *Tenant) error

	// AfterCreate is called after a tenant is created.
	AfterCreate func(ctx context.Context, tenant *Tenant) error

	// BeforeResolve is called before tenant resolution.
	// Return a tenant ID to skip normal resolution.
	BeforeResolve func(ctx context.Context, info ResolveInfo) (string, bool)

	// AfterResolve is called after successful tenant resolution.
	AfterResolve func(ctx context.Context, tenant *Tenant, info ResolveInfo)

	// OnResolveFailed is called when tenant resolution fails.
	OnResolveFailed func(ctx context.Context, info ResolveInfo, err error)

	// ValidateTenant allows custom tenant validation.
	// Return error to reject the tenant (e.g., inactive, suspended).
	ValidateTenant func(ctx context.Context, tenant *Tenant) error
}

// DefaultPasswordPolicy returns sensible defaults.
func DefaultPasswordPolicy() *PasswordPolicy {
	return &PasswordPolicy{
		MinLength:        8,
		RequireUppercase: true,
		RequireLowercase: true,
		RequireNumbers:   true,
		RequireSymbols:   false,
		MaxAgeDays:       0,
		HistoryCount:     0,
	}
}
