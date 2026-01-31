package tenant

import (
	"context"
	"fmt"
	"net/http"
	"strings"
)

// ---- Built-in Resolver Implementations ----

// SubdomainResolver extracts tenant from subdomain.
// Example: tenant1.example.com → "tenant1"
type SubdomainResolver struct {
	// BaseDomain is the root domain (e.g., "example.com")
	BaseDomain string

	// Position is which subdomain part to use (0 = first, -1 = last before base)
	Position int
}

func NewSubdomainResolver(baseDomain string) *SubdomainResolver {
	return &SubdomainResolver{
		BaseDomain: baseDomain,
		Position:   0,
	}
}

func (r *SubdomainResolver) Resolve(ctx context.Context, req *http.Request) (string, error) {
	host := req.Host
	// Remove port if present
	if idx := strings.Index(host, ":"); idx != -1 {
		host = host[:idx]
	}

	// Check if it's the base domain
	if host == r.BaseDomain || host == "www."+r.BaseDomain {
		return "", nil // No tenant for root domain
	}

	// Extract subdomain
	if !strings.HasSuffix(host, "."+r.BaseDomain) {
		return "", nil
	}

	subdomain := strings.TrimSuffix(host, "."+r.BaseDomain)
	parts := strings.Split(subdomain, ".")

	if len(parts) == 0 {
		return "", nil
	}

	if r.Position >= 0 && r.Position < len(parts) {
		return parts[r.Position], nil
	}
	if r.Position == -1 {
		return parts[len(parts)-1], nil
	}

	return parts[0], nil
}

// HeaderResolver extracts tenant from a request header.
// Example: X-Tenant-ID: tenant1
type HeaderResolver struct {
	// HeaderName is the header to read (default: X-Tenant-ID)
	HeaderName string
}

func NewHeaderResolver(headerName string) *HeaderResolver {
	if headerName == "" {
		headerName = "X-Tenant-ID"
	}
	return &HeaderResolver{HeaderName: headerName}
}

func (r *HeaderResolver) Resolve(ctx context.Context, req *http.Request) (string, error) {
	return req.Header.Get(r.HeaderName), nil
}

// PathResolver extracts tenant from URL path.
// Example: /api/v1/tenants/{tenant}/users → "tenant1"
type PathResolver struct {
	// PathPrefix is the path segment before the tenant (e.g., "/api/v1/tenants/")
	PathPrefix string

	// Position is the path segment index (0-based) to use as tenant.
	// If PathPrefix is set, this is relative to after the prefix.
	Position int
}

func NewPathResolver(prefix string, position int) *PathResolver {
	return &PathResolver{
		PathPrefix: prefix,
		Position:   position,
	}
}

func (r *PathResolver) Resolve(ctx context.Context, req *http.Request) (string, error) {
	path := req.URL.Path

	if r.PathPrefix != "" {
		if !strings.HasPrefix(path, r.PathPrefix) {
			return "", nil
		}
		path = strings.TrimPrefix(path, r.PathPrefix)
	}

	// Remove leading slash and split
	path = strings.TrimPrefix(path, "/")
	parts := strings.Split(path, "/")

	if r.Position >= 0 && r.Position < len(parts) {
		return parts[r.Position], nil
	}

	return "", nil
}

// QueryResolver extracts tenant from query parameter.
// Example: ?tenant=tenant1
type QueryResolver struct {
	// ParamName is the query parameter name (default: tenant)
	ParamName string
}

func NewQueryResolver(paramName string) *QueryResolver {
	if paramName == "" {
		paramName = "tenant"
	}
	return &QueryResolver{ParamName: paramName}
}

func (r *QueryResolver) Resolve(ctx context.Context, req *http.Request) (string, error) {
	return req.URL.Query().Get(r.ParamName), nil
}

// JWTClaimResolver extracts tenant from a JWT claim.
// Requires the JWT to be parsed and stored in context first.
type JWTClaimResolver struct {
	// ClaimName is the JWT claim containing the tenant ID (default: tenant_id)
	ClaimName string

	// ClaimsContextKey is the context key where claims are stored
	ClaimsContextKey any
}

func NewJWTClaimResolver(claimName string, claimsKey any) *JWTClaimResolver {
	if claimName == "" {
		claimName = "tenant_id"
	}
	return &JWTClaimResolver{
		ClaimName:        claimName,
		ClaimsContextKey: claimsKey,
	}
}

func (r *JWTClaimResolver) Resolve(ctx context.Context, req *http.Request) (string, error) {
	claims, ok := ctx.Value(r.ClaimsContextKey).(map[string]any)
	if !ok {
		return "", nil
	}

	if tenantID, ok := claims[r.ClaimName].(string); ok {
		return tenantID, nil
	}

	return "", nil
}

// ChainResolver tries multiple resolvers in order until one succeeds.
type ChainResolver struct {
	Resolvers []Resolver
}

func NewChainResolver(resolvers ...Resolver) *ChainResolver {
	return &ChainResolver{Resolvers: resolvers}
}

func (r *ChainResolver) Resolve(ctx context.Context, req *http.Request) (string, error) {
	for _, resolver := range r.Resolvers {
		tenantID, err := resolver.Resolve(ctx, req)
		if err != nil {
			return "", err
		}
		if tenantID != "" {
			return tenantID, nil
		}
	}
	return "", nil
}

// StaticResolver always returns the same tenant ID.
// Useful for single-tenant deployments or testing.
type StaticResolver struct {
	TenantID string
}

func NewStaticResolver(tenantID string) *StaticResolver {
	return &StaticResolver{TenantID: tenantID}
}

func (r *StaticResolver) Resolve(ctx context.Context, req *http.Request) (string, error) {
	return r.TenantID, nil
}

// CacheResolver wraps another resolver with caching.
// The cache key is derived from the request (configurable).
type CacheResolver struct {
	Inner   Resolver
	Cache   Cache
	KeyFunc func(*http.Request) string
	TTL     int // seconds
}

// Cache interface for resolver caching.
type Cache interface {
	Get(ctx context.Context, key string) (string, bool)
	Set(ctx context.Context, key string, value string, ttlSeconds int) error
}

func NewCacheResolver(inner Resolver, cache Cache, keyFunc func(*http.Request) string) *CacheResolver {
	if keyFunc == nil {
		keyFunc = func(r *http.Request) string { return r.Host }
	}
	return &CacheResolver{
		Inner:   inner,
		Cache:   cache,
		KeyFunc: keyFunc,
		TTL:     300, // 5 minutes default
	}
}

func (r *CacheResolver) Resolve(ctx context.Context, req *http.Request) (string, error) {
	key := r.KeyFunc(req)

	// Check cache
	if cached, ok := r.Cache.Get(ctx, key); ok {
		return cached, nil
	}

	// Resolve
	tenantID, err := r.Inner.Resolve(ctx, req)
	if err != nil {
		return "", err
	}

	// Cache result
	if tenantID != "" {
		r.Cache.Set(ctx, key, tenantID, r.TTL)
	}

	return tenantID, nil
}

// ValidatingResolver wraps a resolver and validates the resolved tenant exists.
type ValidatingResolver struct {
	Inner Resolver
	Store Store
}

func NewValidatingResolver(inner Resolver, store Store) *ValidatingResolver {
	return &ValidatingResolver{
		Inner: inner,
		Store: store,
	}
}

func (r *ValidatingResolver) Resolve(ctx context.Context, req *http.Request) (string, error) {
	tenantID, err := r.Inner.Resolve(ctx, req)
	if err != nil {
		return "", err
	}

	if tenantID == "" {
		return "", nil
	}

	// Validate tenant exists
	tenant, err := r.Store.Get(ctx, tenantID)
	if err != nil {
		return "", fmt.Errorf("tenant not found: %s", tenantID)
	}

	if !tenant.Active {
		return "", fmt.Errorf("tenant is inactive: %s", tenantID)
	}

	return tenantID, nil
}
