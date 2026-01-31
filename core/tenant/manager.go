package tenant

import (
	"context"
	"fmt"
	"net/http"
)

// Manager coordinates tenant resolution, validation, and lifecycle.
// It provides a high-level API while allowing full customization via hooks.
type Manager struct {
	store    Store
	resolver Resolver
	hooks    Hooks

	// DefaultTenantID is used when no tenant is resolved and RequireTenant is false.
	DefaultTenantID string

	// RequireTenant determines if requests without a tenant should fail.
	RequireTenant bool

	// LoadFullTenant determines if the full tenant object should be loaded into context.
	// If false, only the tenant ID is stored (more lightweight).
	LoadFullTenant bool
}

// ManagerOption configures the Manager.
type ManagerOption func(*Manager)

// NewManager creates a new tenant manager with the given store and resolver.
func NewManager(store Store, resolver Resolver, opts ...ManagerOption) *Manager {
	m := &Manager{
		store:          store,
		resolver:       resolver,
		RequireTenant:  true,
		LoadFullTenant: true,
	}

	for _, opt := range opts {
		opt(m)
	}

	return m
}

// WithHooks sets lifecycle hooks.
func WithHooks(hooks Hooks) ManagerOption {
	return func(m *Manager) {
		m.hooks = hooks
	}
}

// WithDefaultTenant sets a fallback tenant ID.
func WithDefaultTenant(id string) ManagerOption {
	return func(m *Manager) {
		m.DefaultTenantID = id
		m.RequireTenant = false
	}
}

// WithOptionalTenant makes tenant resolution optional.
func WithOptionalTenant() ManagerOption {
	return func(m *Manager) {
		m.RequireTenant = false
	}
}

// WithLightweight only stores tenant ID in context, not full object.
func WithLightweight() ManagerOption {
	return func(m *Manager) {
		m.LoadFullTenant = false
	}
}

// ResolveFromRequest resolves and validates the tenant from an HTTP request.
// Returns the tenant and a new context with tenant info.
func (m *Manager) ResolveFromRequest(ctx context.Context, r *http.Request) (*Tenant, context.Context, error) {
	var tenantID string

	// 1. Check BeforeResolve hook
	if m.hooks.BeforeResolve != nil {
		if id, handled := m.hooks.BeforeResolve(ctx, r); handled {
			tenantID = id
		}
	}

	// 2. Use resolver if not handled by hook
	if tenantID == "" {
		var err error
		tenantID, err = m.resolver.Resolve(ctx, r)
		if err != nil {
			if m.hooks.OnResolveFailed != nil {
				m.hooks.OnResolveFailed(ctx, r, err)
			}
			return nil, ctx, fmt.Errorf("tenant resolution failed: %w", err)
		}
	}

	// 3. Apply default if no tenant resolved
	if tenantID == "" {
		tenantID = m.DefaultTenantID
	}

	// 4. Check if tenant is required
	if tenantID == "" {
		if m.RequireTenant {
			err := fmt.Errorf("tenant required but not found")
			if m.hooks.OnResolveFailed != nil {
				m.hooks.OnResolveFailed(ctx, r, err)
			}
			return nil, ctx, err
		}
		return nil, ctx, nil
	}

	// 5. Load tenant from store
	tenant, err := m.store.Get(ctx, tenantID)
	if err != nil {
		if m.hooks.OnResolveFailed != nil {
			m.hooks.OnResolveFailed(ctx, r, err)
		}
		return nil, ctx, fmt.Errorf("tenant not found: %s", tenantID)
	}

	// 6. Validate tenant
	if m.hooks.ValidateTenant != nil {
		if err := m.hooks.ValidateTenant(ctx, tenant); err != nil {
			return nil, ctx, err
		}
	} else if !tenant.Active {
		return nil, ctx, fmt.Errorf("tenant is inactive: %s", tenantID)
	}

	// 7. Add to context
	if m.LoadFullTenant {
		ctx = WithTenant(ctx, tenant)
	} else {
		ctx = WithTenantID(ctx, tenantID)
	}

	// 8. Call AfterResolve hook
	if m.hooks.AfterResolve != nil {
		m.hooks.AfterResolve(ctx, tenant, r)
	}

	return tenant, ctx, nil
}

// Create creates a new tenant.
func (m *Manager) Create(ctx context.Context, tenant *Tenant) error {
	if m.hooks.BeforeCreate != nil {
		if err := m.hooks.BeforeCreate(ctx, tenant); err != nil {
			return err
		}
	}

	if err := m.store.Create(ctx, tenant); err != nil {
		return err
	}

	if m.hooks.AfterCreate != nil {
		return m.hooks.AfterCreate(ctx, tenant)
	}

	return nil
}

// Get retrieves a tenant by ID.
func (m *Manager) Get(ctx context.Context, id string) (*Tenant, error) {
	return m.store.Get(ctx, id)
}

// GetByDomain retrieves a tenant by domain.
func (m *Manager) GetByDomain(ctx context.Context, domain string) (*Tenant, error) {
	return m.store.GetByDomain(ctx, domain)
}

// Update updates a tenant.
func (m *Manager) Update(ctx context.Context, tenant *Tenant) error {
	return m.store.Update(ctx, tenant)
}

// Delete removes a tenant.
func (m *Manager) Delete(ctx context.Context, id string) error {
	return m.store.Delete(ctx, id)
}

// List returns tenants matching the filter.
func (m *Manager) List(ctx context.Context, filter ListFilter) ([]*Tenant, error) {
	return m.store.List(ctx, filter)
}

// ---- HTTP Middleware Factory ----

// HTTPMiddleware returns an http.Handler middleware that resolves tenants.
func (m *Manager) HTTPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, ctx, err := m.ResolveFromRequest(r.Context(), r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// HTTPMiddlewareFunc returns a middleware function compatible with most routers.
func (m *Manager) HTTPMiddlewareFunc(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, ctx, err := m.ResolveFromRequest(r.Context(), r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		next(w, r.WithContext(ctx))
	}
}

// ---- Scoped Storage Helper ----

// ScopedStore wraps a tenant store to automatically scope operations to a tenant.
type ScopedStore struct {
	inner    Store
	tenantID string
}

// NewScopedStore creates a store scoped to a specific tenant.
func NewScopedStore(inner Store, tenantID string) *ScopedStore {
	return &ScopedStore{inner: inner, tenantID: tenantID}
}

// TenantID returns the scoped tenant ID.
func (s *ScopedStore) TenantID() string {
	return s.tenantID
}
