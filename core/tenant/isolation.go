package tenant

import (
	"context"
	"errors"
)

// Errors reported by tenant isolation.
var (
	// ErrNoTenant reports that a tenant-scoped operation was attempted with no
	// tenant in the context.
	//
	// Storage adapters must treat this as a failure rather than as "return
	// everything": silently widening a scoped query is how one customer's data
	// reaches another.
	ErrNoTenant = errors.New("tenant: no tenant in context")

	// ErrCrossTenant reports an attempt to reach a record belonging to another
	// tenant.
	ErrCrossTenant = errors.New("tenant: record belongs to a different tenant")
)

// Scoper applies tenant isolation to a storage query.
//
// Kayan does not dictate how tenants are separated. Row-level (a tenant_id
// column), schema-per-tenant, and database-per-tenant are all valid, and which
// one fits depends on the deployment — so the decision belongs to the storage
// adapter rather than to this package.
//
// The query type is opaque: a GORM adapter receives a *gorm.DB, a Mongo
// adapter a filter document. Implementations assert the type they expect.
//
//	func (s *mongoScoper) Scope(ctx context.Context, q any) (any, error) {
//	    filter, ok := q.(bson.M)
//	    if !ok {
//	        return nil, fmt.Errorf("expected bson.M, got %T", q)
//	    }
//	    id, ok := tenant.RequireID(ctx)
//	    if !ok {
//	        return nil, tenant.ErrNoTenant
//	    }
//	    filter["tenant_id"] = id
//	    return filter, nil
//	}
type Scoper interface {
	Scope(ctx context.Context, query any) (any, error)
}

// ScoperFunc adapts a function to [Scoper].
type ScoperFunc func(ctx context.Context, query any) (any, error)

// Scope implements [Scoper].
func (f ScoperFunc) Scope(ctx context.Context, query any) (any, error) {
	return f(ctx, query)
}

// systemContextKey marks a context as permitted to cross tenant boundaries.
type systemContextKey struct{}

// WithSystemContext marks ctx as a deliberate cross-tenant operation.
//
// Isolation fails closed, so a query with no ambient tenant is an error rather
// than an unscoped read. Genuine cross-tenant work — a platform administrator
// listing every tenant, a background job sweeping expired tokens — needs a way
// to say so, and it should be explicit and greppable rather than implied by an
// absent value.
//
//	// Deliberately spans tenants: this job expires tokens everywhere.
//	ctx = tenant.WithSystemContext(ctx)
func WithSystemContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, systemContextKey{}, true)
}

// IsSystemContext reports whether ctx was marked by [WithSystemContext].
func IsSystemContext(ctx context.Context) bool {
	system, _ := ctx.Value(systemContextKey{}).(bool)
	return system
}

// RequireID returns the ambient tenant ID.
//
// The second result is false when there is no tenant and the context was not
// marked as a system context. A storage adapter that gets false must fail the
// operation, not proceed unscoped.
//
//	id, ok := tenant.RequireID(ctx)
//	if !ok {
//	    return tenant.ErrNoTenant
//	}
//	db = db.Where("tenant_id = ?", id)
func RequireID(ctx context.Context) (string, bool) {
	if IsSystemContext(ctx) {
		// A system context deliberately spans tenants, so there is no ID to
		// scope by and the caller should not add a predicate.
		return "", true
	}

	id := IDFromContext(ctx)
	if id == "" {
		return "", false
	}
	return id, true
}

// Scoped is implemented by records that belong to a tenant.
//
// A storage adapter uses it to stamp the tenant on write and to verify it on
// read, so a record cannot be created without one or returned across a
// boundary.
type Scoped interface {
	// TenantID returns the tenant this record belongs to.
	TenantID() string

	// SetTenantID assigns the tenant. Adapters call it before insert.
	SetTenantID(id string)
}

// Verify reports whether a record may be returned in the current context.
//
// It exists so an adapter that cannot push isolation into the query — a
// key-value store, a cache — can still enforce it on the way out.
func Verify(ctx context.Context, record Scoped) error {
	if IsSystemContext(ctx) {
		return nil
	}

	want := IDFromContext(ctx)
	if want == "" {
		return ErrNoTenant
	}
	if record.TenantID() != want {
		// The error deliberately does not name the record's tenant: that would
		// confirm the record exists and disclose which tenant owns it.
		return ErrCrossTenant
	}
	return nil
}
