package gormstore

import (
	"errors"
	"fmt"
	"reflect"

	"github.com/getkayan/kayan/core/tenant"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// TenantColumn is the column tenant isolation filters on.
const TenantColumn = "tenant_id"

// RegisterTenantIsolation installs GORM callbacks that scope every query to
// the tenant in the context.
//
// Isolation is applied by a callback rather than by each repository method
// remembering to add a predicate. Per-method application is how leaks happen:
// the one query somebody forgets is the one that returns another customer's
// rows, and nothing fails until it does.
//
//	db, _ := gorm.Open(postgres.Open(dsn), &gorm.Config{})
//	if err := gormstore.RegisterTenantIsolation(db); err != nil { ... }
//
// Only models implementing [tenant.Scoped] are affected, so tables with no
// tenant dimension are untouched. For those that are scoped:
//
//   - reads, updates, and deletes gain a tenant_id predicate;
//   - inserts are stamped with the ambient tenant;
//   - a query with no tenant in the context fails, rather than running
//     unscoped.
//
// Use [tenant.WithSystemContext] for deliberate cross-tenant work.
func RegisterTenantIsolation(db *gorm.DB) error {
	callbacks := []struct {
		name     string
		register func(string, func(*gorm.DB)) error
	}{
		{"kayan:tenant_query", db.Callback().Query().Before("gorm:query").Register},
		{"kayan:tenant_update", db.Callback().Update().Before("gorm:update").Register},
		{"kayan:tenant_delete", db.Callback().Delete().Before("gorm:delete").Register},
		{"kayan:tenant_row", db.Callback().Row().Before("gorm:row").Register},
	}

	for _, cb := range callbacks {
		if err := cb.register(cb.name, scopeQuery); err != nil {
			return fmt.Errorf("gormstore: register %s: %w", cb.name, err)
		}
	}

	if err := db.Callback().Create().Before("gorm:create").Register("kayan:tenant_create", stampTenant); err != nil {
		return fmt.Errorf("gormstore: register kayan:tenant_create: %w", err)
	}
	return nil
}

// scopeQuery adds the tenant predicate to a statement.
func scopeQuery(db *gorm.DB) {
	if db.Statement == nil || db.Error != nil {
		return
	}
	if !isScopedModel(db) {
		return
	}

	ctx := db.Statement.Context
	if tenant.IsSystemContext(ctx) {
		return
	}

	id, ok := tenant.RequireID(ctx)
	if !ok {
		// Fail the query rather than run it unscoped. An adapter that
		// silently drops the predicate returns every tenant's rows.
		_ = db.AddError(tenant.ErrNoTenant)
		return
	}

	db.Statement.AddClause(clause.Where{
		Exprs: []clause.Expression{scopeClause(db, id)},
	})
}

// stampTenant assigns the ambient tenant to a record being inserted.
func stampTenant(db *gorm.DB) {
	if db.Statement == nil || db.Error != nil {
		return
	}
	if !isScopedModel(db) {
		return
	}

	ctx := db.Statement.Context
	if tenant.IsSystemContext(ctx) {
		// A system context has no tenant to stamp. The caller is responsible
		// for setting one, and the NOT NULL constraint catches it otherwise.
		return
	}

	id, ok := tenant.RequireID(ctx)
	if !ok {
		_ = db.AddError(tenant.ErrNoTenant)
		return
	}

	// Set the column directly so it applies to every row of a batch insert,
	// including maps and slices, which a field assignment would miss.
	db.Statement.SetColumn(TenantColumn, id)
}

// scopeClause builds the tenant predicate, qualified by table name so it stays
// unambiguous once a join is involved.
//
// The column is a constant and the tenant ID is bound, so neither reaches the
// SQL grammar.
func scopeClause(db *gorm.DB, id string) clause.Expression {
	column := clause.Column{Name: TenantColumn}
	if table := db.Statement.Table; table != "" {
		column.Table = table
	}
	return clause.Eq{Column: column, Value: id}
}

// isScopedModel reports whether the statement's model belongs to a tenant.
func isScopedModel(db *gorm.DB) bool {
	if db.Statement.Model != nil {
		if _, ok := tenant.AsScoped(db.Statement.Model); ok {
			return true
		}
	}
	if db.Statement.Dest != nil {
		if _, ok := tenant.AsScoped(db.Statement.Dest); ok {
			return true
		}
		// A destination slice carries the element type, so check that too.
		if scopedElement(db.Statement.Dest) {
			return true
		}
	}
	return false
}

// scopedElement reports whether dest is a slice whose element implements
// [tenant.Scoped].
func scopedElement(dest any) bool {
	v := reflect.ValueOf(dest)
	for v.Kind() == reflect.Ptr {
		if v.IsNil() {
			return false
		}
		v = v.Elem()
	}
	if v.Kind() != reflect.Slice {
		return false
	}

	element := v.Type().Elem()
	if element.Kind() != reflect.Ptr {
		element = reflect.PointerTo(element)
	}
	_, ok := tenant.AsScoped(reflect.New(element.Elem()).Interface())
	return ok
}

// ErrTenantIsolationNotRegistered reports that a tenant-scoped model was used
// on a database with no isolation callbacks.
var ErrTenantIsolationNotRegistered = errors.New("gormstore: tenant isolation is not registered on this database")
