package tenant

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// These are the primitives every storage adapter builds isolation on, and
// until now none of them had a test. Both isolation bugs found in kayan-gorm
// -- core models that never mapped tenant_id, and a session repository
// querying the unscoped core type -- were failures to use these correctly, so
// the contract they promise is worth pinning here rather than only at each
// call site.

type scopedRecord struct{ tenant string }

func (r *scopedRecord) TenantID() string      { return r.tenant }
func (r *scopedRecord) SetTenantID(id string) { r.tenant = id }

// legacyRecord implements the deprecated TenantAware shape.
type legacyRecord struct{ tenant string }

func (r *legacyRecord) GetTenantID() string   { return r.tenant }
func (r *legacyRecord) SetTenantID(id string) { r.tenant = id }

type unscopedRecord struct{ Name string }

// TestRequireIDFailsClosed is the central promise: no tenant in context is an
// error, never an unscoped read.
//
// The signature invites the opposite mistake. RequireID returns (string, bool)
// and an adapter that reads only the string gets "" -- which, dropped into a
// query, matches every row stamped with an empty tenant rather than failing.
// The bool is the whole guarantee.
func TestRequireIDFailsClosed(t *testing.T) {
	id, ok := RequireID(context.Background())
	if ok {
		t.Error("RequireID reported success with no tenant in context")
	}
	if id != "" {
		t.Errorf("id = %q, want empty", id)
	}
}

func TestRequireIDReturnsTheAmbientTenant(t *testing.T) {
	id, ok := RequireID(WithTenantID(context.Background(), "tenant-a"))
	if !ok {
		t.Fatal("RequireID refused a context carrying a tenant")
	}
	if id != "tenant-a" {
		t.Errorf("id = %q, want tenant-a", id)
	}
}

// TestRequireIDInSystemContext covers the deliberate cross-tenant case, and
// the ambiguity it creates.
//
// A system context returns ("", true): permitted, but with no id to scope by.
// That is the same empty string a missing tenant produces, distinguished only
// by the bool -- so an adapter that adds `WHERE tenant_id = ?` with the
// returned value would scope a deliberately cross-tenant query to the empty
// tenant and quietly return nothing. The contract is that true plus an empty
// id means add no predicate at all.
func TestRequireIDInSystemContext(t *testing.T) {
	ctx := WithSystemContext(context.Background())

	id, ok := RequireID(ctx)
	if !ok {
		t.Fatal("RequireID refused a system context")
	}
	if id != "" {
		t.Errorf("id = %q, want empty: a system context spans tenants and has none to scope by", id)
	}
}

// TestSystemContextOverridesAnAmbientTenant pins the precedence. A background
// job that sets a system context must span tenants even when it inherited a
// request context that carried one.
func TestSystemContextOverridesAnAmbientTenant(t *testing.T) {
	ctx := WithSystemContext(WithTenantID(context.Background(), "tenant-a"))

	id, ok := RequireID(ctx)
	if !ok || id != "" {
		t.Errorf("RequireID = (%q, %v), want (\"\", true)", id, ok)
	}
	if err := Verify(ctx, &scopedRecord{tenant: "tenant-b"}); err != nil {
		t.Errorf("Verify refused another tenant's record in a system context: %v", err)
	}
}

// TestIsSystemContextDefaultsToFalse keeps the marker from being something a
// context acquires by accident. Everything is scoped unless it says otherwise.
func TestIsSystemContextDefaultsToFalse(t *testing.T) {
	if IsSystemContext(context.Background()) {
		t.Error("a plain context reported itself as a system context")
	}
	if IsSystemContext(WithTenantID(context.Background(), "tenant-a")) {
		t.Error("setting a tenant marked the context as system")
	}
	if !IsSystemContext(WithSystemContext(context.Background())) {
		t.Error("WithSystemContext did not mark the context")
	}
}

// TestVerifyRejectsForeignRecords covers the read-side check, for adapters
// that cannot push a predicate into the query -- a key-value store or a cache
// -- and must enforce isolation on the way out instead.
func TestVerifyRejectsForeignRecords(t *testing.T) {
	ctx := WithTenantID(context.Background(), "tenant-a")

	if err := Verify(ctx, &scopedRecord{tenant: "tenant-a"}); err != nil {
		t.Errorf("Verify refused a record belonging to the ambient tenant: %v", err)
	}
	if err := Verify(ctx, &scopedRecord{tenant: "tenant-b"}); !errors.Is(err, ErrCrossTenant) {
		t.Errorf("error = %v, want ErrCrossTenant", err)
	}
	// A record with no tenant is not owned by the caller either. Treating an
	// unstamped row as belonging to whoever asks is how a record written
	// before isolation existed becomes readable by every tenant.
	if err := Verify(ctx, &scopedRecord{}); !errors.Is(err, ErrCrossTenant) {
		t.Errorf("error = %v for an unstamped record, want ErrCrossTenant", err)
	}
}

// TestVerifyFailsClosedWithoutATenant is the same promise as RequireID's, on
// the read path.
func TestVerifyFailsClosedWithoutATenant(t *testing.T) {
	err := Verify(context.Background(), &scopedRecord{tenant: "tenant-a"})
	if !errors.Is(err, ErrNoTenant) {
		t.Errorf("error = %v, want ErrNoTenant", err)
	}
}

// TestVerifyDoesNotDiscloseTheOwningTenant pins a deliberate omission. Naming
// the owner in the error would confirm the record exists and say who has it,
// which is a cross-tenant disclosure through the error channel.
func TestVerifyDoesNotDiscloseTheOwningTenant(t *testing.T) {
	ctx := WithTenantID(context.Background(), "tenant-a")
	err := Verify(ctx, &scopedRecord{tenant: "acme-corp"})
	if err == nil {
		t.Fatal("Verify accepted a foreign record")
	}
	if strings.Contains(err.Error(), "acme-corp") {
		t.Errorf("the error names the owning tenant: %v", err)
	}
}

// TestAsScopedRecognisesBothShapes covers the adapter, including the negative
// case that decides whether a model is isolated at all.
//
// This is the check kayan-gorm's callback keys off: a model AsScoped rejects
// gets no tenant predicate. Reporting true for something that cannot carry a
// tenant would be worse than reporting false, because the query would then be
// built as though it were scoped.
func TestAsScopedRecognisesBothShapes(t *testing.T) {
	scoped, ok := AsScoped(&scopedRecord{tenant: "tenant-a"})
	if !ok {
		t.Fatal("AsScoped rejected a Scoped implementation")
	}
	if scoped.TenantID() != "tenant-a" {
		t.Errorf("TenantID = %q, want tenant-a", scoped.TenantID())
	}

	legacy, ok := AsScoped(&legacyRecord{tenant: "tenant-b"})
	if !ok {
		t.Fatal("AsScoped rejected a TenantAware implementation")
	}
	if legacy.TenantID() != "tenant-b" {
		t.Errorf("TenantID = %q, want tenant-b", legacy.TenantID())
	}
	// The adapter must write through to the underlying value, or a stamped
	// insert would silently lose its tenant.
	legacy.SetTenantID("tenant-c")
	if legacy.TenantID() != "tenant-c" {
		t.Error("SetTenantID through the adapter did not reach the record")
	}

	if _, ok := AsScoped(&unscopedRecord{Name: "x"}); ok {
		t.Error("AsScoped accepted a model with no tenant dimension")
	}
	if _, ok := AsScoped(nil); ok {
		t.Error("AsScoped accepted nil")
	}
}

// TestScopedAdapterStampsThroughToTheRecord covers the write path for the
// legacy shape specifically, since an insert that loses its tenant produces a
// row no tenant can read back.
func TestScopedAdapterStampsThroughToTheRecord(t *testing.T) {
	record := &legacyRecord{}
	scoped, ok := AsScoped(record)
	if !ok {
		t.Fatal("AsScoped rejected the record")
	}
	scoped.SetTenantID("tenant-a")
	if record.tenant != "tenant-a" {
		t.Errorf("the underlying record has tenant %q, want tenant-a", record.tenant)
	}
}
