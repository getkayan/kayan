package gormstore

import (
	"context"
	"errors"
	"testing"

	"github.com/getkayan/kayan/core/tenant"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

// scopedRecord belongs to a tenant.
type scopedRecord struct {
	ID       string `gorm:"primaryKey"`
	TenantId string `gorm:"column:tenant_id;index"`
	Email    string
}

func (r *scopedRecord) TenantID() string      { return r.TenantId }
func (r *scopedRecord) SetTenantID(id string) { r.TenantId = id }

func (scopedRecord) TableName() string { return "scoped_records" }

// unscopedRecord has no tenant dimension and must be left alone.
type unscopedRecord struct {
	ID   string `gorm:"primaryKey"`
	Name string
}

func (unscopedRecord) TableName() string { return "unscoped_records" }

func newTenantDB(t *testing.T) *gorm.DB {
	t.Helper()

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&scopedRecord{}, &unscopedRecord{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := RegisterTenantIsolation(db); err != nil {
		t.Fatalf("register isolation: %v", err)
	}
	return db
}

// seedTenants creates one record per tenant and returns the database.
func seedTenants(t *testing.T) *gorm.DB {
	t.Helper()
	db := newTenantDB(t)

	for _, tc := range []struct{ id, tenant, email string }{
		{"a1", "tenant-a", "alice@a.test"},
		{"a2", "tenant-a", "amir@a.test"},
		{"b1", "tenant-b", "bob@b.test"},
	} {
		ctx := tenant.WithTenantID(context.Background(), tc.tenant)
		record := &scopedRecord{ID: tc.id, Email: tc.email}
		if err := db.WithContext(ctx).Create(record).Error; err != nil {
			t.Fatalf("seed %s: %v", tc.id, err)
		}
	}
	return db
}

// TestNoCrossTenantReads is the property the previous implementation never
// had: one tenant's query must never return another's rows.
//
// It runs over every read shape rather than a single spot check, because a
// leak hides in the one method nobody tested.
func TestNoCrossTenantReads(t *testing.T) {
	db := seedTenants(t)
	ctxA := tenant.WithTenantID(context.Background(), "tenant-a")
	ctxB := tenant.WithTenantID(context.Background(), "tenant-b")

	t.Run("Find returns only the ambient tenant", func(t *testing.T) {
		var records []scopedRecord
		if err := db.WithContext(ctxA).Find(&records).Error; err != nil {
			t.Fatalf("Find: %v", err)
		}
		if len(records) != 2 {
			t.Fatalf("tenant-a sees %d records, want 2", len(records))
		}
		for _, r := range records {
			if r.TenantId != "tenant-a" {
				t.Errorf("tenant-a received a record belonging to %q", r.TenantId)
			}
		}
	})

	t.Run("First cannot reach another tenant by primary key", func(t *testing.T) {
		// b1 exists, but not for tenant-a. Knowing the ID must not be enough.
		var record scopedRecord
		err := db.WithContext(ctxA).First(&record, "id = ?", "b1").Error
		if err == nil {
			t.Fatalf("tenant-a read record b1, which belongs to %q", record.TenantId)
		}
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			t.Errorf("error = %v, want ErrRecordNotFound", err)
		}
	})

	t.Run("Count excludes other tenants", func(t *testing.T) {
		var count int64
		if err := db.WithContext(ctxB).Model(&scopedRecord{}).Count(&count).Error; err != nil {
			t.Fatalf("Count: %v", err)
		}
		if count != 1 {
			t.Errorf("tenant-b counts %d records, want 1", count)
		}
	})

	t.Run("Update cannot modify another tenant", func(t *testing.T) {
		result := db.WithContext(ctxA).
			Model(&scopedRecord{}).
			Where("id = ?", "b1").
			Update("email", "hijacked@a.test")
		if result.Error != nil {
			t.Fatalf("Update: %v", result.Error)
		}
		if result.RowsAffected != 0 {
			t.Fatalf("tenant-a modified %d rows belonging to tenant-b", result.RowsAffected)
		}

		// Confirm the record is untouched.
		var record scopedRecord
		if err := db.WithContext(ctxB).First(&record, "id = ?", "b1").Error; err != nil {
			t.Fatalf("read back: %v", err)
		}
		if record.Email != "bob@b.test" {
			t.Errorf("tenant-b record was modified: email = %q", record.Email)
		}
	})

	t.Run("Delete cannot remove another tenant", func(t *testing.T) {
		result := db.WithContext(ctxA).Delete(&scopedRecord{}, "id = ?", "b1")
		if result.Error != nil {
			t.Fatalf("Delete: %v", result.Error)
		}
		if result.RowsAffected != 0 {
			t.Fatalf("tenant-a deleted %d rows belonging to tenant-b", result.RowsAffected)
		}

		var count int64
		if err := db.WithContext(ctxB).Model(&scopedRecord{}).Count(&count).Error; err != nil {
			t.Fatalf("Count: %v", err)
		}
		if count != 1 {
			t.Error("tenant-b's record was deleted by tenant-a")
		}
	})
}

// TestIsolationFailsClosed proves a query with no tenant errors rather than
// running unscoped. Returning everything would be the worst outcome: the
// caller believes it asked a scoped question.
func TestIsolationFailsClosed(t *testing.T) {
	db := seedTenants(t)
	ctx := context.Background() // no tenant

	t.Run("read", func(t *testing.T) {
		var records []scopedRecord
		err := db.WithContext(ctx).Find(&records).Error
		if !errors.Is(err, tenant.ErrNoTenant) {
			t.Fatalf("error = %v, want ErrNoTenant; the query must not run unscoped", err)
		}
		if len(records) != 0 {
			t.Fatalf("an unscoped query returned %d records", len(records))
		}
	})

	t.Run("write", func(t *testing.T) {
		err := db.WithContext(ctx).Create(&scopedRecord{ID: "orphan", Email: "x@x.test"}).Error
		if !errors.Is(err, tenant.ErrNoTenant) {
			t.Fatalf("error = %v, want ErrNoTenant", err)
		}
	})

	t.Run("count", func(t *testing.T) {
		var count int64
		err := db.WithContext(ctx).Model(&scopedRecord{}).Count(&count).Error
		if !errors.Is(err, tenant.ErrNoTenant) {
			t.Fatalf("error = %v, want ErrNoTenant", err)
		}
	})
}

// TestSystemContextSpansTenants proves deliberate cross-tenant work is
// possible, and that it has to be asked for.
func TestSystemContextSpansTenants(t *testing.T) {
	db := seedTenants(t)
	ctx := tenant.WithSystemContext(context.Background())

	var records []scopedRecord
	if err := db.WithContext(ctx).Find(&records).Error; err != nil {
		t.Fatalf("Find: %v", err)
	}
	if len(records) != 3 {
		t.Errorf("a system context sees %d records, want all 3", len(records))
	}
}

// TestInsertsAreStamped proves a record cannot be created without a tenant,
// so nothing lands in the table unowned.
func TestInsertsAreStamped(t *testing.T) {
	db := newTenantDB(t)
	ctx := tenant.WithTenantID(context.Background(), "tenant-a")

	// The caller does not set TenantId; the callback does.
	record := &scopedRecord{ID: "new", Email: "new@a.test"}
	if err := db.WithContext(ctx).Create(record).Error; err != nil {
		t.Fatalf("Create: %v", err)
	}

	var stored scopedRecord
	if err := db.WithContext(ctx).First(&stored, "id = ?", "new").Error; err != nil {
		t.Fatalf("read back: %v", err)
	}
	if stored.TenantId != "tenant-a" {
		t.Errorf("stored tenant = %q, want tenant-a", stored.TenantId)
	}
}

// TestUnscopedModelsAreUnaffected proves isolation does not break tables with
// no tenant dimension.
func TestUnscopedModelsAreUnaffected(t *testing.T) {
	db := newTenantDB(t)
	ctx := context.Background() // deliberately no tenant

	if err := db.WithContext(ctx).Create(&unscopedRecord{ID: "u1", Name: "shared"}).Error; err != nil {
		t.Fatalf("Create: %v", err)
	}

	var records []unscopedRecord
	if err := db.WithContext(ctx).Find(&records).Error; err != nil {
		t.Fatalf("Find: %v", err)
	}
	if len(records) != 1 {
		t.Errorf("found %d unscoped records, want 1", len(records))
	}
}

// TestTenantCannotBeOverriddenByCaller proves a caller cannot write into
// another tenant by setting the field themselves.
func TestTenantCannotBeOverriddenByCaller(t *testing.T) {
	db := newTenantDB(t)
	ctx := tenant.WithTenantID(context.Background(), "tenant-a")

	// The caller claims to belong to tenant-b.
	record := &scopedRecord{ID: "forged", TenantId: "tenant-b", Email: "forged@b.test"}
	if err := db.WithContext(ctx).Create(record).Error; err != nil {
		t.Fatalf("Create: %v", err)
	}

	// It must have landed in tenant-a, the ambient tenant.
	var stored scopedRecord
	if err := db.WithContext(tenant.WithSystemContext(context.Background())).
		First(&stored, "id = ?", "forged").Error; err != nil {
		t.Fatalf("read back: %v", err)
	}
	if stored.TenantId != "tenant-a" {
		t.Errorf("record was written to tenant %q; a caller must not choose it", stored.TenantId)
	}
}
