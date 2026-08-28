package gormstore

import (
	"context"
	"fmt"
	"strings"
	"testing"

	scim "github.com/getkayan/kayan/kayan-scim"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

// user is the caller-owned identity model these tests map onto. GetID and
// SetID are what let the mapper carry a resource id through, without which
// every created user lands with an empty primary key.
type user struct {
	ID    string `gorm:"primaryKey"`
	Email string
}

func (u *user) GetID() any  { return u.ID }
func (u *user) SetID(v any) { u.ID, _ = v.(string) }

func newTestRepo(t *testing.T) *ScimRepository {
	t.Helper()

	// A bare ":memory:" DSN gives every pooled connection its own empty
	// database, so anything concurrent finds no tables. A named shared-cache
	// database is one database; capping the pool at a single connection keeps
	// SQLite's writer lock from turning contention into SQLITE_BUSY.
	//
	// Capping the pool does not weaken a concurrency test: statements from
	// different goroutines still interleave on that connection, so a
	// read-then-write would still race.
	dsn := fmt.Sprintf("file:%s?mode=memory&cache=shared", strings.ReplaceAll(t.Name(), "/", "_"))
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	pool, err := db.DB()
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	pool.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = pool.Close() })
	if err := db.AutoMigrate(&user{}); err != nil {
		t.Fatalf("migrate user model: %v", err)
	}

	mapper := scim.NewMapper(
		func() any { return &user{} },
		scim.MapperConfig{FieldMappings: map[string]string{"userName": "Email"}},
	)

	repo := NewScimRepository(db, mapper)
	if err := repo.AutoMigrate(); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return repo
}

// TestUnfilteredListReturnsEverything is the baseline the filter tests narrow
// from. Filtering itself is covered in filter_test.go.
func TestUnfilteredListReturnsEverything(t *testing.T) {
	ctx := context.Background()
	repo := newTestRepo(t)

	if _, _, err := repo.ListScimGroups(ctx, "", 1, 10); err != nil {
		t.Fatalf("unfiltered list failed: %v", err)
	}
}
