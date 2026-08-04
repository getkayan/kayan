package gormstore

import (
	"context"
	"testing"

	scim "github.com/getkayan/kayan/kayan-scim"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func newTestRepo(t *testing.T) *ScimRepository {
	t.Helper()

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	type user struct {
		ID    string `gorm:"primaryKey"`
		Email string
	}
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
