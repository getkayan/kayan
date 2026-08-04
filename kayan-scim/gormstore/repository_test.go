package gormstore

import (
	"context"
	"errors"
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

// TestListRejectsUnsupportedFilter guards against the store silently returning
// every resource for a filtered request. Okta and Entra ID both list users by
// filter; over-returning would hand back the whole directory.
func TestListRejectsUnsupportedFilter(t *testing.T) {
	ctx := context.Background()
	repo := newTestRepo(t)

	t.Run("users", func(t *testing.T) {
		_, _, err := repo.ListScimUsers(ctx, `userName eq "someone"`, 1, 10)
		if !errors.Is(err, scim.ErrFilterUnsupported) {
			t.Fatalf("error = %v, want ErrFilterUnsupported", err)
		}
	})

	t.Run("groups", func(t *testing.T) {
		_, _, err := repo.ListScimGroups(ctx, `displayName eq "admins"`, 1, 10)
		if !errors.Is(err, scim.ErrFilterUnsupported) {
			t.Fatalf("error = %v, want ErrFilterUnsupported", err)
		}
	})

	t.Run("empty filter still lists", func(t *testing.T) {
		if _, _, err := repo.ListScimGroups(ctx, "", 1, 10); err != nil {
			t.Fatalf("unfiltered list failed: %v", err)
		}
	})
}
