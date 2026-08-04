package gormstore

import (
	"context"
	"testing"

	scim "github.com/getkayan/kayan/kayan-scim"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

// filterUser is the caller's identity model for these tests.
type filterUser struct {
	ID     string `gorm:"primaryKey"`
	Email  string
	Name   string
	Active bool
}

func newFilterRepo(t *testing.T) *ScimRepository {
	t.Helper()

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&filterUser{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	seed := []filterUser{
		{ID: "1", Email: "alice@example.test", Name: "Alice", Active: true},
		{ID: "2", Email: "bob@example.test", Name: "Bob", Active: true},
		{ID: "3", Email: "carol@other.test", Name: "Carol", Active: false},
	}
	for _, u := range seed {
		if err := db.Create(&u).Error; err != nil {
			t.Fatalf("seed: %v", err)
		}
	}

	mapper := scim.NewMapper(
		func() any { return &filterUser{} },
		scim.MapperConfig{FieldMappings: map[string]string{
			"userName":    "Email",
			"displayName": "Name",
			"active":      "Active",
			"id":          "ID",
		}},
	)

	repo := NewScimRepository(db, mapper)
	if err := repo.AutoMigrate(); err != nil {
		t.Fatalf("migrate scim tables: %v", err)
	}
	return repo
}

// TestFilterNarrowsResults is the property the previous implementation lacked:
// a filtered list must return a subset, not the whole table.
func TestFilterNarrowsResults(t *testing.T) {
	ctx := context.Background()
	repo := newFilterRepo(t)

	tests := []struct {
		filter string
		want   int
	}{
		{`userName eq "alice@example.test"`, 1},
		{`userName co "example.test"`, 2},
		{`userName sw "bob"`, 1},
		{`userName ew "other.test"`, 1},
		{`displayName eq "Carol"`, 1},
		{`active eq true`, 2},
		{`active eq false`, 1},
		{`userName co "example.test" and active eq true`, 2},
		{`displayName eq "Alice" or displayName eq "Bob"`, 2},
		{`not (active eq true)`, 1},
		{`displayName pr`, 3},
		{`userName eq "nobody@example.test"`, 0},
	}

	for _, tc := range tests {
		t.Run(tc.filter, func(t *testing.T) {
			users, total, err := repo.ListScimUsers(ctx, tc.filter, 1, 100)
			if err != nil {
				t.Fatalf("ListScimUsers: %v", err)
			}
			if len(users) != tc.want {
				t.Errorf("returned %d users, want %d", len(users), tc.want)
			}
			// The total must reflect matches, not the size of the table.
			if total != tc.want {
				t.Errorf("total = %d, want %d", total, tc.want)
			}
		})
	}
}

// TestFilterEscapesLikeWildcards proves a wildcard in a value cannot widen the
// query. Without escaping, `co "%"` matches every row — a filtered request
// silently returning the entire directory.
func TestFilterEscapesLikeWildcards(t *testing.T) {
	ctx := context.Background()
	repo := newFilterRepo(t)

	for _, filter := range []string{
		`userName co "%"`,
		`userName co "_"`,
		`userName sw "%"`,
	} {
		t.Run(filter, func(t *testing.T) {
			users, _, err := repo.ListScimUsers(ctx, filter, 1, 100)
			if err != nil {
				t.Fatalf("ListScimUsers: %v", err)
			}
			if len(users) == 3 {
				t.Fatalf("filter %q matched every user; LIKE wildcards were not escaped", filter)
			}
		})
	}
}

// TestUnmappedAttributeIsRefused proves a filter cannot reach a column the
// deployment did not expose.
func TestUnmappedAttributeIsRefused(t *testing.T) {
	ctx := context.Background()
	repo := newFilterRepo(t)

	for _, filter := range []string{
		`password eq "secret"`,
		`internalNotes co "x"`,
	} {
		t.Run(filter, func(t *testing.T) {
			if _, _, err := repo.ListScimUsers(ctx, filter, 1, 100); err == nil {
				t.Fatalf("filter on an unmapped attribute was accepted: %q", filter)
			}
		})
	}
}

// TestMalformedFilterIsRefused proves a bad filter errors rather than being
// ignored, which would return everything.
func TestMalformedFilterIsRefused(t *testing.T) {
	ctx := context.Background()
	repo := newFilterRepo(t)

	for _, filter := range []string{
		`userName eq`,
		`userName xx "a"`,
		`(userName eq "a"`,
	} {
		t.Run(filter, func(t *testing.T) {
			if _, _, err := repo.ListScimUsers(ctx, filter, 1, 100); err == nil {
				t.Fatalf("malformed filter was accepted: %q", filter)
			}
		})
	}
}

// TestFilterCannotInjectSQL drives values that would break a query built by
// string concatenation.
func TestFilterCannotInjectSQL(t *testing.T) {
	ctx := context.Background()
	repo := newFilterRepo(t)

	payloads := []string{
		`userName eq "' OR '1'='1"`,
		`userName eq "'; DROP TABLE filter_users; --"`,
		`userName eq "\" OR \"\"=\""`,
	}

	for _, filter := range payloads {
		t.Run(filter, func(t *testing.T) {
			users, _, err := repo.ListScimUsers(ctx, filter, 1, 100)
			if err != nil {
				// Refusing to parse is a fine outcome.
				return
			}
			if len(users) != 0 {
				t.Fatalf("injection payload matched %d users", len(users))
			}
		})
	}

	// The table must still exist after the DROP attempt.
	if _, total, err := repo.ListScimUsers(ctx, "", 1, 100); err != nil || total != 3 {
		t.Fatalf("after injection attempts: total = %d, err = %v; want 3 users intact", total, err)
	}
}

// TestGroupFilter covers the group listing path.
func TestGroupFilter(t *testing.T) {
	ctx := context.Background()
	repo := newFilterRepo(t)

	for _, name := range []string{"admins", "engineers"} {
		if err := repo.CreateScimGroup(ctx, &scim.Group{DisplayName: name}); err != nil {
			t.Fatalf("create group: %v", err)
		}
	}

	groups, total, err := repo.ListScimGroups(ctx, `displayName eq "admins"`, 1, 100)
	if err != nil {
		t.Fatalf("ListScimGroups: %v", err)
	}
	if len(groups) != 1 || total != 1 {
		t.Errorf("returned %d groups (total %d), want 1", len(groups), total)
	}
}
