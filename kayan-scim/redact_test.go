package scim

import (
	"context"
	"errors"
	"testing"
)

const storedHash = "$2a$10$abcdefghijklmnopqrstuv"

// sortingMock adds sorting to the mock so ListUsersSorted reaches storage.
type sortingMock struct{ *mockScimStorage }

func (sortingMock) SupportsSorting() bool { return true }
func (s sortingMock) ListScimUsersSorted(ctx context.Context, opts ListOptions) ([]*User, int, error) {
	return s.ListScimUsers(ctx, "", opts.StartIndex, opts.Count)
}
func (s sortingMock) ListScimGroupsSorted(ctx context.Context, opts ListOptions) ([]*Group, int, error) {
	return s.ListScimGroups(ctx, "", opts.StartIndex, opts.Count)
}

func seededManager(t *testing.T) (*Manager, *mockScimStorage, string) {
	t.Helper()
	store := newMockScimStorage()
	user := &User{UserName: "alice", Password: storedHash}
	if err := store.CreateScimUser(context.Background(), user); err != nil {
		t.Fatal(err)
	}
	return NewManager(sortingMock{store}, nil), store, user.ID
}

// TestPasswordIsNeverReturned. RFC 7643 marks password returned="never". A
// storage that maps it -- a gormstore deployment mapping "password" to its
// hash column so SCIM creates can set it -- handed the hash back on every
// read, and the mock pattern echoed plaintext.
func TestPasswordIsNeverReturned(t *testing.T) {
	ctx := context.Background()
	manager, store, id := seededManager(t)

	got, err := manager.GetUser(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if got.Password != "" {
		t.Errorf("GetUser returned the password")
	}

	list, err := manager.ListUsers(ctx, "", 1, 10)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range list.Resources {
		if r.(*User).Password != "" {
			t.Errorf("ListUsers returned the password")
		}
	}

	sorted, err := manager.ListUsersSorted(ctx, ListOptions{SortBy: "userName"})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range sorted.Resources {
		if r.(*User).Password != "" {
			t.Errorf("ListUsersSorted returned the password")
		}
	}

	created, err := manager.CreateUser(ctx, &User{UserName: "bob", Password: "plaintext"})
	if err != nil {
		t.Fatal(err)
	}
	if created.Password != "" {
		t.Errorf("CreateUser echoed the password")
	}

	updated, err := manager.UpdateUser(ctx, id, &User{UserName: "alice", Password: "new-plaintext"})
	if err != nil {
		t.Fatal(err)
	}
	if updated.Password != "" {
		t.Errorf("UpdateUser echoed the password")
	}

	// Redaction must not reach into what storage holds: clearing the stored
	// record would make the next write persist an empty password.
	if store.users[created.ID].Password != "plaintext" {
		t.Errorf("redaction cleared the stored password")
	}
}

// TestPasswordCannotBeFilteredOrSorted. Redaction alone leaves an oracle:
// totalResults for `password sw "<prefix>"` recovers the stored hash one
// character at a time.
func TestPasswordCannotBeFilteredOrSorted(t *testing.T) {
	ctx := context.Background()
	manager, _, _ := seededManager(t)

	filters := []string{
		`password sw "$2a$10$a"`,
		`PASSWORD pr`,
		`urn:ietf:params:scim:schemas:core:2.0:User:password eq "x"`,
		`userName eq "alice" and password sw "$"`,
		`userName eq "nobody" or password sw "$"`,
		`not (password sw "$")`,
		`emails[password sw "$"]`,
	}
	for _, filter := range filters {
		if _, err := manager.ListUsers(ctx, filter, 1, 10); !errors.Is(err, ErrAttributeNotQueryable) {
			t.Errorf("ListUsers(%q): err = %v, want ErrAttributeNotQueryable", filter, err)
		}
		if _, err := manager.ListUsersSorted(ctx, ListOptions{Filter: filter, SortBy: "userName"}); !errors.Is(err, ErrAttributeNotQueryable) {
			t.Errorf("ListUsersSorted(%q): err = %v, want ErrAttributeNotQueryable", filter, err)
		}
	}

	for _, sortBy := range []string{"password", "Password"} {
		if _, err := manager.ListUsersSorted(ctx, ListOptions{SortBy: sortBy}); !errors.Is(err, ErrAttributeNotQueryable) {
			t.Errorf("sortBy=%s: err = %v, want ErrAttributeNotQueryable", sortBy, err)
		}
	}

	// An ordinary query is unaffected.
	if _, err := manager.ListUsers(ctx, `userName eq "alice"`, 1, 10); err != nil {
		t.Errorf("ordinary filter refused: %v", err)
	}
}
