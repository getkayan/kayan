package gormstore

import (
	"context"
	"fmt"
	"testing"

	scim "github.com/getkayan/kayan/kayan-scim"
)

// TestListingIsOrderedByID is the test that can fail.
//
// The groups are inserted in descending id order, so insertion order and id
// order disagree. Without ORDER BY, SQLite hands back rowid order and this
// test sees the reverse of what it asked for.
//
// The companion tests below assert the property a client cares about -- every
// resource on exactly one page -- but SQLite's natural rowid order satisfies
// those whether or not the ORDER BY is there, so they lock the behaviour
// rather than prove the fix. This one proves it.
func TestListingIsOrderedByID(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()

	const total = 12
	for i := total - 1; i >= 0; i-- {
		group := &scim.Group{DisplayName: fmt.Sprintf("group-%02d", i)}
		group.ID = fmt.Sprintf("id-%02d", i)
		if err := repo.CreateScimGroup(ctx, group); err != nil {
			t.Fatalf("CreateScimGroup: %v", err)
		}
	}

	page, _, err := repo.ListScimGroups(ctx, "", 1, total)
	if err != nil {
		t.Fatalf("ListScimGroups: %v", err)
	}
	if len(page) != total {
		t.Fatalf("got %d groups, want %d", len(page), total)
	}
	for i := 1; i < len(page); i++ {
		if page[i-1].ID >= page[i].ID {
			t.Fatalf("results are not ordered by id: %s came before %s; without an "+
				"order, OFFSET pages sample an unordered set",
				page[i-1].ID, page[i].ID)
		}
	}
}

// TestPagingVisitsEveryGroupExactlyOnce is the property a client depends on.
//
// OFFSET and LIMIT without ORDER BY sample an unordered set: SQL guarantees no
// order without one, and the order a database happens to return shifts as rows
// are written or the planner changes its mind. A provisioning connector paging
// a directory then receives some resources twice and never receives others.
// Every page looks well formed, the totals add up, and the users who were
// skipped are simply never provisioned.
func TestPagingVisitsEveryGroupExactlyOnce(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()

	const total = 40
	for i := range total {
		group := &scim.Group{DisplayName: fmt.Sprintf("group-%02d", i)}
		group.ID = fmt.Sprintf("id-%02d", i)
		if err := repo.CreateScimGroup(ctx, group); err != nil {
			t.Fatalf("CreateScimGroup: %v", err)
		}
	}

	const pageSize = 7
	seen := map[string]int{}
	for start := 1; start <= total; start += pageSize {
		page, count, err := repo.ListScimGroups(ctx, "", start, pageSize)
		if err != nil {
			t.Fatalf("ListScimGroups(start=%d): %v", start, err)
		}
		if count != total {
			t.Errorf("totalResults = %d, want %d", count, total)
		}
		for _, group := range page {
			seen[group.ID]++
		}
	}

	if len(seen) != total {
		t.Errorf("paging visited %d distinct groups out of %d; the rest were never "+
			"returned to the client", len(seen), total)
	}
	for id, times := range seen {
		if times != 1 {
			t.Errorf("group %s appeared on %d pages", id, times)
		}
	}
}

// TestPagingIsRepeatable. Two identical requests must return the same page.
// Without an order they need not, and a connector that retries a timed-out
// page silently processes a different set of resources.
func TestPagingIsRepeatable(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()

	for i := range 25 {
		group := &scim.Group{DisplayName: fmt.Sprintf("g%02d", i)}
		group.ID = fmt.Sprintf("id-%02d", i)
		if err := repo.CreateScimGroup(ctx, group); err != nil {
			t.Fatalf("CreateScimGroup: %v", err)
		}
	}

	first, _, err := repo.ListScimGroups(ctx, "", 6, 5)
	if err != nil {
		t.Fatalf("ListScimGroups: %v", err)
	}
	again, _, err := repo.ListScimGroups(ctx, "", 6, 5)
	if err != nil {
		t.Fatalf("ListScimGroups: %v", err)
	}

	if len(first) != len(again) {
		t.Fatalf("page sizes differ: %d and %d", len(first), len(again))
	}
	for i := range first {
		if first[i].ID != again[i].ID {
			t.Errorf("position %d held %s then %s; the same request returned a "+
				"different page", i, first[i].ID, again[i].ID)
		}
	}
}
