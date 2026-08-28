package gormstore

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	scim "github.com/getkayan/kayan/kayan-scim"
)

func seedGroups(t *testing.T, repo *ScimRepository, names ...string) {
	t.Helper()
	ctx := context.Background()
	for i, name := range names {
		group := &scim.Group{DisplayName: name}
		// Ids run counter to the names on purpose: an implementation that
		// ignored sortBy and fell back to the primary key would produce the
		// reverse of the expected order rather than something that happens to
		// look sorted.
		group.ID = fmt.Sprintf("id-%02d", len(names)-i)
		if err := repo.CreateScimGroup(ctx, group); err != nil {
			t.Fatalf("CreateScimGroup(%s): %v", name, err)
		}
	}
}

func displayNames(groups []*scim.Group) []string {
	out := make([]string, len(groups))
	for i, group := range groups {
		out[i] = group.DisplayName
	}
	return out
}

func TestSortAscendingAndDescending(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()
	seedGroups(t, repo, "alpha", "bravo", "charlie", "delta")

	ascending, _, err := repo.ListScimGroupsSorted(ctx, scim.ListOptions{
		StartIndex: 1, Count: 10, SortBy: "displayName",
	})
	if err != nil {
		t.Fatalf("ascending: %v", err)
	}
	if got := strings.Join(displayNames(ascending), ","); got != "alpha,bravo,charlie,delta" {
		t.Errorf("ascending = %s", got)
	}

	descending, _, err := repo.ListScimGroupsSorted(ctx, scim.ListOptions{
		StartIndex: 1, Count: 10, SortBy: "displayName", SortOrder: scim.SortDescending,
	})
	if err != nil {
		t.Fatalf("descending: %v", err)
	}
	if got := strings.Join(displayNames(descending), ","); got != "delta,charlie,bravo,alpha" {
		t.Errorf("descending = %s", got)
	}
}

// TestSortSurvivesPaging. A sort that is applied per page rather than across
// the result set orders each page internally and interleaves them, which reads
// as sorted until a client looks at two pages together.
func TestSortSurvivesPaging(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()
	seedGroups(t, repo, "aa", "bb", "cc", "dd", "ee", "ff")

	var collected []string
	for start := 1; start <= 6; start += 2 {
		page, total, err := repo.ListScimGroupsSorted(ctx, scim.ListOptions{
			StartIndex: start, Count: 2, SortBy: "displayName",
		})
		if err != nil {
			t.Fatalf("page at %d: %v", start, err)
		}
		if total != 6 {
			t.Errorf("totalResults = %d, want 6", total)
		}
		collected = append(collected, displayNames(page)...)
	}

	if got := strings.Join(collected, ","); got != "aa,bb,cc,dd,ee,ff" {
		t.Errorf("paged order = %s, want the sort to hold across pages", got)
	}
}

// TestUnmappedSortAttributeIsRefused.
//
// sortBy is client text destined for an ORDER BY clause, which cannot be
// parameterised. Resolving it through the deployment's attribute mapping is
// what keeps it from reaching a column -- or an expression -- the deployment
// never meant to expose.
func TestUnmappedSortAttributeIsRefused(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()
	seedGroups(t, repo, "alpha")

	for _, sortBy := range []string{
		"notAnAttribute",
		"password",
		"id; DROP TABLE scim_groups--",
		"(SELECT 1)",
	} {
		_, _, err := repo.ListScimGroupsSorted(ctx, scim.ListOptions{
			StartIndex: 1, Count: 10, SortBy: sortBy,
		})
		if err == nil {
			t.Errorf("sortBy %q was accepted", sortBy)
			continue
		}
		if !errors.Is(err, scim.ErrInvalidSortAttribute) {
			t.Errorf("sortBy %q: error = %v, want ErrInvalidSortAttribute", sortBy, err)
		}
	}

	// The table must still be there, which an accepted injection would not
	// leave behind.
	if _, _, err := repo.ListScimGroups(ctx, "", 1, 10); err != nil {
		t.Errorf("listing after the injection attempts failed: %v", err)
	}
}

// TestTiedSortIsStillDeterministic.
//
// Ordering by a non-unique column leaves tied rows in no defined order, so
// paging through the ties has the same duplicate-and-skip problem an unordered
// listing has -- confined to the ties, which makes it harder to notice rather
// than less wrong. The primary key breaks them.
//
// Users are used rather than groups because every group column is unique, so
// a group query has no ties to break.
func TestTiedSortIsStillDeterministic(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()

	// Every user shares a userName, so the sort column tells them apart not at
	// all and only the tiebreaker decides the order.
	const tied = 10
	for i := range tied {
		user := &scim.User{UserName: "shared@example.test"}
		user.ID = fmt.Sprintf("id-%02d", tied-i)
		if err := repo.CreateScimUser(ctx, user); err != nil {
			t.Fatalf("CreateScimUser: %v", err)
		}
	}

	opts := scim.ListOptions{StartIndex: 1, Count: 4, SortBy: "userName"}

	// Page through the ties. Without a tiebreaker the windows overlap and some
	// rows never appear.
	seen := map[string]int{}
	for start := 1; start <= tied; start += 4 {
		page := opts
		page.StartIndex = start
		users, _, err := repo.ListScimUsersSorted(ctx, page)
		if err != nil {
			t.Fatalf("ListScimUsersSorted(start=%d): %v", start, err)
		}
		for _, user := range users {
			seen[user.ID]++
		}
	}

	if len(seen) != tied {
		t.Errorf("paging tied rows visited %d of %d; the rest were never returned",
			len(seen), tied)
	}
	for id, times := range seen {
		if times != 1 {
			t.Errorf("user %s appeared on %d pages", id, times)
		}
	}

	// And the order must be repeatable across identical requests.
	first, _, err := repo.ListScimUsersSorted(ctx, opts)
	if err != nil {
		t.Fatalf("ListScimUsersSorted: %v", err)
	}
	again, _, err := repo.ListScimUsersSorted(ctx, opts)
	if err != nil {
		t.Fatalf("ListScimUsersSorted: %v", err)
	}
	for i := range first {
		if first[i].ID != again[i].ID {
			t.Errorf("position %d held %s then %s across identical requests",
				i, first[i].ID, again[i].ID)
		}
	}
	// The tiebreaker orders by primary key, so the first page is the lowest
	// ids -- not the insertion order, which ran the other way.
	if len(first) > 0 && first[0].ID != "id-01" {
		t.Errorf("first result = %s, want id-01 from the primary-key tiebreaker", first[0].ID)
	}
}
