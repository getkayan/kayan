package gormstore

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	scim "github.com/getkayan/kayan/kayan-scim"
)

// TestGroupUpdateIsCompareAndSwap is the central test.
//
// Okta and Entra maintain group membership by reading a group, computing a
// change, and writing it back. Two of those cycles overlapping -- two
// connectors, or one connector retrying after a timeout -- means the second
// write is computed from a state the first has already replaced. Without a
// version check the second silently reverts the first, and both requests are
// answered 200, so the audit trail shows two successful operations and the
// removed member is back.
func TestGroupUpdateIsCompareAndSwap(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()

	group := &scim.Group{DisplayName: "engineering"}
	group.ID = "group-1"
	if err := repo.CreateScimGroup(ctx, group); err != nil {
		t.Fatalf("CreateScimGroup: %v", err)
	}

	// Both writers read the same starting version, as two connectors would.
	read, err := repo.GetScimGroup(ctx, "group-1")
	if err != nil {
		t.Fatalf("GetScimGroup: %v", err)
	}
	stale := read.Meta.Version
	if stale == "" {
		t.Fatal("the group carries no meta.version, so nothing can be conditioned on it")
	}

	first := &scim.Group{DisplayName: "engineering-renamed"}
	first.ID = "group-1"
	if err := repo.UpdateScimGroupIfMatch(ctx, first, stale); err != nil {
		t.Fatalf("the first conditional write failed: %v", err)
	}

	// The second writer still holds the version it read before the first write.
	second := &scim.Group{DisplayName: "engineering-clobbered"}
	second.ID = "group-1"
	err = repo.UpdateScimGroupIfMatch(ctx, second, stale)
	if !errors.Is(err, scim.ErrPreconditionFailed) {
		t.Fatalf("error = %v, want ErrPreconditionFailed; the second write overwrote the first", err)
	}

	after, err := repo.GetScimGroup(ctx, "group-1")
	if err != nil {
		t.Fatalf("GetScimGroup: %v", err)
	}
	if after.DisplayName != "engineering-renamed" {
		t.Errorf("DisplayName = %q, want the first write to have survived", after.DisplayName)
	}
	if after.Meta.Version == stale {
		t.Error("the version did not move after a successful write, so the stale ETag " +
			"would keep matching forever")
	}
}

// TestConcurrentGroupUpdatesElectOneWinner. The guarantee is compare-and-swap,
// not "usually compare-and-swap": a check followed by a write would let both
// of these through under load, which is exactly when it matters.
func TestConcurrentGroupUpdatesElectOneWinner(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()

	group := &scim.Group{DisplayName: "start"}
	group.ID = "group-race"
	if err := repo.CreateScimGroup(ctx, group); err != nil {
		t.Fatalf("CreateScimGroup: %v", err)
	}
	read, err := repo.GetScimGroup(ctx, "group-race")
	if err != nil {
		t.Fatalf("GetScimGroup: %v", err)
	}
	version := read.Meta.Version

	const writers = 16
	var wg sync.WaitGroup
	results := make(chan error, writers)
	for i := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			candidate := &scim.Group{DisplayName: "writer"}
			candidate.ID = "group-race"
			_ = i
			results <- repo.UpdateScimGroupIfMatch(ctx, candidate, version)
		}()
	}
	wg.Wait()
	close(results)

	won := 0
	for err := range results {
		switch {
		case err == nil:
			won++
		case errors.Is(err, scim.ErrPreconditionFailed):
		default:
			t.Errorf("unexpected error: %v", err)
		}
	}
	if won != 1 {
		t.Errorf("%d of %d writers holding the same version succeeded, want exactly 1", won, writers)
	}
}

// TestWildcardMatchesAnyExistingGroup. RFC 7232 section 3.1: "*" means the
// resource must exist, nothing about which version. A missing resource must
// still fail, or a conditional delete would report success for an id that was
// never there.
func TestWildcardMatchesAnyExistingGroup(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()

	group := &scim.Group{DisplayName: "wildcard"}
	group.ID = "group-2"
	if err := repo.CreateScimGroup(ctx, group); err != nil {
		t.Fatalf("CreateScimGroup: %v", err)
	}

	updated := &scim.Group{DisplayName: "wildcard-renamed"}
	updated.ID = "group-2"
	if err := repo.UpdateScimGroupIfMatch(ctx, updated, "*"); err != nil {
		t.Errorf("the wildcard did not match an existing group: %v", err)
	}

	missing := &scim.Group{DisplayName: "ghost"}
	missing.ID = "no-such-group"
	if err := repo.UpdateScimGroupIfMatch(ctx, missing, "*"); !errors.Is(err, scim.ErrPreconditionFailed) {
		t.Errorf("error = %v, want the wildcard to fail against a group that does not exist", err)
	}
}

// TestConditionalDeleteHonoursTheVersion. A delete is the operation where a
// lost update is least recoverable, so it gets the same check.
func TestConditionalDeleteHonoursTheVersion(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()

	group := &scim.Group{DisplayName: "doomed"}
	group.ID = "group-3"
	if err := repo.CreateScimGroup(ctx, group); err != nil {
		t.Fatalf("CreateScimGroup: %v", err)
	}
	read, err := repo.GetScimGroup(ctx, "group-3")
	if err != nil {
		t.Fatalf("GetScimGroup: %v", err)
	}
	stale := read.Meta.Version

	// Something else changes it first.
	renamed := &scim.Group{DisplayName: "renamed"}
	renamed.ID = "group-3"
	if err := repo.UpdateScimGroup(ctx, renamed); err != nil {
		t.Fatalf("UpdateScimGroup: %v", err)
	}

	if err := repo.DeleteScimGroupIfMatch(ctx, "group-3", stale); !errors.Is(err, scim.ErrPreconditionFailed) {
		t.Fatalf("error = %v, want the delete refused against a stale version", err)
	}
	if _, err := repo.GetScimGroup(ctx, "group-3"); err != nil {
		t.Error("the group was deleted despite the failed precondition")
	}
}

// TestUnconditionalUpdateAdvancesTheVersion. If the plain path left the
// counter alone, an ETag read before it would keep matching afterwards, and a
// conditional write would be told nothing had changed when everything had.
func TestUnconditionalUpdateAdvancesTheVersion(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()

	group := &scim.Group{DisplayName: "before"}
	group.ID = "group-4"
	if err := repo.CreateScimGroup(ctx, group); err != nil {
		t.Fatalf("CreateScimGroup: %v", err)
	}
	before, err := repo.GetScimGroup(ctx, "group-4")
	if err != nil {
		t.Fatalf("GetScimGroup: %v", err)
	}

	renamed := &scim.Group{DisplayName: "after"}
	renamed.ID = "group-4"
	if err := repo.UpdateScimGroup(ctx, renamed); err != nil {
		t.Fatalf("UpdateScimGroup: %v", err)
	}

	after, err := repo.GetScimGroup(ctx, "group-4")
	if err != nil {
		t.Fatalf("GetScimGroup: %v", err)
	}
	if after.Meta.Version == before.Meta.Version {
		t.Error("an unconditional update left the version unchanged, so a stale ETag " +
			"still matches a group that has been rewritten")
	}
}

// TestGroupMetaIsPopulated. Every SCIM response this library produced carried
// an empty meta. A connector reads resourceType to tell a User from a Group and
// follows location to address the resource.
func TestGroupMetaIsPopulated(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()

	group := &scim.Group{DisplayName: "meta"}
	group.ID = "group-5"
	if err := repo.CreateScimGroup(ctx, group); err != nil {
		t.Fatalf("CreateScimGroup: %v", err)
	}

	read, err := repo.GetScimGroup(ctx, "group-5")
	if err != nil {
		t.Fatalf("GetScimGroup: %v", err)
	}
	if read.Meta.ResourceType != scim.ResourceTypeGroup {
		t.Errorf("meta.resourceType = %q, want %q", read.Meta.ResourceType, scim.ResourceTypeGroup)
	}
	if read.Meta.Created.IsZero() {
		t.Error("meta.created is empty")
	}
	if read.Meta.LastModified.IsZero() {
		t.Error("meta.lastModified is empty")
	}
	if !strings.HasPrefix(read.Meta.Version, "W/") {
		t.Errorf("meta.version = %q, want a weak ETag", read.Meta.Version)
	}
}

// TestMalformedIfMatchIsRefused. An unparsable precondition must never widen
// into an unconditional write, which is what dropping the predicate would do.
func TestMalformedIfMatchIsRefused(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()

	group := &scim.Group{DisplayName: "guarded"}
	group.ID = "group-6"
	if err := repo.CreateScimGroup(ctx, group); err != nil {
		t.Fatalf("CreateScimGroup: %v", err)
	}

	for _, ifMatch := range []string{"", `W/"1", W/"2"`} {
		attempt := &scim.Group{DisplayName: "overwritten"}
		attempt.ID = "group-6"
		if err := repo.UpdateScimGroupIfMatch(ctx, attempt, ifMatch); err == nil {
			t.Errorf("If-Match %q was accepted and the write went through unconditionally", ifMatch)
		}
	}

	after, err := repo.GetScimGroup(ctx, "group-6")
	if err != nil {
		t.Fatalf("GetScimGroup: %v", err)
	}
	if after.DisplayName != "guarded" {
		t.Errorf("DisplayName = %q, want the group untouched", after.DisplayName)
	}
}
