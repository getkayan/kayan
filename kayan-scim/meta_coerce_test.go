package scim

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"
)

// These cover the coercion helpers directly. They read fields off the caller's
// own struct, so the set of types they meet is whatever a deployment happens to
// use -- and a type they silently do not understand becomes an omitted meta
// member rather than an error, which is exactly the kind of gap that is only
// visible from a table like this.

func TestAsTimeAcceptsTheShapesDeploymentsStore(t *testing.T) {
	moment := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)

	cases := []struct {
		name    string
		value   any
		want    time.Time
		present bool
	}{
		{"time.Time", moment, moment, true},
		{"pointer to time.Time", &moment, moment, true},
		{"unix seconds", moment.Unix(), moment, true},
		{"zero time", time.Time{}, time.Time{}, false},
		{"nil pointer", (*time.Time)(nil), time.Time{}, false},
		{"zero unix seconds", int64(0), time.Time{}, false},
		// A type this does not understand must report absent rather than
		// guess. An invented timestamp tells a provisioning connector the
		// resource changed when nothing did.
		{"unsupported type", "2026-03-04", time.Time{}, false},
		{"nil", nil, time.Time{}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, present := asTime(tc.value)
			if present != tc.present {
				t.Fatalf("present = %v, want %v", present, tc.present)
			}
			if present && !got.Equal(tc.want) {
				t.Errorf("time = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestAsVersionWrapsWhateverTheStoreKeeps(t *testing.T) {
	moment := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)

	cases := []struct {
		name  string
		value any
		want  string
	}{
		{"counter", 7, `W/"7"`},
		{"int64 counter", int64(7), `W/"7"`},
		{"uint counter", uint(7), `W/"7"`},
		{"uint64 counter", uint64(7), `W/"7"`},
		{"revision string", "rev-3", `W/"rev-3"`},
		// Already an ETag: wrapping it again produces a value that matches
		// nothing, since the client returns what it was given.
		{"already weak", `W/"rev-3"`, `W/"rev-3"`},
		{"already quoted", `"rev-3"`, `"rev-3"`},
		{"modification time", moment, `W/"` + strconv.FormatInt(moment.UnixNano(), 10) + `"`},
		{"empty string", "", ""},
		{"zero time", time.Time{}, ""},
		{"unsupported type", 3.5, ""},
		{"nil", nil, ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := asVersion(tc.value); got != tc.want {
				t.Errorf("asVersion(%v) = %q, want %q", tc.value, got, tc.want)
			}
		})
	}
}

// TestApplyGroupMetaUsesTheStoredVersion. A store that keeps a revision counter
// must have it reflected in meta.version, or a conditional write conditions on
// a hash the store cannot compare against.
func TestApplyGroupMetaUsesTheStoredVersion(t *testing.T) {
	group := &Group{DisplayName: "engineering"}
	group.ID = "group-1"
	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

	ApplyGroupMeta(group, "https://api.example.test/scim/v2", created, created, uint64(9))

	if group.Meta.ResourceType != ResourceTypeGroup {
		t.Errorf("resourceType = %q", group.Meta.ResourceType)
	}
	if want := `W/"9"`; group.Meta.Version != want {
		t.Errorf("version = %q, want %q", group.Meta.Version, want)
	}
	if want := "https://api.example.test/scim/v2/Groups/group-1"; group.Meta.Location != want {
		t.Errorf("location = %q, want %q", group.Meta.Location, want)
	}
}

// TestApplyGroupMetaDerivesAVersionWhenTheStoreKeepsNone. A store with no
// revision column still needs an ETag for caching; it is the compare-and-swap
// path that needs a stored one.
func TestApplyGroupMetaDerivesAVersionWhenTheStoreKeepsNone(t *testing.T) {
	first := &Group{DisplayName: "engineering"}
	first.ID = "group-1"
	ApplyGroupMeta(first, "", time.Time{}, time.Time{}, nil)

	same := &Group{DisplayName: "engineering"}
	same.ID = "group-1"
	ApplyGroupMeta(same, "", time.Time{}, time.Time{}, nil)

	changed := &Group{DisplayName: "platform"}
	changed.ID = "group-1"
	ApplyGroupMeta(changed, "", time.Time{}, time.Time{}, nil)

	if !strings.HasPrefix(first.Meta.Version, "W/") {
		t.Errorf("version = %q, want a weak ETag", first.Meta.Version)
	}
	if first.Meta.Version != same.Meta.Version {
		t.Error("two reads of an unchanged group produced different versions")
	}
	if first.Meta.Version == changed.Meta.Version {
		t.Error("a renamed group kept its version, so a stale ETag still matches")
	}
	if first.Meta.Location != "" {
		t.Errorf("location = %q, want it omitted with no base URL", first.Meta.Location)
	}
	// A nil group must not panic: a store that failed to build one would
	// otherwise take the process down inside a list response.
	ApplyGroupMeta(nil, "", time.Time{}, time.Time{}, nil)
}

// TestConditionalManagerPathsRefuseWithoutSupport covers the remaining
// conditional entry points against storage that cannot compare and swap.
func TestConditionalManagerPathsRefuseWithoutSupport(t *testing.T) {
	manager := NewManager(&noConditionalStorage{}, metaMapper(false, ""))
	ctx := context.Background()

	if err := manager.DeleteUserIfMatch(ctx, "user-1", `W/"1"`); err != ErrConditionalUnsupported {
		t.Errorf("DeleteUserIfMatch error = %v, want ErrConditionalUnsupported", err)
	}
	if _, err := manager.UpdateGroupIfMatch(ctx, "group-1", &Group{}, `W/"1"`); err != ErrConditionalUnsupported {
		t.Errorf("UpdateGroupIfMatch error = %v, want ErrConditionalUnsupported", err)
	}
}

// TestConditionalPathsRequireAPrecondition. A conditional call with no
// condition is a caller bug that would otherwise become an unconditional write
// -- the exact operation the caller was trying to avoid.
func TestConditionalPathsRequireAPrecondition(t *testing.T) {
	manager := NewManager(&noConditionalStorage{}, metaMapper(false, ""))
	ctx := context.Background()

	if _, err := manager.UpdateUserIfMatch(ctx, "user-1", &User{}, ""); err == nil {
		t.Error("UpdateUserIfMatch accepted an empty If-Match")
	}
	if err := manager.DeleteUserIfMatch(ctx, "user-1", ""); err == nil {
		t.Error("DeleteUserIfMatch accepted an empty If-Match")
	}
	if _, err := manager.UpdateGroupIfMatch(ctx, "group-1", &Group{}, ""); err == nil {
		t.Error("UpdateGroupIfMatch accepted an empty If-Match")
	}
	if err := manager.DeleteGroupIfMatch(ctx, "group-1", ""); err == nil {
		t.Error("DeleteGroupIfMatch accepted an empty If-Match")
	}
}

// TestListGroupsSortedWithoutSupport mirrors the user path: a sort request
// against storage that cannot sort is refused rather than answered in storage
// order.
func TestListGroupsSortedWithoutSupport(t *testing.T) {
	manager := NewManager(&noConditionalStorage{}, metaMapper(false, ""))

	_, err := manager.ListGroupsSorted(context.Background(), ListOptions{
		StartIndex: 1, Count: 10, SortBy: "displayName",
	})
	if err != ErrSortUnsupported {
		t.Errorf("error = %v, want ErrSortUnsupported", err)
	}
}
