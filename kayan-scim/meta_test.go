package scim

import (
	"context"
	"strings"
	"testing"
	"time"
)

type metaModel struct {
	ID        string
	Email     string
	CreatedAt time.Time
	UpdatedAt time.Time
	Revision  uint64
}

func (m *metaModel) GetID() any  { return m.ID }
func (m *metaModel) SetID(v any) { m.ID, _ = v.(string) }

func metaMapper(withVersion bool, baseURL string) *Mapper {
	mappings := map[string]string{
		MetaCreated:      "CreatedAt",
		MetaLastModified: "UpdatedAt",
	}
	if withVersion {
		mappings[MetaVersion] = "Revision"
	}
	return NewMapper(func() any { return &metaModel{} }, MapperConfig{
		FieldMappings:   map[string]string{"userName": "Email"},
		MetaMappings:    mappings,
		ResourceBaseURL: baseURL,
	})
}

// TestUserMetaIsPopulated covers the attribute every response used to omit.
//
// A provisioning connector reads resourceType to tell a User from a Group,
// follows location to address the resource, and compares lastModified to work
// out what changed since its last sync. Given none of it, the connector either
// re-reads everything every cycle or concludes nothing moved.
func TestUserMetaIsPopulated(t *testing.T) {
	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	modified := created.Add(48 * time.Hour)
	model := &metaModel{ID: "user-1", Email: "alice@example.test",
		CreatedAt: created, UpdatedAt: modified, Revision: 7}

	user, err := metaMapper(true, "https://api.example.test/scim/v2").FromModel(model)
	if err != nil {
		t.Fatalf("FromModel: %v", err)
	}

	if user.Meta.ResourceType != ResourceTypeUser {
		t.Errorf("resourceType = %q, want %q", user.Meta.ResourceType, ResourceTypeUser)
	}
	if !user.Meta.Created.Equal(created) {
		t.Errorf("created = %v, want %v", user.Meta.Created, created)
	}
	if !user.Meta.LastModified.Equal(modified) {
		t.Errorf("lastModified = %v, want %v", user.Meta.LastModified, modified)
	}
	if want := "https://api.example.test/scim/v2/Users/user-1"; user.Meta.Location != want {
		t.Errorf("location = %q, want %q", user.Meta.Location, want)
	}
	if want := `W/"7"`; user.Meta.Version != want {
		t.Errorf("version = %q, want the mapped revision as %q", user.Meta.Version, want)
	}
}

// TestUnmappedMetaMembersAreOmittedNotInvented.
//
// A lastModified filled with the current time would tell a connector that
// every resource changed on every sync -- a full re-provision each cycle, and
// no way for the operator to see why. An omitted member is the honest answer
// and connectors are required to tolerate it.
func TestUnmappedMetaMembersAreOmittedNotInvented(t *testing.T) {
	mapper := NewMapper(func() any { return &metaModel{} }, MapperConfig{
		FieldMappings: map[string]string{"userName": "Email"},
	})

	user, err := mapper.FromModel(&metaModel{ID: "user-2", Email: "bob@example.test"})
	if err != nil {
		t.Fatalf("FromModel: %v", err)
	}

	if !user.Meta.Created.IsZero() {
		t.Errorf("created = %v, want it omitted when nothing is mapped", user.Meta.Created)
	}
	if !user.Meta.LastModified.IsZero() {
		t.Errorf("lastModified = %v, want it omitted when nothing is mapped", user.Meta.LastModified)
	}
	if user.Meta.Location != "" {
		t.Errorf("location = %q, want it omitted when no base URL is configured; a "+
			"guessed URL resolves nowhere", user.Meta.Location)
	}
	// resourceType and version need nothing from the deployment.
	if user.Meta.ResourceType != ResourceTypeUser {
		t.Errorf("resourceType = %q, want it set regardless", user.Meta.ResourceType)
	}
	if !strings.HasPrefix(user.Meta.Version, "W/") {
		t.Errorf("version = %q, want a derived weak ETag", user.Meta.Version)
	}
}

// TestDerivedVersionTracksContent. The derived ETag's only job is to answer
// "has this changed?", so it must move when the resource does and hold still
// when it does not.
func TestDerivedVersionTracksContent(t *testing.T) {
	mapper := NewMapper(func() any { return &metaModel{} }, MapperConfig{
		FieldMappings: map[string]string{"userName": "Email"},
	})

	first, err := mapper.FromModel(&metaModel{ID: "user-3", Email: "carol@example.test"})
	if err != nil {
		t.Fatalf("FromModel: %v", err)
	}
	same, err := mapper.FromModel(&metaModel{ID: "user-3", Email: "carol@example.test"})
	if err != nil {
		t.Fatalf("FromModel: %v", err)
	}
	changed, err := mapper.FromModel(&metaModel{ID: "user-3", Email: "carol+new@example.test"})
	if err != nil {
		t.Fatalf("FromModel: %v", err)
	}

	if first.Meta.Version != same.Meta.Version {
		t.Error("two reads of an unchanged resource produced different versions, so " +
			"every conditional request would fail")
	}
	if first.Meta.Version == changed.Meta.Version {
		t.Error("a changed resource kept its version, so a stale ETag still matches")
	}
}

// noConditionalStorage is a store that cannot compare and swap, which is the
// default for anything implementing only ScimStorage.
type noConditionalStorage struct{ ScimStorage }

// TestConditionalWriteWithoutSupportIsAnError.
//
// A read-check-write fallback would be worse than refusing. It answers "your
// update was applied against the version you named" while another writer fits
// between the check and the write -- the lost update the precondition exists
// to prevent, now with a receipt saying it did not happen.
func TestConditionalWriteWithoutSupportIsAnError(t *testing.T) {
	manager := NewManager(&noConditionalStorage{}, metaMapper(false, ""))

	if manager.SupportsConditionalWrites() {
		t.Error("a store with no conditional support reported that it has it")
	}

	_, err := manager.UpdateUserIfMatch(context.Background(), "user-1", &User{}, `W/"1"`)
	if err == nil {
		t.Fatal("a conditional update was accepted by a store that cannot honour it")
	}
	if err != ErrConditionalUnsupported {
		t.Errorf("error = %v, want ErrConditionalUnsupported", err)
	}

	if err := manager.DeleteGroupIfMatch(context.Background(), "group-1", "*"); err != ErrConditionalUnsupported {
		t.Errorf("error = %v, want ErrConditionalUnsupported", err)
	}
}

// TestDiscoveryDoesNotAdvertiseETagItCannotServe.
//
// A client that reads etag: true starts sending If-Match and expects 412 on a
// conflict. Against a store that cannot compare and swap, every one of those
// requests is answered as though the precondition held, so the client believes
// its updates are guarded and they are not.
func TestDiscoveryDoesNotAdvertiseETagItCannotServe(t *testing.T) {
	manager := NewManager(&noConditionalStorage{}, metaMapper(false, ""))

	if manager.ServiceProviderConfig(100).ETag.Supported {
		t.Error("discovery advertised etag support against a store that has none")
	}
}

// TestVersionsMatch covers the header forms a client actually sends.
func TestVersionsMatch(t *testing.T) {
	cases := []struct {
		ifMatch string
		version string
		want    bool
	}{
		{`W/"7"`, `W/"7"`, true},
		{`"7"`, `W/"7"`, true},
		{`W/"7"`, `W/"8"`, false},
		{"*", `W/"7"`, true},
		{"*", "", true},
		{"", `W/"7"`, false},
		{`W/"6", W/"7"`, `W/"7"`, true},
		// An empty version must not match a concrete ETag, or a resource with
		// no version would satisfy every precondition.
		{`W/"7"`, "", false},
	}

	for _, tc := range cases {
		if got := VersionsMatch(tc.ifMatch, tc.version); got != tc.want {
			t.Errorf("VersionsMatch(%q, %q) = %v, want %v", tc.ifMatch, tc.version, got, tc.want)
		}
	}
}

// TestNormalizeETagValueRefusesAList. A SCIM resource has one version, so a
// multi-ETag header is a question a storage adapter cannot answer; picking one
// would make it a coin flip whether the write lands.
func TestNormalizeETagValueRefusesAList(t *testing.T) {
	if got := NormalizeETagValue(`W/"1", W/"2"`); got != "" {
		t.Errorf("NormalizeETagValue = %q, want empty for a list", got)
	}
	if got := NormalizeETagValue(`W/"1"`); got != "1" {
		t.Errorf("NormalizeETagValue = %q, want 1", got)
	}
}

// TestSortWithoutSupportIsAnError.
//
// Returning storage order to a client that asked for userName order is the
// wrong-answer-that-looks-right case: the client cannot tell it apart from a
// directory that happens to be stored that way, and it will page through the
// result trusting an order that is not there.
func TestSortWithoutSupportIsAnError(t *testing.T) {
	manager := NewManager(&noConditionalStorage{}, metaMapper(false, ""))

	if manager.SupportsSorting() {
		t.Error("a store with no sorting support reported that it has it")
	}
	if manager.ServiceProviderConfig(100).Sort.Supported {
		t.Error("discovery advertised sort support against a store that has none")
	}

	_, err := manager.ListUsersSorted(context.Background(), ListOptions{
		StartIndex: 1, Count: 10, SortBy: "userName",
	})
	if err != ErrSortUnsupported {
		t.Errorf("error = %v, want ErrSortUnsupported", err)
	}
}

// TestUnsortedListingNeedsNoSortSupport. A deployment whose storage cannot
// sort must still be able to list, or adding the capability would be a
// prerequisite for the ordinary path.
func TestUnsortedListingNeedsNoSortSupport(t *testing.T) {
	manager := NewManager(&listOnlyStorage{}, metaMapper(false, ""))

	resp, err := manager.ListUsersSorted(context.Background(), ListOptions{StartIndex: 1, Count: 10})
	if err != nil {
		t.Fatalf("ListUsersSorted with no SortBy: %v", err)
	}
	if resp.StartIndex != 1 {
		t.Errorf("startIndex = %d, want 1", resp.StartIndex)
	}
}

// TestSortOrderDefaultsToAscending. RFC 7644 section 3.4.2.3 makes ascending
// the default; treating an unrecognised value as descending would silently
// reverse what a client asked for.
func TestSortOrderDefaultsToAscending(t *testing.T) {
	for _, order := range []string{"", "ascending", "ASCENDING", "nonsense"} {
		if (ListOptions{SortOrder: order}).Descending() {
			t.Errorf("SortOrder %q was read as descending", order)
		}
	}
	for _, order := range []string{"descending", "DESCENDING", "Descending"} {
		if !(ListOptions{SortOrder: order}).Descending() {
			t.Errorf("SortOrder %q was not read as descending", order)
		}
	}
}

// listOnlyStorage implements just enough of ScimStorage for a list call.
type listOnlyStorage struct{ ScimStorage }

func (listOnlyStorage) ListScimUsers(context.Context, string, int, int) ([]*User, int, error) {
	return nil, 0, nil
}
