package scim

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Meta member names, as they appear in [MapperConfig.MetaMappings]
// (RFC 7643 section 3.1).
const (
	MetaCreated      = "created"
	MetaLastModified = "lastModified"
	MetaVersion      = "version"
)

// Resource type names used in meta.resourceType and in the location path.
const (
	ResourceTypeUser  = "User"
	ResourceTypeGroup = "Group"
)

// applyMeta fills in the meta complex attribute for a resource.
//
// Every SCIM response this library produced carried an empty meta. The
// attribute is not decoration: provisioning connectors read resourceType to
// tell a User from a Group in a bulk response, follow location to address the
// resource, and compare lastModified to decide what changed since their last
// sync. A connector that receives none of it either re-reads everything on
// every cycle or, worse, treats the resource as unchanged.
//
// created and lastModified come from the caller's own model through
// [MapperConfig.MetaMappings], because BYOS means this library does not own
// that struct and cannot add columns to it. Unmapped members are omitted
// rather than invented -- a lastModified of "now" on every read would tell a
// connector that everything changed on every cycle.
func applyMeta(meta *Meta, resourceType, id, baseURL string, created, lastModified time.Time, version string) {
	meta.ResourceType = resourceType
	if !created.IsZero() {
		meta.Created = created.UTC()
	}
	if !lastModified.IsZero() {
		meta.LastModified = lastModified.UTC()
	}
	if location := resourceLocation(baseURL, resourceType, id); location != "" {
		meta.Location = location
	}
	if version != "" {
		meta.Version = version
	}
}

// resourceLocation builds meta.location.
//
// It returns empty when no base URL was configured. Kayan has no router and
// cannot know the URL it is served under, so guessing one would put an address
// in the response that resolves nowhere -- worse than omitting the member,
// which a connector is required to tolerate.
func resourceLocation(baseURL, resourceType, id string) string {
	if baseURL == "" || id == "" {
		return ""
	}
	var collection string
	switch resourceType {
	case ResourceTypeUser:
		collection = "Users"
	case ResourceTypeGroup:
		collection = "Groups"
	default:
		return ""
	}
	return strings.TrimRight(baseURL, "/") + "/" + collection + "/" + id
}

// deriveVersion computes a weak ETag from a resource's own content.
//
// It is used when the deployment maps no version field. A content hash is a
// correct ETag for caching -- If-None-Match answers "has this changed?"
// exactly right -- but it is NOT sufficient for compare-and-swap, because
// checking it and then writing is two operations and another writer fits
// between them. Conditional writes therefore require
// [ConditionalScimStorage] rather than being layered on top of this.
//
// The weak form (W/) is correct here: two encodings of the same resource that
// differ only in field order are semantically equivalent, and the hash is over
// the marshalled form rather than the bytes any particular response carried.
func deriveVersion(resource any) string {
	// Callers hash the resource before meta is populated, so the version does
	// not depend on itself.
	encoded, err := json.Marshal(resource)
	if err != nil {
		// Unreachable for the resource types in this package, all of which
		// marshal. An empty version omits the member, which is the honest
		// answer when one could not be computed -- returning a constant would
		// make every resource compare equal.
		return ""
	}
	sum := sha256.Sum256(encoded)
	return fmt.Sprintf("W/%q", base64.RawURLEncoding.EncodeToString(sum[:16]))
}

// asTime coerces a mapped struct field into a time.
//
// Deployments store timestamps as time.Time, as a pointer to one, or as a Unix
// second count. Anything else is reported as absent rather than guessed at.
func asTime(value any) (time.Time, bool) {
	switch typed := value.(type) {
	case time.Time:
		return typed, !typed.IsZero()
	case *time.Time:
		if typed == nil {
			return time.Time{}, false
		}
		return *typed, !typed.IsZero()
	case int64:
		if typed == 0 {
			return time.Time{}, false
		}
		return time.Unix(typed, 0).UTC(), true
	}
	return time.Time{}, false
}

// asVersion coerces a mapped struct field into an ETag value.
//
// A GORM optimistic-lock column is an integer; a deployment that keeps its own
// revision string is a string. Both are wrapped in the weak-ETag form, since
// a bare integer is not a syntactically valid ETag and a client comparing it
// against an If-Match header would never match.
func asVersion(value any) string {
	switch typed := value.(type) {
	case string:
		if typed == "" {
			return ""
		}
		if strings.HasPrefix(typed, `W/"`) || strings.HasPrefix(typed, `"`) {
			// Already an ETag. Wrapping it again would produce a value that
			// matches nothing.
			return typed
		}
		return fmt.Sprintf("W/%q", typed)
	case int:
		return fmt.Sprintf(`W/"%d"`, typed)
	case int64:
		return fmt.Sprintf(`W/"%d"`, typed)
	case uint:
		return fmt.Sprintf(`W/"%d"`, typed)
	case uint64:
		return fmt.Sprintf(`W/"%d"`, typed)
	case time.Time:
		if typed.IsZero() {
			return ""
		}
		// A modification timestamp is a usable version, but only at the
		// precision it is stored with: two writes inside one tick produce the
		// same value, and a client would not see the second.
		return fmt.Sprintf(`W/"%d"`, typed.UTC().UnixNano())
	}
	return ""
}

// VersionsMatch reports whether an If-Match header value matches version.
//
// The header may carry several ETags, or the wildcard "*" which matches any
// existing resource (RFC 7232 section 3.1). Comparison ignores the weak
// prefix: RFC 7232 requires the strong form for If-Match, but SCIM versions
// are weak by nature and every provisioning client returns the value it was
// given, so refusing it would make conditional writes unusable in practice.
func VersionsMatch(ifMatch, version string) bool {
	ifMatch = strings.TrimSpace(ifMatch)
	if ifMatch == "" {
		return false
	}
	if ifMatch == "*" {
		return true
	}
	for _, candidate := range strings.Split(ifMatch, ",") {
		if normalizeETag(candidate) == normalizeETag(version) && version != "" {
			return true
		}
	}
	return false
}

// NormalizeETagValue recovers the stored scalar an ETag was built from.
//
// [asVersion] wraps a stored value as W/"<value>", so this is the exact
// inverse rather than a guess. Storage adapters need it to turn a client's
// If-Match header back into something they can compare a column against.
//
// A header carrying several ETags returns empty. A SCIM resource has one
// version, so a list is a question this cannot answer, and picking one of them
// would make it a coin flip whether the write lands.
func NormalizeETagValue(ifMatch string) string {
	if strings.Contains(ifMatch, ",") {
		return ""
	}
	return normalizeETag(ifMatch)
}

// normalizeETag strips the weak prefix and surrounding quotes.
func normalizeETag(value string) string {
	value = strings.TrimSpace(value)
	value = strings.TrimPrefix(value, "W/")
	value = strings.TrimPrefix(value, `"`)
	value = strings.TrimSuffix(value, `"`)
	return value
}

// ApplyGroupMeta fills in a group's meta attribute.
//
// It is exported because a [ScimStorage] implementation builds Group values
// directly rather than through the [Mapper], and a group whose meta a store
// forgot to fill would be indistinguishable in a response from a user's -- no
// resourceType, no location for a connector to follow.
//
// Pass zero times for timestamps the store does not keep; they are omitted
// rather than filled with the current time, which would report every group as
// having just changed.
// version is the store's own revision value -- an integer counter, a revision
// string, or a modification time. Pass nil where the store keeps none, and the
// version is derived from the group's content instead: correct for caching,
// not usable for compare-and-swap.
func ApplyGroupMeta(group *Group, baseURL string, created, lastModified time.Time, version any) {
	if group == nil {
		return
	}
	etag := asVersion(version)
	if etag == "" {
		// Hashed before meta is written, so it does not depend on itself.
		etag = deriveVersion(group)
	}
	applyMeta(&group.Meta, ResourceTypeGroup, group.ID, baseURL, created, lastModified, etag)
}
