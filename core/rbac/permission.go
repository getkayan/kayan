package rbac

import "strings"

// PermissionSeparator divides the segments of a permission string.
//
// Permissions are hierarchical: "billing:invoices:read" names an action within
// a resource within a domain.
const PermissionSeparator = ":"

// Wildcards usable in a granted permission.
//
// They may appear only in a grant, never in the permission being checked —
// otherwise a caller could ask "may I do anything?" and be told yes.
const (
	// WildcardSegment matches exactly one segment. "docs:*:read" matches
	// "docs:public:read" but not "docs:public:draft:read".
	WildcardSegment = "*"

	// WildcardSuffix matches one or more remaining segments. "docs:**" matches
	// "docs:read" and "docs:public:draft:read". It must be the last segment.
	WildcardSuffix = "**"
)

// PermissionGranted reports whether a granted permission covers a requested
// one.
//
// Matching is segment-wise rather than by regular expression: a regex in a
// permission string is a denial-of-service vector, and its semantics are
// unclear to whoever writes the grant. Segments are compared case-sensitively,
// since "Admin" and "admin" being the same permission is a surprise nobody
// asked for.
//
//	PermissionGranted("users:*", "users:delete")        // true
//	PermissionGranted("users:read", "users:delete")     // false
//	PermissionGranted("docs:**", "docs:a:b:c")          // true
//	PermissionGranted("docs:*", "docs:a:b")             // false
//	PermissionGranted("*", "anything")                  // true
//	PermissionGranted("users:read", "users:*")          // false
func PermissionGranted(granted, requested string) bool {
	if granted == "" || requested == "" {
		return false
	}
	if granted == requested {
		return true
	}

	// A wildcard in the request would let a caller probe for any permission at
	// all. Only a grant may widen.
	if strings.Contains(requested, WildcardSegment) {
		return false
	}

	grantedParts := strings.Split(granted, PermissionSeparator)
	requestedParts := strings.Split(requested, PermissionSeparator)

	for i, part := range grantedParts {
		if part == WildcardSuffix {
			// "**" must be last, and covers every remaining segment. It
			// matches at least one, so "docs:**" does not grant bare "docs".
			return i == len(grantedParts)-1 && i < len(requestedParts)
		}

		if i >= len(requestedParts) {
			// The grant is more specific than the request: "users:read:own"
			// does not grant "users:read".
			return false
		}
		if part == WildcardSegment {
			continue
		}
		if part != requestedParts[i] {
			return false
		}
	}

	// Every granted segment matched; the request must not have more.
	return len(grantedParts) == len(requestedParts)
}

// AnyPermissionGranted reports whether any of the granted permissions covers
// the requested one.
func AnyPermissionGranted(granted []string, requested string) bool {
	for _, g := range granted {
		if PermissionGranted(g, requested) {
			return true
		}
	}
	return false
}
