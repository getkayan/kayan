package scim

import (
	"errors"
	"fmt"
	"strings"
)

// ErrAttributeNotQueryable reports a filter or sortBy naming an attribute
// whose value is never returned. Serve it as HTTP 400 with scimType
// "invalidFilter" (or "invalidValue" for sortBy).
//
// Redacting the attribute from responses is not enough on its own. A storage
// that maps "password" to a column answers `password sw "$2a$10$A"` through
// totalResults, so the stored hash is recoverable one character at a time,
// and sortBy=password leaks its ordering the same way.
var ErrAttributeNotQueryable = errors.New("scim: attribute cannot be filtered or sorted on")

// neverReturned reports whether an attribute has returned="never" in the core
// User schema (RFC 7643 section 4.1.1).
func neverReturned(path Path) bool {
	return strings.EqualFold(path.Attribute, "password")
}

// redactUser returns a copy of u with every never-returned attribute cleared.
//
// A copy rather than an in-place clear: the value may be the caller's own
// request body or a record a storage implementation still holds.
func redactUser(u *User) *User {
	if u == nil {
		return nil
	}
	c := *u
	c.Password = ""
	return &c
}

// redactUsers redacts a storage listing into list-response resources.
func redactUsers(users []*User) []any {
	out := make([]any, len(users))
	for i, u := range users {
		out[i] = redactUser(u)
	}
	return out
}

// checkQueryable refuses a filter or sortBy that names a never-returned
// attribute. A filter that does not parse is refused too: storage parses it
// with the same parser, so it would fail there anyway, and letting it through
// unchecked would make the check depend on that.
func checkQueryable(filter, sortBy string) error {
	if filter != "" {
		expr, err := ParseFilter(filter)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrInvalidFilter, err)
		}
		if filterNamesNeverReturned(expr) {
			return fmt.Errorf("%w: filter", ErrAttributeNotQueryable)
		}
	}
	if sortBy != "" {
		path, err := ParsePath(sortBy)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrInvalidSortAttribute, err)
		}
		if neverReturned(path) {
			return fmt.Errorf("%w: sortBy", ErrAttributeNotQueryable)
		}
	}
	return nil
}

func filterNamesNeverReturned(expr FilterExpr) bool {
	switch e := expr.(type) {
	case Comparison:
		return pathNamesNeverReturned(e.Path)
	case ValuePath:
		return pathNamesNeverReturned(e.Path)
	case And:
		return filterNamesNeverReturned(e.Left) || filterNamesNeverReturned(e.Right)
	case Or:
		return filterNamesNeverReturned(e.Left) || filterNamesNeverReturned(e.Right)
	case Not:
		return filterNamesNeverReturned(e.Expr)
	default:
		// An expression this walk does not know is refused: a new node type
		// must not become a way past the check.
		return true
	}
}

func pathNamesNeverReturned(path Path) bool {
	if neverReturned(path) {
		return true
	}
	return path.Filter != nil && filterNamesNeverReturned(path.Filter)
}
