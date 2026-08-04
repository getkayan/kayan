package rbac

import (
	"context"
	"errors"
	"fmt"
)

// Errors reported by this package.
var (
	// ErrRoleNotFound reports a role that has no definition.
	//
	// It is an error rather than a silent denial: a permission check that
	// quietly returns false because the definition is missing looks identical
	// to a legitimate refusal, and the two need different responses.
	ErrRoleNotFound = errors.New("rbac: role is not defined")

	// ErrCycle reports a cycle in role inheritance.
	ErrCycle = errors.New("rbac: role inheritance contains a cycle")
)

// MaxInheritanceDepth bounds how far role inheritance is followed.
//
// Cycles are detected directly, so this only stops a pathological chain from
// costing more than it is worth.
const MaxInheritanceDepth = 32

// Role is a named set of permissions, optionally inheriting from others.
type Role struct {
	Name        string
	Permissions []string

	// Inherits names roles whose permissions this role also has. An admin
	// inheriting from editor gets every editor permission without restating
	// them, so the two cannot drift apart.
	Inherits []string

	// Description is for administrative interfaces.
	Description string
}

// RoleStore persists role definitions.
//
// Definitions live in storage rather than in process memory because they are
// shared state: a role created on one replica must be visible to the next
// request, whichever replica serves it.
type RoleStore interface {
	// GetRole returns a role definition, or [ErrRoleNotFound].
	GetRole(ctx context.Context, name string) (*Role, error)

	// SaveRole creates or replaces a role definition.
	SaveRole(ctx context.Context, role *Role) error

	// DeleteRole removes a role definition.
	DeleteRole(ctx context.Context, name string) error

	// ListRoles returns every defined role.
	ListRoles(ctx context.Context) ([]*Role, error)
}

// resolvePermissions collects a role's permissions along with those of every
// role it inherits.
//
// visiting tracks the current path so a cycle is reported rather than followed
// until the stack runs out.
func resolvePermissions(
	ctx context.Context,
	store RoleStore,
	name string,
	visiting map[string]bool,
	depth int,
) ([]string, error) {
	if depth > MaxInheritanceDepth {
		return nil, fmt.Errorf("%w: %q exceeds depth %d", ErrCycle, name, MaxInheritanceDepth)
	}
	if visiting[name] {
		return nil, fmt.Errorf("%w: %q", ErrCycle, name)
	}

	role, err := store.GetRole(ctx, name)
	if err != nil {
		return nil, err
	}

	visiting[name] = true
	defer delete(visiting, name)

	permissions := make([]string, 0, len(role.Permissions))
	permissions = append(permissions, role.Permissions...)

	for _, parent := range role.Inherits {
		inherited, err := resolvePermissions(ctx, store, parent, visiting, depth+1)
		if err != nil {
			// A missing parent is a broken definition, not an absence of
			// permission. Reporting it lets an operator fix the role instead
			// of debugging a mysterious denial.
			return nil, fmt.Errorf("rbac: role %q inherits %q: %w", name, parent, err)
		}
		permissions = append(permissions, inherited...)
	}

	return permissions, nil
}

// dedupe returns the unique values of in, preserving order.
func dedupe(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, value := range in {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}
