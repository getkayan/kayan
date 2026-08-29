package admin

import (
	"context"
	"fmt"
)

// ResolveCaller builds a [Caller] for a user from the stores this manager was
// given.
//
// Nothing else bridges a user id to a Caller, and without that bridge custom
// roles do nothing. authorize resolves Caller.Roles against
// [DefaultRolePermissions], a fixed table of the built-in role names; a role
// created with [Manager.CreateRole] is not in it, so a Caller carrying that
// role name grants no permission at all. The refusal is safe -- it denies
// rather than allows -- but it looks like the role system is broken rather
// than like a missing step, and the missing step was not written down
// anywhere.
//
// This performs it: the user's roles come from the role store, their
// permissions are flattened onto the Caller, and the role names are kept so
// the built-in table still applies to anyone holding a built-in role.
//
// Call it once per request and pass the result to the admin operations, rather
// than resolving inside authorize -- that would put a storage round trip on
// every permission check.
//
//	caller, err := manager.ResolveCaller(ctx, userID)
//	if err != nil {
//	    return err // deny; never fall back to an empty Caller
//	}
//	users, err := manager.ListUsers(ctx, caller, admin.ListOptions{})
//
// An error must be treated as a denial. Returning a zero Caller on failure
// would hand the operation something that authorizes nothing -- which is the
// safe direction -- but a caller that ignored the error and reused a stale
// Caller would not notice a revoked role, so the error is the answer.
func (m *Manager) ResolveCaller(ctx context.Context, userID any) (*Caller, error) {
	if m.users == nil || m.roles == nil {
		return nil, ErrNotConfigured
	}

	user, err := m.users.Get(ctx, userID)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, ErrNotFound
	}
	// A locked or deleted account must not authorize anything. Resolving one
	// into a working Caller would let a disabled administrator keep acting for
	// as long as something held the value.
	if user.State != UserStateActive {
		return nil, fmt.Errorf("%w: user is %s", ErrForbidden, user.State)
	}

	roles, err := m.roles.GetUserRoles(ctx, userID)
	if err != nil {
		return nil, err
	}

	caller := &Caller{
		ID:       fmt.Sprintf("%v", user.ID),
		TenantID: user.TenantID,
	}
	seen := map[string]bool{}
	for _, role := range roles {
		caller.Roles = append(caller.Roles, role.Name)
		for _, permission := range role.Permissions {
			if seen[permission] {
				continue
			}
			seen[permission] = true
			caller.Permissions = append(caller.Permissions, permission)
		}
	}

	// IsSuperAdmin is deliberately not derived from a role name. It bypasses
	// the permission table entirely, so granting it must be an explicit act by
	// the application rather than a consequence of naming a role "superadmin"
	// -- which anyone with role-write permission could otherwise do to
	// themselves.
	return caller, nil
}
