package scim

import (
	"context"
	"errors"
)

// Errors reported by conditional operations.
var (
	// ErrPreconditionFailed reports that the resource's current version does
	// not match the one the request required. Serve it as HTTP 412
	// (RFC 7644 section 3.14).
	ErrPreconditionFailed = errors.New("scim: resource version does not match the supplied precondition")

	// ErrConditionalUnsupported reports that a precondition was supplied but
	// the configured storage cannot honour it atomically.
	//
	// It is an error rather than a silent fallback. Checking the version and
	// then writing is two operations, and a second writer fits between them,
	// so a fallback would answer "your update was applied against the version
	// you named" when it was not -- the lost update the precondition existed
	// to prevent, now with a receipt saying it did not happen.
	ErrConditionalUnsupported = errors.New("scim: storage does not support conditional writes")
)

// ConditionalScimStorage performs version-checked writes.
//
// It is optional. A storage backend that does not implement it works
// normally; what it cannot do is honour an If-Match header, and
// [Manager.UpdateUserIfMatch] and its siblings say so rather than pretending.
//
// The check and the write are one method for the same reason
// [oauth2.ClientAssertionStore] consumes in one call: the guarantee is
// compare-and-swap, and an interface that let a caller read the version and
// write separately would place the race in every implementation. In SQL this
// is UPDATE ... WHERE id = ? AND version = ?, with a zero row count reported
// as [ErrPreconditionFailed].
//
// This is what SCIM's optimistic concurrency actually protects: two
// provisioning connectors -- or one connector retrying -- issuing overlapping
// PATCHes to the same group. Without it the second write silently reverts the
// first, so a removed member reappears and an audit trail shows both
// operations succeeded.
type ConditionalScimStorage interface {
	// SupportsConditionalWrites reports whether this backend can actually
	// compare and swap right now.
	//
	// Implementing the interface is a compile-time property; being able to use
	// it can depend on configuration. The GORM store, for instance, can
	// compare and swap a user only when the deployment mapped a version field
	// on its own model, since BYOS means the store does not own that struct.
	// Discovery reads this, so a deployment that cannot honour If-Match does
	// not advertise that it can.
	SupportsConditionalWrites() bool

	// UpdateScimUserIfMatch writes user only if its stored version matches
	// one of the ETags in ifMatch, and returns [ErrPreconditionFailed]
	// otherwise. The wildcard "*" matches any existing resource.
	UpdateScimUserIfMatch(ctx context.Context, user *User, ifMatch string) error

	// DeleteScimUserIfMatch deletes only on a version match.
	DeleteScimUserIfMatch(ctx context.Context, id, ifMatch string) error

	// UpdateScimGroupIfMatch writes group only on a version match.
	UpdateScimGroupIfMatch(ctx context.Context, group *Group, ifMatch string) error

	// DeleteScimGroupIfMatch deletes only on a version match.
	DeleteScimGroupIfMatch(ctx context.Context, id, ifMatch string) error
}

// SupportsConditionalWrites reports whether the configured storage can honour
// an If-Match precondition.
//
// [BuildDiscovery] uses it so the service provider configuration advertises
// etag support only where it exists. A client that reads etag: true starts
// sending If-Match and expects 412 on a conflict; against a backend that
// cannot compare and swap, every one of those requests would be answered as
// though the precondition held.
func (m *Manager) SupportsConditionalWrites() bool {
	conditional, ok := m.storage.(ConditionalScimStorage)
	return ok && conditional.SupportsConditionalWrites()
}

// conditionalStorage returns the storage as a conditional one, or an error
// naming what is missing.
func (m *Manager) conditionalStorage() (ConditionalScimStorage, error) {
	conditional, ok := m.storage.(ConditionalScimStorage)
	if !ok || !conditional.SupportsConditionalWrites() {
		return nil, ErrConditionalUnsupported
	}
	return conditional, nil
}

// UpdateUserIfMatch replaces a user only if its current version matches
// ifMatch.
//
// ifMatch is the If-Match header value verbatim, including quotes and any
// weak prefix; "*" matches any existing resource. An empty ifMatch is an
// error, because a conditional call with no condition is a caller bug that
// would otherwise become an unconditional write.
//
// Returns [ErrPreconditionFailed] on a version mismatch -- serve HTTP 412 --
// and [ErrConditionalUnsupported] when the storage cannot compare and swap.
func (m *Manager) UpdateUserIfMatch(ctx context.Context, id string, user *User, ifMatch string) (*User, error) {
	if ifMatch == "" {
		return nil, NewError("400", "invalidValue", "If-Match is required for a conditional update")
	}
	conditional, err := m.conditionalStorage()
	if err != nil {
		return nil, err
	}

	user.ID = id
	if err := conditional.UpdateScimUserIfMatch(ctx, user, ifMatch); err != nil {
		return nil, err
	}
	// Read back so the returned resource carries the version the write
	// produced. Returning the request body would hand the client the ETag it
	// sent, which its next conditional write would then present as current.
	return m.GetUser(ctx, id)
}

// DeleteUserIfMatch removes a user only on a version match.
func (m *Manager) DeleteUserIfMatch(ctx context.Context, id, ifMatch string) error {
	if ifMatch == "" {
		return NewError("400", "invalidValue", "If-Match is required for a conditional delete")
	}
	conditional, err := m.conditionalStorage()
	if err != nil {
		return err
	}
	return conditional.DeleteScimUserIfMatch(ctx, id, ifMatch)
}

// UpdateGroupIfMatch replaces a group only on a version match.
//
// This is the operation that most needs it. Okta and Entra both maintain group
// membership by reading a group, computing a change, and writing it back; two
// of those cycles overlapping means the second silently discards the first's
// membership change.
func (m *Manager) UpdateGroupIfMatch(ctx context.Context, id string, group *Group, ifMatch string) (*Group, error) {
	if ifMatch == "" {
		return nil, NewError("400", "invalidValue", "If-Match is required for a conditional update")
	}
	conditional, err := m.conditionalStorage()
	if err != nil {
		return nil, err
	}

	group.ID = id
	if err := conditional.UpdateScimGroupIfMatch(ctx, group, ifMatch); err != nil {
		return nil, err
	}
	return m.GetGroup(ctx, id)
}

// DeleteGroupIfMatch removes a group only on a version match.
func (m *Manager) DeleteGroupIfMatch(ctx context.Context, id, ifMatch string) error {
	if ifMatch == "" {
		return NewError("400", "invalidValue", "If-Match is required for a conditional delete")
	}
	conditional, err := m.conditionalStorage()
	if err != nil {
		return err
	}
	return conditional.DeleteScimGroupIfMatch(ctx, id, ifMatch)
}
