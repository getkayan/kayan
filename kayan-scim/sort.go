package scim

import (
	"context"
	"errors"
	"strings"
)

// Sort orders (RFC 7644 section 3.4.2.3).
const (
	SortAscending  = "ascending"
	SortDescending = "descending"
)

// Errors reported by sorted listing.
var (
	// ErrSortUnsupported reports that a sort was requested but the configured
	// storage cannot apply one.
	//
	// It is an error rather than a silently unsorted result. A client that
	// asked for users by userName and received them in storage order has no
	// way to tell the difference from a directory that happens to be stored
	// that way, and it will page through that result believing the order it
	// asked for holds.
	ErrSortUnsupported = errors.New("scim: storage does not support sorting")

	// ErrInvalidSortAttribute reports a sortBy naming an attribute the
	// deployment did not map.
	//
	// Unmapped attributes are refused rather than ignored, for the same reason
	// filtering refuses them: sorting by an attribute the deployment never
	// exposed would either reach a column it did not mean to expose or quietly
	// return an order the client did not ask for.
	ErrInvalidSortAttribute = errors.New("scim: sortBy names an attribute this deployment does not expose")
)

// ListOptions carries the query parameters of a list request.
//
// It is a struct rather than more arguments so a later parameter --
// attributes, excludedAttributes, a cursor -- does not break every storage
// implementation again.
type ListOptions struct {
	// Filter is the SCIM filter expression, empty for none.
	Filter string

	// StartIndex is the 1-based index of the first result.
	StartIndex int

	// Count is the maximum number of results.
	Count int

	// SortBy is the attribute path to order by, empty for the storage's own
	// stable order.
	SortBy string

	// SortOrder is [SortAscending] or [SortDescending]. Empty means
	// ascending, which RFC 7644 section 3.4.2.3 makes the default.
	SortOrder string
}

// Descending reports whether the request asked for descending order.
//
// Anything other than "descending" is ascending, matching the specification's
// default. An unrecognised value is not an error: the specification defines
// exactly two, and treating a typo as descending would silently reverse a
// client's expected order.
func (o ListOptions) Descending() bool {
	return strings.EqualFold(o.SortOrder, SortDescending)
}

// SortableScimStorage lists resources in a requested order.
//
// It is optional. Storage that does not implement it still lists and pages
// normally; what it cannot do is honour sortBy, and [Manager.ListUsersSorted]
// says so rather than returning an arbitrary order that looks sorted.
type SortableScimStorage interface {
	// SupportsSorting reports whether this backend can order results right
	// now. Like conditional writes, implementing the interface is a
	// compile-time property while being able to use it can depend on
	// configuration -- an adapter can only sort by attributes the deployment
	// mapped to columns.
	SupportsSorting() bool

	// ListScimUsersSorted lists users, ordered by opts.SortBy. It returns
	// [ErrInvalidSortAttribute] for an attribute it cannot order by.
	ListScimUsersSorted(ctx context.Context, opts ListOptions) ([]*User, int, error)

	// ListScimGroupsSorted lists groups the same way.
	ListScimGroupsSorted(ctx context.Context, opts ListOptions) ([]*Group, int, error)
}

// SupportsSorting reports whether the configured storage can order results.
//
// [Manager.ServiceProviderConfig] uses it, so a deployment does not advertise
// sort support it would refuse.
func (m *Manager) SupportsSorting() bool {
	sortable, ok := m.storage.(SortableScimStorage)
	return ok && sortable.SupportsSorting()
}

// ListUsersSorted lists users with sorting and paging.
//
// An empty SortBy takes the ordinary listing path, so a deployment whose
// storage cannot sort still serves unsorted list requests. A non-empty SortBy
// against storage that cannot sort returns [ErrSortUnsupported].
func (m *Manager) ListUsersSorted(ctx context.Context, opts ListOptions) (*ListResponse, error) {
	opts = normalizeListOptions(opts)

	if opts.SortBy == "" {
		return m.ListUsers(ctx, opts.Filter, opts.StartIndex, opts.Count)
	}
	sortable, ok := m.storage.(SortableScimStorage)
	if !ok || !sortable.SupportsSorting() {
		return nil, ErrSortUnsupported
	}

	resources, total, err := sortable.ListScimUsersSorted(ctx, opts)
	if err != nil {
		return nil, err
	}
	return listResponse(anySlice(resources), total, opts.StartIndex), nil
}

// ListGroupsSorted lists groups with sorting and paging.
func (m *Manager) ListGroupsSorted(ctx context.Context, opts ListOptions) (*ListResponse, error) {
	opts = normalizeListOptions(opts)

	if opts.SortBy == "" {
		return m.ListGroups(ctx, opts.Filter, opts.StartIndex, opts.Count)
	}
	sortable, ok := m.storage.(SortableScimStorage)
	if !ok || !sortable.SupportsSorting() {
		return nil, ErrSortUnsupported
	}

	resources, total, err := sortable.ListScimGroupsSorted(ctx, opts)
	if err != nil {
		return nil, err
	}
	return listResponse(anySlice(resources), total, opts.StartIndex), nil
}

// normalizeListOptions applies the specification's defaults.
func normalizeListOptions(opts ListOptions) ListOptions {
	if opts.StartIndex < 1 {
		// RFC 7644 section 3.4.2.4: a value less than 1 is interpreted as 1.
		opts.StartIndex = 1
	}
	if opts.Count < 0 {
		opts.Count = defaultListCount
	}
	return opts
}

// defaultListCount bounds a list request that named no count.
const defaultListCount = 100

// anySlice widens a typed slice for the ListResponse envelope.
func anySlice[T any](values []T) []any {
	out := make([]any, len(values))
	for i, value := range values {
		out[i] = value
	}
	return out
}

// listResponse builds the SCIM list envelope.
func listResponse(resources []any, total, startIndex int) *ListResponse {
	return &ListResponse{
		Schemas:      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
		TotalResults: total,
		ItemsPerPage: len(resources),
		StartIndex:   startIndex,
		Resources:    resources,
	}
}
