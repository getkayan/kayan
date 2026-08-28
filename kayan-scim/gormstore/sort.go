package gormstore

import (
	"context"
	"fmt"

	scim "github.com/getkayan/kayan/kayan-scim"
	"gorm.io/gorm"
)

var _ scim.SortableScimStorage = (*ScimRepository)(nil)

// SupportsSorting reports that this repository can order results.
//
// It is unconditionally true: sorting needs a column, and which columns exist
// is decided per request by the same attribute mapping that filtering uses.
// An attribute the deployment did not map is refused there rather than here,
// so the answer does not depend on configuration the way conditional writes do.
func (r *ScimRepository) SupportsSorting() bool { return true }

// ListScimUsersSorted lists users ordered by opts.SortBy.
func (r *ScimRepository) ListScimUsersSorted(ctx context.Context, opts scim.ListOptions) ([]*scim.User, int, error) {
	model := r.mapper.ToModelPlaceholder()

	query := r.db.WithContext(ctx).Model(model)
	query, err := r.applyListFilter(query, opts.Filter, r.columnForPath)
	if err != nil {
		return nil, 0, err
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	query, err = applySort(query, opts, r.columnForPath)
	if err != nil {
		return nil, 0, err
	}

	rows, err := query.Offset(opts.StartIndex - 1).Limit(opts.Count).Rows()
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = rows.Close() }()

	users := make([]*scim.User, 0)
	for rows.Next() {
		instance := r.mapper.ToModelPlaceholder()
		if err := r.db.ScanRows(rows, instance); err != nil {
			return nil, 0, fmt.Errorf("scim gormstore: scan resource: %w", err)
		}
		user, err := r.mapper.FromModel(instance)
		if err != nil {
			return nil, 0, err
		}
		users = append(users, user)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("scim gormstore: read resources: %w", err)
	}
	return users, int(total), nil
}

// ListScimGroupsSorted lists groups ordered by opts.SortBy.
func (r *ScimRepository) ListScimGroupsSorted(ctx context.Context, opts scim.ListOptions) ([]*scim.Group, int, error) {
	query := r.db.WithContext(ctx).Model(&gormGroup{})
	query, err := r.applyListFilter(query, opts.Filter, groupColumnForPath)
	if err != nil {
		return nil, 0, err
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	query, err = applySort(query, opts, groupColumnForPath)
	if err != nil {
		return nil, 0, err
	}

	var groups []gormGroup
	if err := query.Offset(opts.StartIndex - 1).Limit(opts.Count).Find(&groups).Error; err != nil {
		return nil, 0, err
	}

	result := make([]*scim.Group, len(groups))
	for i, g := range groups {
		group := &scim.Group{DisplayName: g.DisplayName}
		group.ID = g.ID
		scim.ApplyGroupMeta(group, r.mapper.Config().ResourceBaseURL, g.CreatedAt, g.UpdatedAt, g.Version)
		result[i] = group
	}
	return result, int(total), nil
}

// applyListFilter narrows query by a SCIM filter expression.
func (r *ScimRepository) applyListFilter(query *gorm.DB, filter string, resolve func(scim.Path) (string, error)) (*gorm.DB, error) {
	if filter == "" {
		return query, nil
	}
	expr, err := scim.ParseFilter(filter)
	if err != nil {
		return nil, err
	}
	return applyFilter(query, expr, resolve)
}

// applySort adds the ORDER BY clause.
//
// The column comes from the deployment's own attribute mapping, never from the
// request. sortBy is client-supplied text going into a clause that cannot be
// parameterised, so resolving it through the mapping is what keeps it from
// being an injection point -- the same reason filtering resolves columns that
// way.
//
// The primary key is appended as a tiebreaker. Sorting by a non-unique column
// alone leaves rows within a tied group in no defined order, so paging through
// them has the same duplicate-and-skip problem an unordered listing has, only
// now confined to the ties -- which is harder to notice and no less wrong.
func applySort(query *gorm.DB, opts scim.ListOptions, resolve func(scim.Path) (string, error)) (*gorm.DB, error) {
	if opts.SortBy == "" {
		return query.Order("id"), nil
	}

	path, err := scim.ParsePath(opts.SortBy)
	if err != nil {
		return nil, fmt.Errorf("%w: %q", scim.ErrInvalidSortAttribute, opts.SortBy)
	}
	column, err := resolve(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %q", scim.ErrInvalidSortAttribute, opts.SortBy)
	}

	direction := "ASC"
	if opts.Descending() {
		direction = "DESC"
	}
	return query.Order(fmt.Sprintf("%s %s", column, direction)).Order("id"), nil
}
