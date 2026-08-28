package gormstore

import (
	"context"
	"fmt"

	scim "github.com/getkayan/kayan/kayan-scim"
	"gorm.io/gorm"
)

var _ scim.ConditionalScimStorage = (*ScimRepository)(nil)

// SupportsConditionalWrites reports whether this repository can compare and
// swap.
//
// Groups always can: gormGroup is this package's own model and carries a
// version counter. Users can only when the deployment mapped a version field
// on its own struct, because BYOS means this package does not own that struct
// and cannot add a column to it. Both must hold, since advertising etag
// support that covers only half the resource types would have a connector send
// If-Match on a user and receive an answer that ignored it.
func (r *ScimRepository) SupportsConditionalWrites() bool {
	return r.userVersionColumn() != ""
}

// userVersionColumn returns the column backing the user's version, or empty
// when the deployment mapped none.
func (r *ScimRepository) userVersionColumn() string {
	field, ok := r.mapper.Config().MetaMappings[scim.MetaVersion]
	if !ok || field == "" {
		return ""
	}
	return toColumnName(field)
}

// UpdateScimUserIfMatch writes user only if the stored version still matches.
//
// The comparison and the write are one statement. Reading the version and then
// writing would leave a window for another connector's update, which is the
// lost update the precondition exists to prevent -- and the caller would be
// told the precondition held.
func (r *ScimRepository) UpdateScimUserIfMatch(ctx context.Context, user *scim.User, ifMatch string) error {
	column := r.userVersionColumn()
	if column == "" {
		return scim.ErrConditionalUnsupported
	}

	model, err := r.mapper.ToModel(user)
	if err != nil {
		return err
	}

	query := r.db.WithContext(ctx).Model(model).Where("id = ?", user.ID)
	query, err = whereVersionMatches(query, column, ifMatch)
	if err != nil {
		return err
	}

	result := query.Updates(model)
	if result.Error != nil {
		return result.Error
	}
	// Zero rows means the id was gone or the version had moved on. Both are a
	// failed precondition from the client's point of view, and neither wrote
	// anything.
	if result.RowsAffected == 0 {
		return scim.ErrPreconditionFailed
	}
	return nil
}

// DeleteScimUserIfMatch removes a user only on a version match.
func (r *ScimRepository) DeleteScimUserIfMatch(ctx context.Context, id, ifMatch string) error {
	column := r.userVersionColumn()
	if column == "" {
		return scim.ErrConditionalUnsupported
	}

	model := r.mapper.ToModelPlaceholder()
	query := r.db.WithContext(ctx).Model(model).Where("id = ?", id)
	query, err := whereVersionMatches(query, column, ifMatch)
	if err != nil {
		return err
	}

	result := query.Delete(model)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return scim.ErrPreconditionFailed
	}
	return nil
}

// UpdateScimGroupIfMatch writes a group only if its version counter still
// matches, and increments it.
//
// The increment is part of the same statement. A separate read-modify-write on
// the counter would reintroduce exactly the race the counter exists to close.
func (r *ScimRepository) UpdateScimGroupIfMatch(ctx context.Context, group *scim.Group, ifMatch string) error {
	query := r.db.WithContext(ctx).Model(&gormGroup{}).Where("id = ?", group.ID)
	query, err := whereVersionMatches(query, "version", ifMatch)
	if err != nil {
		return err
	}

	result := query.Updates(map[string]any{
		"display_name": group.DisplayName,
		"version":      gorm.Expr("version + 1"),
	})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return scim.ErrPreconditionFailed
	}
	return nil
}

// DeleteScimGroupIfMatch removes a group only on a version match.
func (r *ScimRepository) DeleteScimGroupIfMatch(ctx context.Context, id, ifMatch string) error {
	query := r.db.WithContext(ctx).Model(&gormGroup{}).Where("id = ?", id)
	query, err := whereVersionMatches(query, "version", ifMatch)
	if err != nil {
		return err
	}

	result := query.Delete(&gormGroup{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return scim.ErrPreconditionFailed
	}
	return nil
}

// whereVersionMatches narrows query to rows whose version satisfies ifMatch.
//
// The wildcard adds no predicate: "*" means any existing resource, and the id
// predicate already expresses existence.
//
// Otherwise the ETag is unwrapped back to the stored scalar it was built
// from. asVersion wraps that scalar as W/"<value>", so the client returns the
// quoted weak form and the raw header string never equals the column; the
// unwrapping is exact rather than a guess. The comparison itself stays inside
// the single UPDATE, which is what makes this a compare-and-swap.
func whereVersionMatches(query *gorm.DB, column, ifMatch string) (*gorm.DB, error) {
	if ifMatch == "*" {
		return query, nil
	}
	stored, err := extractVersionOperand(ifMatch)
	if err != nil {
		return nil, err
	}
	return query.Where(fmt.Sprintf("%s = ?", column), stored), nil
}

// extractVersionOperand recovers the stored value an ETag was built from.
//
// asVersion wraps the stored scalar as W/"<value>", so unwrapping is exact
// rather than a guess. A header carrying several ETags is refused: SCIM
// resources have one version, so a list means the client is asking a question
// this cannot answer, and picking one of them would be a coin flip on whether
// the write lands.
func extractVersionOperand(ifMatch string) (string, error) {
	value := scim.NormalizeETagValue(ifMatch)
	if value == "" {
		return "", scim.ErrPreconditionFailed
	}
	return value, nil
}
