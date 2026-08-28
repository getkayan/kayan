// Package gormstore persists SCIM resources with GORM.
//
// It is one implementation of [scim.ScimStorage]. Any other backend — Mongo,
// a filesystem, a bespoke service — satisfies the same interface and drops in
// without changes elsewhere.
package gormstore

import (
	"context"
	"fmt"
	"strings"
	"time"

	scim "github.com/getkayan/kayan/kayan-scim"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type ScimRepository struct {
	db     *gorm.DB
	mapper *scim.Mapper
}

func NewScimRepository(db *gorm.DB, mapper *scim.Mapper) *ScimRepository {
	return &ScimRepository{
		db:     db,
		mapper: mapper,
	}
}

func (r *ScimRepository) CreateScimUser(ctx context.Context, user *scim.User) error {
	model, err := r.mapper.ToModel(user)
	if err != nil {
		return err
	}
	if err := r.db.WithContext(ctx).Create(model).Error; err != nil {
		return err
	}
	// Map back to update ID and other fields
	updated, err := r.mapper.FromModel(model)
	if err != nil {
		return err
	}
	*user = *updated
	return nil
}

func (r *ScimRepository) GetScimUser(ctx context.Context, id string) (*scim.User, error) {
	model, err := r.getIdentityModel(ctx, id)
	if err != nil {
		return nil, err
	}
	return r.mapper.FromModel(model)
}

func (r *ScimRepository) FindScimUserByUserName(ctx context.Context, userName string) (*scim.User, error) {
	// Look up which struct field userName maps to
	structField, ok := r.mapper.Config().FieldMappings["userName"]
	if !ok {
		return nil, scim.NewError("500", "internal", "userName mapping missing")
	}

	model := r.mapper.ToModelPlaceholder()
	if err := r.db.WithContext(ctx).Where(fmt.Sprintf("%s = ?", structField), userName).First(model).Error; err != nil {
		return nil, scim.ErrNotFound
	}
	return r.mapper.FromModel(model)
}

func (r *ScimRepository) UpdateScimUser(ctx context.Context, user *scim.User) error {
	model, err := r.mapper.ToModel(user)
	if err != nil {
		return err
	}
	return r.db.WithContext(ctx).Save(model).Error
}

func (r *ScimRepository) DeleteScimUser(ctx context.Context, id string) error {
	model := r.mapper.ToModelPlaceholder() // Should yield an empty model
	return r.db.WithContext(ctx).Delete(model, "id = ?", id).Error
}

func (r *ScimRepository) ListScimUsers(ctx context.Context, filter string, startIndex, count int) ([]*scim.User, int, error) {
	m := r.mapper.ToModelPlaceholder()

	query := r.db.WithContext(ctx).Model(m)
	if filter != "" {
		expr, err := scim.ParseFilter(filter)
		if err != nil {
			return nil, 0, err
		}
		query, err = applyFilter(query, expr, r.columnForPath)
		if err != nil {
			return nil, 0, err
		}
	}

	// Count before paging, so the caller learns how many resources match
	// rather than how many are on this page.
	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	rows, err := query.Offset(startIndex - 1).Limit(count).Rows()
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	users := make([]*scim.User, 0)
	for rows.Next() {
		inst := r.mapper.ToModelPlaceholder()
		if err := r.db.ScanRows(rows, inst); err != nil {
			return nil, 0, fmt.Errorf("scim gormstore: scan resource: %w", err)
		}
		u, err := r.mapper.FromModel(inst)
		if err == nil && u != nil {
			users = append(users, u)
		}
	}

	return users, int(total), nil
}

// Group implementations (Basic GORM implementations)

func (r *ScimRepository) CreateScimGroup(ctx context.Context, group *scim.Group) error {
	// A group created without an ID needs one assigned. Without this, every
	// such group shares the empty primary key and the second insert fails on
	// a constraint the caller cannot see.
	if group.ID == "" {
		group.ID = uuid.NewString()
	}

	g := &gormGroup{
		ID:          group.ID,
		DisplayName: group.DisplayName,
		Version:     1,
	}
	return r.db.WithContext(ctx).Create(g).Error
}

func (r *ScimRepository) GetScimGroup(ctx context.Context, id string) (*scim.Group, error) {
	var g gormGroup
	if err := r.db.WithContext(ctx).First(&g, "id = ?", id).Error; err != nil {
		return nil, scim.ErrNotFound
	}
	res := &scim.Group{
		DisplayName: g.DisplayName,
	}
	res.ID = g.ID
	scim.ApplyGroupMeta(res, r.mapper.Config().ResourceBaseURL, g.CreatedAt, g.UpdatedAt, g.Version)
	return res, nil
}

func (r *ScimRepository) UpdateScimGroup(ctx context.Context, group *scim.Group) error {
	// The version advances on an unconditional write too. A client that read
	// the group, then had it changed underneath by this path, must not find
	// its stale ETag still matching.
	result := r.db.WithContext(ctx).Model(&gormGroup{}).Where("id = ?", group.ID).
		Updates(map[string]any{
			"display_name": group.DisplayName,
			"version":      gorm.Expr("version + 1"),
		})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return scim.ErrNotFound
	}
	return nil
}

func (r *ScimRepository) DeleteScimGroup(ctx context.Context, id string) error {
	return r.db.WithContext(ctx).Delete(&gormGroup{}, "id = ?", id).Error
}

func (r *ScimRepository) ListScimGroups(ctx context.Context, filter string, startIndex, count int) ([]*scim.Group, int, error) {
	query := r.db.WithContext(ctx).Model(&gormGroup{})
	if filter != "" {
		expr, err := scim.ParseFilter(filter)
		if err != nil {
			return nil, 0, err
		}
		query, err = applyFilter(query, expr, groupColumnForPath)
		if err != nil {
			return nil, 0, err
		}
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	var groups []gormGroup
	if err := query.Offset(startIndex - 1).Limit(count).Find(&groups).Error; err != nil {
		return nil, 0, err
	}

	res := make([]*scim.Group, len(groups))
	for i, g := range groups {
		group := &scim.Group{
			DisplayName: g.DisplayName,
		}
		group.ID = g.ID
		scim.ApplyGroupMeta(group, r.mapper.Config().ResourceBaseURL, g.CreatedAt, g.UpdatedAt, g.Version)
		res[i] = group
	}
	return res, int(total), nil
}

func (r *ScimRepository) getIdentityModel(ctx context.Context, id string) (any, error) {
	model := r.mapper.ToModelPlaceholder()
	if err := r.db.WithContext(ctx).First(model, "id = ?", id).Error; err != nil {
		return nil, err
	}
	return model, nil
}

// gormGroup is the persisted form of a SCIM group.
type gormGroup struct {
	ID          string `gorm:"primaryKey"`
	DisplayName string `gorm:"uniqueIndex"`
	// CreatedAt and UpdatedAt back meta.created and meta.lastModified. GORM
	// maintains both by name. A provisioning connector compares lastModified
	// to decide what changed since its last sync, so without them every cycle
	// either re-reads everything or concludes nothing moved.
	CreatedAt time.Time
	UpdatedAt time.Time
	// Version is the optimistic-concurrency counter behind meta.version. It is
	// incremented inside the same UPDATE that checks it, so two overlapping
	// membership edits cannot both succeed against the same starting state.
	Version uint64 `gorm:"not null;default:1"`
}

func (gormGroup) TableName() string { return "scim_groups" }

// AutoMigrate creates the tables this repository needs.
//
// For development only. Production deployments should run versioned
// migrations; see the module README.
func (r *ScimRepository) AutoMigrate() error {
	return r.db.AutoMigrate(&gormGroup{})
}

// columnForPath resolves a SCIM attribute path to a database column on the
// caller's user model.
//
// The mapping is the one supplied at construction, so an attribute the
// deployment did not map is refused rather than guessed at. That also keeps a
// filter from reaching a column the deployment never meant to expose.
func (r *ScimRepository) columnForPath(path scim.Path) (string, error) {
	attribute := path.Attribute
	if path.SubAttribute != "" {
		attribute += "." + path.SubAttribute
	}

	for scimPath, field := range r.mapper.Config().FieldMappings {
		if strings.EqualFold(scimPath, attribute) {
			return toColumnName(field), nil
		}
	}

	return "", scim.NewError("400", "invalidFilter",
		fmt.Sprintf("attribute %q is not filterable in this deployment", attribute))
}

// groupColumnForPath resolves a path against the group model.
func groupColumnForPath(path scim.Path) (string, error) {
	if path.SubAttribute != "" {
		return "", scim.NewError("400", "invalidFilter", "group filters do not support sub-attributes")
	}

	switch strings.ToLower(path.Attribute) {
	case "id":
		return "id", nil
	case "displayname":
		return "display_name", nil
	default:
		return "", scim.NewError("400", "invalidFilter",
			fmt.Sprintf("attribute %q is not filterable on groups", path.Attribute))
	}
}

// toColumnName converts a Go field name to GORM's default snake_case column.
func toColumnName(field string) string {
	var b strings.Builder
	for i, r := range field {
		if r >= 'A' && r <= 'Z' {
			if i > 0 {
				b.WriteByte('_')
			}
			b.WriteRune(r + 32)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
