package kgorm

import (
	"context"
	"fmt"

	"github.com/getkayan/kayan/core/scim"
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
	// Basic implementation without complex filter parsing
	var total int64
	m := r.mapper.ToModelPlaceholder()
	r.db.WithContext(ctx).Model(m).Count(&total)

	rows, err := r.db.WithContext(ctx).Model(m).Offset(startIndex - 1).Limit(count).Rows()
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	users := make([]*scim.User, 0)
	for rows.Next() {
		inst := r.mapper.ToModelPlaceholder()
		r.db.ScanRows(rows, inst)
		u, err := r.mapper.FromModel(inst)
		if err == nil && u != nil {
			users = append(users, u)
		}
	}

	return users, int(total), nil
}

// Group implementations (Basic GORM implementations)

func (r *ScimRepository) CreateScimGroup(ctx context.Context, group *scim.Group) error {
	g := &gormGroup{
		ID:          group.ID,
		DisplayName: group.DisplayName,
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
	return res, nil
}

func (r *ScimRepository) UpdateScimGroup(ctx context.Context, group *scim.Group) error {
	g := &gormGroup{
		ID:          group.ID,
		DisplayName: group.DisplayName,
	}
	return r.db.WithContext(ctx).Save(g).Error
}

func (r *ScimRepository) DeleteScimGroup(ctx context.Context, id string) error {
	return r.db.WithContext(ctx).Delete(&gormGroup{}, "id = ?", id).Error
}

func (r *ScimRepository) ListScimGroups(ctx context.Context, filter string, startIndex, count int) ([]*scim.Group, int, error) {
	var total int64
	r.db.WithContext(ctx).Model(&gormGroup{}).Count(&total)

	var groups []gormGroup
	if err := r.db.WithContext(ctx).Offset(startIndex - 1).Limit(count).Find(&groups).Error; err != nil {
		return nil, 0, err
	}

	res := make([]*scim.Group, len(groups))
	for i, g := range groups {
		group := &scim.Group{
			DisplayName: g.DisplayName,
		}
		group.ID = g.ID
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
