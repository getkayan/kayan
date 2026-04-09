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
	updated, _ := r.mapper.FromModel(model)
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
		u, _ := r.mapper.FromModel(inst)
		users = append(users, u)
	}

	return users, int(total), nil
}

// Group implementations (Simplified)

func (r *ScimRepository) CreateScimGroup(ctx context.Context, group *scim.Group) error {
	return scim.ErrUnsupported
}

func (r *ScimRepository) GetScimGroup(ctx context.Context, id string) (*scim.Group, error) {
	return nil, scim.ErrNotFound
}

func (r *ScimRepository) UpdateScimGroup(ctx context.Context, group *scim.Group) error {
	return scim.ErrUnsupported
}

func (r *ScimRepository) DeleteScimGroup(ctx context.Context, id string) error {
	return scim.ErrUnsupported
}

func (r *ScimRepository) ListScimGroups(ctx context.Context, filter string, startIndex, count int) ([]*scim.Group, int, error) {
	return nil, 0, nil
}

func (r *ScimRepository) getIdentityModel(ctx context.Context, id string) (any, error) {
	model := r.mapper.ToModelPlaceholder()
	if err := r.db.WithContext(ctx).First(model, "id = ?", id).Error; err != nil {
		return nil, err
	}
	return model, nil
}
