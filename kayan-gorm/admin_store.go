package gormstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/getkayan/kayan/core/admin"
	"github.com/getkayan/kayan/core/audit"
	"github.com/getkayan/kayan/core/identity"
	"github.com/getkayan/kayan/core/rbac"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// AdminStores groups the persistent stores consumed by core/admin.
//
// The stores are separate because admin.UserStore and admin.RoleStore both
// define methods named List, Get, Create, Update, and Delete with different
// signatures. Go cannot implement both interfaces on one concrete type.
type AdminStores struct {
	Users    *AdminUserStore
	Sessions *AdminSessionStore
	Roles    *AdminRoleStore
	Audit    *AdminAuditStore
}

// NewAdminStores creates GORM-backed stores for user, session, role, and audit
// administration. They use the same tables as the authentication and RBAC
// repositories, so an administrative change is visible to authorization and
// login immediately.
func NewAdminStores(db *gorm.DB) *AdminStores {
	return &AdminStores{
		Users:    &AdminUserStore{db: db},
		Sessions: &AdminSessionStore{db: db},
		Roles:    &AdminRoleStore{db: db},
		Audit:    &AdminAuditStore{db: db},
	}
}

// AdminUserStore manages Kayan's default identity model for core/admin.
// Applications using a custom BYOS identity model implement admin.UserStore
// for that model instead; the adapter cannot infer where arbitrary structs
// keep state and timestamps.
type AdminUserStore struct{ db *gorm.DB }

// AdminSessionStore manages database-backed sessions for core/admin.
type AdminSessionStore struct{ db *gorm.DB }

// AdminRoleStore manages the same definitions and assignments used by
// rbac.StorageStrategy.
type AdminRoleStore struct{ db *gorm.DB }

// AdminAuditStore reads the same append-only events written through
// audit.AuditStore.
type AdminAuditStore struct{ db *gorm.DB }

var (
	_ admin.UserStore             = (*AdminUserStore)(nil)
	_ admin.UserProvisioningStore = (*AdminUserStore)(nil)
	_ admin.SessionStore          = (*AdminSessionStore)(nil)
	_ admin.RoleStore             = (*AdminRoleStore)(nil)
	_ admin.AuditStore            = (*AdminAuditStore)(nil)
)

func adminPage(limit, offset int) (int, int) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 100 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}

func applyAdminTenant(db *gorm.DB, tenantID string) *gorm.DB {
	if tenantID != "" {
		return db.Where("tenant_id = ?", tenantID)
	}
	return db
}

func traitsMap(raw identity.JSON) map[string]any {
	traits := make(map[string]any)
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &traits)
	}
	return traits
}

func adminUserFromModel(model *gormIdentity) admin.User {
	traits := traitsMap(model.Traits)
	email, _ := traits["email"].(string)
	return admin.User{
		ID: model.ID, Email: email, Traits: traits, State: admin.UserState(model.State),
		TenantID: model.TenantID_, CreatedAt: model.CreatedAt, UpdatedAt: model.UpdatedAt,
	}
}

func modelFromAdminUser(user *admin.User) (*gormIdentity, error) {
	if user == nil {
		return nil, errors.New("gormstore: admin user is nil")
	}
	id := fmt.Sprintf("%v", user.ID)
	if id == "" || id == "<nil>" {
		return nil, errors.New("gormstore: admin user ID is required")
	}
	traits := user.Traits
	if traits == nil {
		traits = make(map[string]any)
	}
	traits["email"] = user.Email
	raw, err := json.Marshal(traits)
	if err != nil {
		return nil, fmt.Errorf("gormstore: marshal admin user traits: %w", err)
	}
	now := time.Now()
	created := user.CreatedAt
	if created.IsZero() {
		created = now
	}
	updated := user.UpdatedAt
	if updated.IsZero() {
		updated = now
	}
	state := user.State
	if state == "" {
		state = admin.UserStateActive
	}
	return &gormIdentity{
		ID: id, TenantID_: user.TenantID, Traits: identity.JSON(raw), State: string(state),
		CreatedAt: created, UpdatedAt: updated,
	}, nil
}

// List implements admin.UserStore.
func (s *AdminUserStore) List(ctx context.Context, opts admin.ListOptions) (*admin.UserListResult, error) {
	limit, offset := adminPage(opts.Limit, opts.Offset)
	db := applyAdminTenant(s.db.WithContext(ctx).Model(&gormIdentity{}), opts.TenantID)
	if q := strings.TrimSpace(opts.Query); q != "" {
		like := "%" + strings.ToLower(q) + "%"
		var identityIDs []string
		credDB := applyAdminTenant(s.db.WithContext(ctx).Model(&gormCredential{}), opts.TenantID)
		if err := credDB.Where("LOWER(identifier) LIKE ?", like).Distinct().Pluck("identity_id", &identityIDs).Error; err != nil {
			return nil, storageError("list admin user identifiers", err)
		}
		if len(identityIDs) == 0 {
			db = db.Where("LOWER(id) LIKE ?", like)
		} else {
			db = db.Where("LOWER(id) LIKE ? OR id IN ?", like, identityIDs)
		}
	}

	var total int64
	if err := db.Count(&total).Error; err != nil {
		return nil, storageError("count admin users", err)
	}
	var models []gormIdentity
	if err := db.Order("created_at DESC").Limit(limit).Offset(offset).Find(&models).Error; err != nil {
		return nil, storageError("list admin users", err)
	}
	users := make([]admin.User, len(models))
	for i := range models {
		users[i] = adminUserFromModel(&models[i])
	}
	return &admin.UserListResult{Data: users, Total: int(total), Limit: limit, Offset: offset}, nil
}

// Get implements admin.UserStore.
func (s *AdminUserStore) Get(ctx context.Context, id any) (*admin.User, error) {
	var model gormIdentity
	if err := s.db.WithContext(ctx).First(&model, "id = ?", id).Error; err != nil {
		return nil, storageError("get admin user", err)
	}
	user := adminUserFromModel(&model)
	return &user, nil
}

// GetByEmail implements admin.UserStore.
func (s *AdminUserStore) GetByEmail(ctx context.Context, email string) (*admin.User, error) {
	var credential gormCredential
	err := s.db.WithContext(ctx).Where("identifier = ?", email).Order("created_at").First(&credential).Error
	if err == nil {
		return s.Get(ctx, credential.IdentityID)
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, storageError("get admin user by email", err)
	}

	// Credential-free invited users still have email in their traits. This
	// fallback is intentionally portable across PostgreSQL, MySQL, and SQLite;
	// each has different JSON query syntax.
	var models []gormIdentity
	if err := s.db.WithContext(ctx).Find(&models).Error; err != nil {
		return nil, storageError("find invited admin user by email", err)
	}
	for i := range models {
		user := adminUserFromModel(&models[i])
		if strings.EqualFold(user.Email, email) {
			return &user, nil
		}
	}
	return nil, fmt.Errorf("gormstore: get admin user by email: %w", admin.ErrNotFound)
}

// Create implements admin.UserStore for credential-free invitations.
func (s *AdminUserStore) Create(ctx context.Context, user *admin.User) error {
	model, err := modelFromAdminUser(user)
	if err != nil {
		return err
	}
	return storageError("create admin user", s.db.WithContext(ctx).Create(model).Error)
}

// Provision atomically persists the identity, optional password credential,
// and initial role assignments.
func (s *AdminUserStore) Provision(ctx context.Context, user *admin.User, credential *admin.PasswordCredential, roles []string) error {
	model, err := modelFromAdminUser(user)
	if err != nil {
		return err
	}
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		for _, role := range roles {
			var definition RoleDefinition
			query := tx.Where("name = ?", role)
			if model.TenantID_ != "" {
				query = query.Where("tenant_id = ?", model.TenantID_)
			}
			if err := query.First(&definition).Error; err != nil {
				if errors.Is(err, gorm.ErrRecordNotFound) {
					return fmt.Errorf("gormstore: provision admin user: %w: %q", rbac.ErrRoleNotFound, role)
				}
				return storageError("validate provisioned role", err)
			}
		}
		if err := tx.Create(model).Error; err != nil {
			return storageError("provision admin user", err)
		}
		if credential != nil {
			stored := &gormCredential{
				ID: uuid.NewString(), TenantID_: model.TenantID_, IdentityID: model.ID,
				Type: "password", Identifier: credential.Identifier, Secret: credential.SecretHash,
				CreatedAt: time.Now(), UpdatedAt: time.Now(),
			}
			if err := tx.Create(stored).Error; err != nil {
				return storageError("provision admin password", err)
			}
		}
		for _, role := range roles {
			assignment := &RoleAssignment{TenantId: model.TenantID_, IdentityID: model.ID, Role: role}
			if err := tx.Create(assignment).Error; err != nil {
				return storageError("provision admin role", err)
			}
		}
		return nil
	})
}

// Update implements admin.UserStore and changes password login identifiers
// together with the user email.
func (s *AdminUserStore) Update(ctx context.Context, user *admin.User) error {
	model, err := modelFromAdminUser(user)
	if err != nil {
		return err
	}
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var existing gormIdentity
		if err := tx.First(&existing, "id = ?", model.ID).Error; err != nil {
			return storageError("get admin user for update", err)
		}
		oldEmail, _ := traitsMap(existing.Traits)["email"].(string)
		if err := tx.Model(&gormIdentity{}).Where("id = ?", model.ID).Updates(map[string]any{
			"traits": model.Traits, "state": model.State, "updated_at": model.UpdatedAt,
		}).Error; err != nil {
			return storageError("update admin user", err)
		}
		if oldEmail != "" && oldEmail != user.Email {
			if err := tx.Model(&gormCredential{}).
				Where("identity_id = ? AND identifier = ?", model.ID, oldEmail).
				Update("identifier", user.Email).Error; err != nil {
				return storageError("update admin login identifier", err)
			}
		}
		if model.State != "" && model.State != string(admin.UserStateActive) {
			if err := tx.Model(&gormSession{}).Where("identity_id = ?", model.ID).
				Update("active", false).Error; err != nil {
				return storageError("revoke disabled admin user sessions", err)
			}
		}
		return nil
	})
}

// Delete implements admin.UserStore. Related authentication state is removed
// in the same transaction so deleting a user cannot leave a working session.
func (s *AdminUserStore) Delete(ctx context.Context, id any) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		for model, description := range map[any]string{
			&gormCredential{}: "credentials", &gormSession{}: "sessions", &RoleAssignment{}: "roles",
		} {
			if err := tx.Delete(model, "identity_id = ?", id).Error; err != nil {
				return storageError("delete admin user "+description, err)
			}
		}
		result := tx.Delete(&gormIdentity{}, "id = ?", id)
		if result.Error != nil {
			return storageError("delete admin user", result.Error)
		}
		if result.RowsAffected == 0 {
			return fmt.Errorf("gormstore: delete admin user: %w", admin.ErrNotFound)
		}
		return nil
	})
}

// UpdateState implements admin.UserStore.
func (s *AdminUserStore) UpdateState(ctx context.Context, id any, state admin.UserState) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		result := tx.Model(&gormIdentity{}).Where("id = ?", id).
			Updates(map[string]any{"state": state, "updated_at": time.Now()})
		if result.Error != nil {
			return storageError("update admin user state", result.Error)
		}
		if result.RowsAffected == 0 {
			return fmt.Errorf("gormstore: update admin user state: %w", admin.ErrNotFound)
		}
		if state != admin.UserStateActive {
			if err := tx.Model(&gormSession{}).Where("identity_id = ?", id).
				Update("active", false).Error; err != nil {
				return storageError("revoke locked admin user sessions", err)
			}
		}
		return nil
	})
}

// ListByUser implements admin.SessionStore.
func (s *AdminSessionStore) ListByUser(ctx context.Context, userID any) ([]admin.Session, error) {
	var models []gormSession
	if err := s.db.WithContext(ctx).Where("identity_id = ? AND active = ?", userID, true).
		Order("issued_at DESC").Find(&models).Error; err != nil {
		return nil, storageError("list admin sessions", err)
	}
	result := make([]admin.Session, len(models))
	for i := range models {
		result[i] = admin.Session{
			ID: models[i].ID, UserID: models[i].IdentityID, TenantID: models[i].TenantID_,
			Active: models[i].Active, AuthMethod: "database", IssuedAt: models[i].IssuedAt,
			ExpiresAt: models[i].ExpiresAt,
		}
	}
	return result, nil
}

// Revoke implements admin.SessionStore.
func (s *AdminSessionStore) Revoke(ctx context.Context, id any) error {
	result := s.db.WithContext(ctx).Model(&gormSession{}).Where("id = ?", id).Update("active", false)
	if result.Error != nil {
		return storageError("revoke admin session", result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("gormstore: revoke admin session: %w", admin.ErrNotFound)
	}
	return nil
}

// RevokeByUser implements admin.SessionStore.
func (s *AdminSessionStore) RevokeByUser(ctx context.Context, userID any) error {
	return storageError("revoke admin user sessions", s.db.WithContext(ctx).Model(&gormSession{}).
		Where("identity_id = ?", userID).Update("active", false).Error)
}

func adminRoleFromModel(model *RoleDefinition) admin.Role {
	return admin.Role{
		ID: model.Name, Name: model.Name, Description: model.Description,
		TenantID: model.TenantId, Permissions: append([]string(nil), model.Permissions...),
	}
}

// List implements admin.RoleStore.
func (s *AdminRoleStore) List(ctx context.Context, opts admin.ListOptions) (*admin.RoleListResult, error) {
	limit, offset := adminPage(opts.Limit, opts.Offset)
	db := applyAdminTenant(s.db.WithContext(ctx).Model(&RoleDefinition{}), opts.TenantID)
	if q := strings.TrimSpace(opts.Query); q != "" {
		db = db.Where("LOWER(name) LIKE ?", "%"+strings.ToLower(q)+"%")
	}
	var total int64
	if err := db.Count(&total).Error; err != nil {
		return nil, storageError("count admin roles", err)
	}
	var models []RoleDefinition
	if err := db.Order("name").Limit(limit).Offset(offset).Find(&models).Error; err != nil {
		return nil, storageError("list admin roles", err)
	}
	roles := make([]admin.Role, len(models))
	for i := range models {
		roles[i] = adminRoleFromModel(&models[i])
	}
	return &admin.RoleListResult{Data: roles, Total: int(total), Limit: limit, Offset: offset}, nil
}

// Get implements admin.RoleStore. Role IDs are role names because the shared
// RBAC schema keys definitions by name.
func (s *AdminRoleStore) Get(ctx context.Context, id string) (*admin.Role, error) {
	var model RoleDefinition
	if err := s.db.WithContext(ctx).First(&model, "name = ?", id).Error; err != nil {
		return nil, storageError("get admin role", err)
	}
	role := adminRoleFromModel(&model)
	return &role, nil
}

// Create implements admin.RoleStore.
func (s *AdminRoleStore) Create(ctx context.Context, role *admin.Role) error {
	if role == nil || role.Name == "" {
		return admin.ErrInvalidInput
	}
	model := &RoleDefinition{
		Name: role.Name, TenantId: role.TenantID, Description: role.Description,
		Permissions: append([]string(nil), role.Permissions...),
	}
	return storageError("create admin role", s.db.WithContext(ctx).Create(model).Error)
}

// Update implements admin.RoleStore.
func (s *AdminRoleStore) Update(ctx context.Context, role *admin.Role) error {
	if role == nil || role.Name == "" {
		return admin.ErrInvalidInput
	}
	result := s.db.WithContext(ctx).Model(&RoleDefinition{}).Where("name = ?", role.ID).
		Updates(map[string]any{"name": role.Name, "description": role.Description, "permissions": role.Permissions})
	if result.Error != nil {
		return storageError("update admin role", result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("gormstore: update admin role: %w", admin.ErrNotFound)
	}
	return nil
}

// Delete implements admin.RoleStore. Existing assignments intentionally remain
// and fail with rbac.ErrRoleNotFound instead of becoming a silent denial.
func (s *AdminRoleStore) Delete(ctx context.Context, id string) error {
	result := s.db.WithContext(ctx).Delete(&RoleDefinition{}, "name = ?", id)
	if result.Error != nil {
		return storageError("delete admin role", result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("gormstore: delete admin role: %w", admin.ErrNotFound)
	}
	return nil
}

// AssignToUser implements admin.RoleStore.
func (s *AdminRoleStore) AssignToUser(ctx context.Context, userID any, roleID string) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var user gormIdentity
		if err := tx.First(&user, "id = ?", userID).Error; err != nil {
			return storageError("get admin role assignee", err)
		}
		var role RoleDefinition
		if err := tx.Where("name = ? AND tenant_id = ?", roleID, user.TenantID_).First(&role).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return fmt.Errorf("gormstore: assign admin role: %w: %q", rbac.ErrRoleNotFound, roleID)
			}
			return storageError("get assigned admin role", err)
		}
		assignment := &RoleAssignment{TenantId: user.TenantID_, IdentityID: fmt.Sprintf("%v", userID), Role: roleID}
		return storageError("assign admin role", tx.Where(*assignment).FirstOrCreate(assignment).Error)
	})
}

// RemoveFromUser implements admin.RoleStore.
func (s *AdminRoleStore) RemoveFromUser(ctx context.Context, userID any, roleID string) error {
	return storageError("remove admin role", s.db.WithContext(ctx).
		Delete(&RoleAssignment{}, "identity_id = ? AND role = ?", userID, roleID).Error)
}

// GetUserRoles implements admin.RoleStore.
func (s *AdminRoleStore) GetUserRoles(ctx context.Context, userID any) ([]admin.Role, error) {
	var assignments []RoleAssignment
	if err := s.db.WithContext(ctx).Where("identity_id = ?", userID).Order("id").Find(&assignments).Error; err != nil {
		return nil, storageError("get admin user role assignments", err)
	}
	roles := make([]admin.Role, 0, len(assignments))
	for i := range assignments {
		var definition RoleDefinition
		if err := s.db.WithContext(ctx).
			Where("name = ? AND tenant_id = ?", assignments[i].Role, assignments[i].TenantId).
			First(&definition).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return nil, fmt.Errorf("gormstore: get admin user roles: %w: %q", rbac.ErrRoleNotFound, assignments[i].Role)
			}
			return nil, storageError("get admin role definition", err)
		}
		roles = append(roles, adminRoleFromModel(&definition))
	}
	return roles, nil
}

// Query implements admin.AuditStore.
func (s *AdminAuditStore) Query(ctx context.Context, query admin.AuditQuery) (*admin.AuditEventListResult, error) {
	limit, offset := adminPage(query.Limit, query.Offset)
	filter := audit.Filter{
		TenantID: query.TenantID, ActorID: query.UserID, Types: query.Types,
		StartTime: query.StartTime, EndTime: query.EndTime, Limit: limit, Offset: offset,
	}
	repository := &Repository{db: s.db}
	var total int64
	db := repository.applyFilter(s.db.WithContext(ctx).Model(&gormAuditEvent{}), filter)
	if err := db.Order(nil).Limit(-1).Offset(-1).Count(&total).Error; err != nil {
		return nil, storageError("count admin audit events", err)
	}
	var models []gormAuditEvent
	if err := repository.applyFilter(s.db.WithContext(ctx), filter).Find(&models).Error; err != nil {
		return nil, storageError("query admin audit events", err)
	}
	events := make([]admin.AuditEvent, len(models))
	for i := range models {
		metadata := make(map[string]any)
		if len(models[i].Metadata) > 0 {
			_ = json.Unmarshal(models[i].Metadata, &metadata)
		}
		events[i] = admin.AuditEvent{
			ID: models[i].ID, Type: models[i].Type, ActorID: models[i].ActorID,
			SubjectID: models[i].SubjectID, TenantID: models[i].TenantID_,
			Action: models[i].Message, Status: models[i].Status, Metadata: metadata,
			Timestamp: models[i].CreatedAt,
		}
	}
	return &admin.AuditEventListResult{Data: events, Total: int(total), Limit: limit, Offset: offset}, nil
}
