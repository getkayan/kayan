// Package admin provides a framework-agnostic admin manager for Kayan.
// All functions are pure Go - no HTTP dependencies. Any framework (Echo, Gin, Chi)
// can wrap these functions with their own handlers.
package admin

import (
	"context"
	"strings"
	"time"
)

// ---- Core Types ----

// User represents an identity in the admin context.
type User struct {
	ID        any            `json:"id"`
	Email     string         `json:"email"`
	Traits    map[string]any `json:"traits"`
	State     UserState      `json:"state"`
	TenantID  string         `json:"tenant_id,omitempty"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	LastLogin *time.Time     `json:"last_login,omitempty"`
}

type UserState string

const (
	UserStateActive   UserState = "active"
	UserStateInactive UserState = "inactive"
	UserStateLocked   UserState = "locked"
	UserStatePending  UserState = "pending"
)

// Session represents an active user session.
type Session struct {
	ID         any       `json:"id"`
	UserID     any       `json:"user_id"`
	TenantID   string    `json:"tenant_id,omitempty"`
	Active     bool      `json:"active"`
	IPAddress  string    `json:"ip_address,omitempty"`
	UserAgent  string    `json:"user_agent,omitempty"`
	AuthMethod string    `json:"auth_method"`
	AAL        string    `json:"aal"`
	IssuedAt   time.Time `json:"issued_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// Tenant represents a tenant.
type Tenant struct {
	ID        string         `json:"id"`
	Name      string         `json:"name"`
	Domain    string         `json:"domain,omitempty"`
	Active    bool           `json:"active"`
	Settings  map[string]any `json:"settings,omitempty"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
}

// Role represents an RBAC role.
type Role struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	TenantID    string    `json:"tenant_id,omitempty"`
	Permissions []string  `json:"permissions"`
	CreatedAt   time.Time `json:"created_at"`
}

// AuditEvent represents an audit log entry.
type AuditEvent struct {
	ID        string         `json:"id"`
	Type      string         `json:"type"`
	ActorID   string         `json:"actor_id,omitempty"`
	SubjectID string         `json:"subject_id,omitempty"`
	TenantID  string         `json:"tenant_id,omitempty"`
	Action    string         `json:"action"`
	Status    string         `json:"status"`
	Metadata  map[string]any `json:"metadata,omitempty"`
	Timestamp time.Time      `json:"timestamp"`
}

// Caller represents the admin making the request (for authorization).
type Caller struct {
	ID           string   `json:"id"`
	Roles        []string `json:"roles"`
	Permissions  []string `json:"permissions"`
	TenantID     string   `json:"tenant_id,omitempty"`
	IsSuperAdmin bool     `json:"is_super_admin"`
}

// ---- Query/Request Types ----

type ListOptions struct {
	Limit    int    `json:"limit"`
	Offset   int    `json:"offset"`
	Query    string `json:"query,omitempty"`
	TenantID string `json:"tenant_id,omitempty"`
}

type ListResult[T any] struct {
	Data   []T `json:"data"`
	Total  int `json:"total"`
	Limit  int `json:"limit"`
	Offset int `json:"offset"`
}

type CreateUserInput struct {
	Email    string         `json:"email"`
	Password string         `json:"password,omitempty"`
	Traits   map[string]any `json:"traits,omitempty"`
	TenantID string         `json:"tenant_id,omitempty"`
	Roles    []string       `json:"roles,omitempty"`
}

type UpdateUserInput struct {
	Email  *string        `json:"email,omitempty"`
	Traits map[string]any `json:"traits,omitempty"`
	State  *UserState     `json:"state,omitempty"`
}

type CreateTenantInput struct {
	Name     string         `json:"name"`
	Domain   string         `json:"domain,omitempty"`
	Settings map[string]any `json:"settings,omitempty"`
}

type UpdateTenantInput struct {
	Name     *string        `json:"name,omitempty"`
	Domain   *string        `json:"domain,omitempty"`
	Settings map[string]any `json:"settings,omitempty"`
}

type CreateRoleInput struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Permissions []string `json:"permissions"`
	TenantID    string   `json:"tenant_id,omitempty"`
}

type AuditQuery struct {
	TenantID  string    `json:"tenant_id,omitempty"`
	UserID    string    `json:"user_id,omitempty"`
	Types     []string  `json:"types,omitempty"`
	StartTime time.Time `json:"start_time,omitempty"`
	EndTime   time.Time `json:"end_time,omitempty"`
	Limit     int       `json:"limit"`
	Offset    int       `json:"offset"`
}

// ---- Store Interfaces (to be implemented by storage layer) ----

// UserStore defines storage operations for users.
type UserStore interface {
	List(ctx context.Context, opts ListOptions) (*ListResult[User], error)
	Get(ctx context.Context, id any) (*User, error)
	GetByEmail(ctx context.Context, email string) (*User, error)
	Create(ctx context.Context, user *User) error
	Update(ctx context.Context, user *User) error
	Delete(ctx context.Context, id any) error
	UpdateState(ctx context.Context, id any, state UserState) error
}

// SessionStore defines storage operations for sessions.
type SessionStore interface {
	ListByUser(ctx context.Context, userID any) ([]Session, error)
	Revoke(ctx context.Context, id any) error
	RevokeByUser(ctx context.Context, userID any) error
}

// TenantStore defines storage operations for tenants.
type TenantStore interface {
	List(ctx context.Context, opts ListOptions) (*ListResult[Tenant], error)
	Get(ctx context.Context, id string) (*Tenant, error)
	Create(ctx context.Context, tenant *Tenant) error
	Update(ctx context.Context, tenant *Tenant) error
	Delete(ctx context.Context, id string) error
}

// RoleStore defines storage operations for roles.
type RoleStore interface {
	List(ctx context.Context, opts ListOptions) (*ListResult[Role], error)
	Get(ctx context.Context, id string) (*Role, error)
	Create(ctx context.Context, role *Role) error
	Update(ctx context.Context, role *Role) error
	Delete(ctx context.Context, id string) error
	AssignToUser(ctx context.Context, userID any, roleID string) error
	RemoveFromUser(ctx context.Context, userID any, roleID string) error
	GetUserRoles(ctx context.Context, userID any) ([]Role, error)
}

// AuditStore defines storage operations for audit logs.
type AuditStore interface {
	Query(ctx context.Context, query AuditQuery) (*ListResult[AuditEvent], error)
}

// PasswordHasher defines password hashing operations.
type PasswordHasher interface {
	Hash(password string) (string, error)
	Verify(hash, password string) bool
}

// IDGenerator defines ID generation.
type IDGenerator interface {
	Generate() any
}

// ---- Manager ----

// Manager provides admin operations. Framework-agnostic.
type Manager struct {
	users    UserStore
	sessions SessionStore
	tenants  TenantStore
	roles    RoleStore
	audit    AuditStore
	hasher   PasswordHasher
	idGen    IDGenerator
}

// ManagerOption configures the Manager.
type ManagerOption func(*Manager)

// NewManager creates a new admin manager.
func NewManager(opts ...ManagerOption) *Manager {
	m := &Manager{}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

func WithUserStore(s UserStore) ManagerOption           { return func(m *Manager) { m.users = s } }
func WithSessionStore(s SessionStore) ManagerOption     { return func(m *Manager) { m.sessions = s } }
func WithTenantStore(s TenantStore) ManagerOption       { return func(m *Manager) { m.tenants = s } }
func WithRoleStore(s RoleStore) ManagerOption           { return func(m *Manager) { m.roles = s } }
func WithAuditStore(s AuditStore) ManagerOption         { return func(m *Manager) { m.audit = s } }
func WithPasswordHasher(h PasswordHasher) ManagerOption { return func(m *Manager) { m.hasher = h } }
func WithIDGenerator(g IDGenerator) ManagerOption       { return func(m *Manager) { m.idGen = g } }

// ---- User Operations ----

// ListUsers returns paginated users.
func (m *Manager) ListUsers(ctx context.Context, caller *Caller, opts ListOptions) (*ListResult[User], error) {
	if err := m.authorize(caller, PermUsersRead); err != nil {
		return nil, err
	}
	if m.users == nil {
		return nil, ErrNotConfigured
	}
	// Scope by tenant if caller is not super admin
	if !caller.IsSuperAdmin && caller.TenantID != "" {
		opts.TenantID = caller.TenantID
	}
	return m.users.List(ctx, opts)
}

// GetUser returns a user by ID.
func (m *Manager) GetUser(ctx context.Context, caller *Caller, id any) (*User, error) {
	if err := m.authorize(caller, PermUsersRead); err != nil {
		return nil, err
	}
	if m.users == nil {
		return nil, ErrNotConfigured
	}
	user, err := m.users.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	// Tenant scoping
	if !caller.IsSuperAdmin && caller.TenantID != "" && user.TenantID != caller.TenantID {
		return nil, ErrNotFound
	}
	return user, nil
}

// CreateUser creates a new user.
func (m *Manager) CreateUser(ctx context.Context, caller *Caller, input CreateUserInput) (*User, error) {
	if err := m.authorize(caller, PermUsersWrite); err != nil {
		return nil, err
	}
	if m.users == nil {
		return nil, ErrNotConfigured
	}

	// Validate
	if input.Email == "" {
		return nil, ErrInvalidInput
	}

	// Check if user exists
	existing, _ := m.users.GetByEmail(ctx, input.Email)
	if existing != nil {
		return nil, ErrAlreadyExists
	}

	user := &User{
		Email:     input.Email,
		Traits:    input.Traits,
		State:     UserStateActive,
		TenantID:  input.TenantID,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Generate ID
	if m.idGen != nil {
		user.ID = m.idGen.Generate()
	}

	// Set traits email if not set
	if user.Traits == nil {
		user.Traits = make(map[string]any)
	}
	user.Traits["email"] = input.Email

	if err := m.users.Create(ctx, user); err != nil {
		return nil, err
	}

	return user, nil
}

// UpdateUser updates a user.
func (m *Manager) UpdateUser(ctx context.Context, caller *Caller, id any, input UpdateUserInput) (*User, error) {
	if err := m.authorize(caller, PermUsersWrite); err != nil {
		return nil, err
	}
	if m.users == nil {
		return nil, ErrNotConfigured
	}

	user, err := m.users.Get(ctx, id)
	if err != nil {
		return nil, err
	}

	// Tenant scoping
	if !caller.IsSuperAdmin && caller.TenantID != "" && user.TenantID != caller.TenantID {
		return nil, ErrNotFound
	}

	if input.Email != nil {
		user.Email = *input.Email
		user.Traits["email"] = *input.Email
	}
	if input.Traits != nil {
		for k, v := range input.Traits {
			user.Traits[k] = v
		}
	}
	if input.State != nil {
		user.State = *input.State
	}
	user.UpdatedAt = time.Now()

	if err := m.users.Update(ctx, user); err != nil {
		return nil, err
	}

	return user, nil
}

// DeleteUser deletes a user.
func (m *Manager) DeleteUser(ctx context.Context, caller *Caller, id any) error {
	if err := m.authorize(caller, PermUsersDelete); err != nil {
		return err
	}
	if m.users == nil {
		return ErrNotConfigured
	}

	user, err := m.users.Get(ctx, id)
	if err != nil {
		return err
	}

	// Tenant scoping
	if !caller.IsSuperAdmin && caller.TenantID != "" && user.TenantID != caller.TenantID {
		return ErrNotFound
	}

	return m.users.Delete(ctx, id)
}

// LockUser locks a user account.
func (m *Manager) LockUser(ctx context.Context, caller *Caller, id any, reason string) error {
	if err := m.authorize(caller, PermUsersWrite); err != nil {
		return err
	}
	if m.users == nil {
		return ErrNotConfigured
	}
	return m.users.UpdateState(ctx, id, UserStateLocked)
}

// UnlockUser unlocks a user account.
func (m *Manager) UnlockUser(ctx context.Context, caller *Caller, id any) error {
	if err := m.authorize(caller, PermUsersWrite); err != nil {
		return err
	}
	if m.users == nil {
		return ErrNotConfigured
	}
	return m.users.UpdateState(ctx, id, UserStateActive)
}

// ListUserSessions returns sessions for a user.
func (m *Manager) ListUserSessions(ctx context.Context, caller *Caller, userID any) ([]Session, error) {
	if err := m.authorize(caller, PermSessionsRead); err != nil {
		return nil, err
	}
	if m.sessions == nil {
		return nil, ErrNotConfigured
	}
	return m.sessions.ListByUser(ctx, userID)
}

// RevokeUserSessions revokes all sessions for a user.
func (m *Manager) RevokeUserSessions(ctx context.Context, caller *Caller, userID any) error {
	if err := m.authorize(caller, PermSessionsRevoke); err != nil {
		return err
	}
	if m.sessions == nil {
		return ErrNotConfigured
	}
	return m.sessions.RevokeByUser(ctx, userID)
}

// ---- Tenant Operations ----

// ListTenants returns paginated tenants.
func (m *Manager) ListTenants(ctx context.Context, caller *Caller, opts ListOptions) (*ListResult[Tenant], error) {
	if err := m.authorize(caller, PermTenantsRead); err != nil {
		return nil, err
	}
	if m.tenants == nil {
		return nil, ErrNotConfigured
	}
	return m.tenants.List(ctx, opts)
}

// GetTenant returns a tenant by ID.
func (m *Manager) GetTenant(ctx context.Context, caller *Caller, id string) (*Tenant, error) {
	if err := m.authorize(caller, PermTenantsRead); err != nil {
		return nil, err
	}
	if m.tenants == nil {
		return nil, ErrNotConfigured
	}
	return m.tenants.Get(ctx, id)
}

// CreateTenant creates a new tenant.
func (m *Manager) CreateTenant(ctx context.Context, caller *Caller, input CreateTenantInput) (*Tenant, error) {
	if err := m.authorize(caller, PermTenantsWrite); err != nil {
		return nil, err
	}
	if m.tenants == nil {
		return nil, ErrNotConfigured
	}

	if input.Name == "" {
		return nil, ErrInvalidInput
	}

	tenant := &Tenant{
		Name:      input.Name,
		Domain:    input.Domain,
		Active:    true,
		Settings:  input.Settings,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if m.idGen != nil {
		if id, ok := m.idGen.Generate().(string); ok {
			tenant.ID = id
		}
	}

	if err := m.tenants.Create(ctx, tenant); err != nil {
		return nil, err
	}

	return tenant, nil
}

// DeleteTenant deletes a tenant.
func (m *Manager) DeleteTenant(ctx context.Context, caller *Caller, id string) error {
	if err := m.authorize(caller, PermTenantsDelete); err != nil {
		return err
	}
	if m.tenants == nil {
		return ErrNotConfigured
	}
	return m.tenants.Delete(ctx, id)
}

// ---- Role Operations ----

// ListRoles returns paginated roles.
func (m *Manager) ListRoles(ctx context.Context, caller *Caller, opts ListOptions) (*ListResult[Role], error) {
	if err := m.authorize(caller, PermRolesRead); err != nil {
		return nil, err
	}
	if m.roles == nil {
		return nil, ErrNotConfigured
	}
	return m.roles.List(ctx, opts)
}

// GetRole returns a role by ID.
func (m *Manager) GetRole(ctx context.Context, caller *Caller, id string) (*Role, error) {
	if err := m.authorize(caller, PermRolesRead); err != nil {
		return nil, err
	}
	if m.roles == nil {
		return nil, ErrNotConfigured
	}
	return m.roles.Get(ctx, id)
}

// CreateRole creates a new role.
func (m *Manager) CreateRole(ctx context.Context, caller *Caller, input CreateRoleInput) (*Role, error) {
	if err := m.authorize(caller, PermRolesWrite); err != nil {
		return nil, err
	}
	if m.roles == nil {
		return nil, ErrNotConfigured
	}

	if input.Name == "" || len(input.Permissions) == 0 {
		return nil, ErrInvalidInput
	}

	role := &Role{
		Name:        input.Name,
		Description: input.Description,
		Permissions: input.Permissions,
		TenantID:    input.TenantID,
		CreatedAt:   time.Now(),
	}

	if m.idGen != nil {
		if id, ok := m.idGen.Generate().(string); ok {
			role.ID = id
		}
	}

	if err := m.roles.Create(ctx, role); err != nil {
		return nil, err
	}

	return role, nil
}

// DeleteRole deletes a role.
func (m *Manager) DeleteRole(ctx context.Context, caller *Caller, id string) error {
	if err := m.authorize(caller, PermRolesDelete); err != nil {
		return err
	}
	if m.roles == nil {
		return ErrNotConfigured
	}
	return m.roles.Delete(ctx, id)
}

// AssignRoleToUser assigns a role to a user.
func (m *Manager) AssignRoleToUser(ctx context.Context, caller *Caller, userID any, roleID string) error {
	if err := m.authorize(caller, PermRolesWrite); err != nil {
		return err
	}
	if m.roles == nil {
		return ErrNotConfigured
	}
	return m.roles.AssignToUser(ctx, userID, roleID)
}

// GetUserRoles returns roles assigned to a user.
func (m *Manager) GetUserRoles(ctx context.Context, caller *Caller, userID any) ([]Role, error) {
	if err := m.authorize(caller, PermRolesRead); err != nil {
		return nil, err
	}
	if m.roles == nil {
		return nil, ErrNotConfigured
	}
	return m.roles.GetUserRoles(ctx, userID)
}

// ---- Audit Operations ----

// QueryAudit queries audit logs.
func (m *Manager) QueryAudit(ctx context.Context, caller *Caller, query AuditQuery) (*ListResult[AuditEvent], error) {
	if err := m.authorize(caller, PermAuditRead); err != nil {
		return nil, err
	}
	if m.audit == nil {
		return nil, ErrNotConfigured
	}
	// Scope by tenant
	if !caller.IsSuperAdmin && caller.TenantID != "" {
		query.TenantID = caller.TenantID
	}
	return m.audit.Query(ctx, query)
}

// ---- Authorization ----

func (m *Manager) authorize(caller *Caller, permission string) error {
	if caller == nil {
		return ErrUnauthorized
	}
	if caller.IsSuperAdmin {
		return nil
	}
	if checkPerm(caller.Permissions, permission) {
		return nil
	}
	// Check role permissions
	for _, role := range caller.Roles {
		if perms, ok := DefaultRolePermissions[role]; ok {
			if checkPerm(perms, permission) {
				return nil
			}
		}
	}
	return ErrForbidden
}

func checkPerm(perms []string, required string) bool {
	for _, p := range perms {
		if p == "*" || p == required {
			return true
		}
		if strings.HasSuffix(p, ":*") {
			prefix := strings.TrimSuffix(p, "*")
			if strings.HasPrefix(required, prefix) {
				return true
			}
		}
	}
	return false
}

// ---- Permissions ----

const (
	PermUsersRead      = "users:read"
	PermUsersWrite     = "users:write"
	PermUsersDelete    = "users:delete"
	PermTenantsRead    = "tenants:read"
	PermTenantsWrite   = "tenants:write"
	PermTenantsDelete  = "tenants:delete"
	PermRolesRead      = "roles:read"
	PermRolesWrite     = "roles:write"
	PermRolesDelete    = "roles:delete"
	PermSessionsRead   = "sessions:read"
	PermSessionsRevoke = "sessions:revoke"
	PermAuditRead      = "audit:read"
	PermAuditExport    = "audit:export"
)

var DefaultRolePermissions = map[string][]string{
	"admin": {
		PermUsersRead, PermUsersWrite, PermUsersDelete,
		PermTenantsRead, PermTenantsWrite, PermTenantsDelete,
		PermRolesRead, PermRolesWrite, PermRolesDelete,
		PermSessionsRead, PermSessionsRevoke,
		PermAuditRead, PermAuditExport,
	},
	"operator": {
		PermUsersRead, PermTenantsRead, PermSessionsRead,
		PermSessionsRevoke, PermAuditRead,
	},
	"viewer": {
		PermUsersRead, PermTenantsRead, PermRolesRead,
		PermSessionsRead, PermAuditRead,
	},
}

// ---- Errors ----

var (
	ErrNoToken        = &AdminError{Code: "no_token", Message: "no authentication token provided"}
	ErrInvalidToken   = &AdminError{Code: "invalid_token", Message: "invalid authentication token"}
	ErrUnauthorized   = &AdminError{Code: "unauthorized", Message: "unauthorized"}
	ErrForbidden      = &AdminError{Code: "forbidden", Message: "insufficient permissions"}
	ErrNotFound       = &AdminError{Code: "not_found", Message: "not found"}
	ErrAlreadyExists  = &AdminError{Code: "already_exists", Message: "already exists"}
	ErrInvalidInput   = &AdminError{Code: "invalid_input", Message: "invalid input"}
	ErrNotConfigured  = &AdminError{Code: "not_configured", Message: "service not configured"}
	ErrUserNotFound   = &AdminError{Code: "user_not_found", Message: "user not found"}
	ErrTenantNotFound = &AdminError{Code: "tenant_not_found", Message: "tenant not found"}
	ErrRoleNotFound   = &AdminError{Code: "role_not_found", Message: "role not found"}
)
