package scim

import (
	"context"
	"fmt"
)

// Manager orchestrates SCIM operations.
type Manager struct {
	storage ScimStorage
	mapper  *Mapper
}

func NewManager(storage ScimStorage, mapper *Mapper) *Manager {
	return &Manager{
		storage: storage,
		mapper:  mapper,
	}
}

// User operations

func (m *Manager) CreateUser(ctx context.Context, user *User) (*User, error) {
	if user.UserName == "" {
		return nil, NewError("400", "invalidValue", "userName is required")
	}

	// 1. Check if user already exists
	existing, _ := m.storage.FindScimUserByUserName(ctx, user.UserName)
	if existing != nil {
		return nil, NewError("409", "uniqueness", "User already exists")
	}

	// 2. Persist
	if err := m.storage.CreateScimUser(ctx, user); err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	return user, nil
}

func (m *Manager) GetUser(ctx context.Context, id string) (*User, error) {
	user, err := m.storage.GetScimUser(ctx, id)
	if err != nil {
		return nil, NewError("404", "", "User not found")
	}
	return user, nil
}

func (m *Manager) UpdateUser(ctx context.Context, id string, user *User) (*User, error) {
	user.ID = id
	if err := m.storage.UpdateScimUser(ctx, user); err != nil {
		return nil, fmt.Errorf("failed to update user: %w", err)
	}
	return user, nil
}

func (m *Manager) DeleteUser(ctx context.Context, id string) error {
	if err := m.storage.DeleteScimUser(ctx, id); err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}
	return nil
}

func (m *Manager) ListUsers(ctx context.Context, filter string, startIndex, count int) (*ListResponse, error) {
	if startIndex < 1 {
		startIndex = 1
	}
	if count < 0 {
		count = 100 // Default limit
	}

	resources, total, err := m.storage.ListScimUsers(ctx, filter, startIndex, count)
	if err != nil {
		return nil, err
	}

	resp := &ListResponse{
		Schemas:      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
		TotalResults: total,
		ItemsPerPage: len(resources),
		StartIndex:   startIndex,
		Resources:    make([]any, len(resources)),
	}

	for i, r := range resources {
		resp.Resources[i] = r
	}

	return resp, nil
}

// Group operations

func (m *Manager) CreateGroup(ctx context.Context, group *Group) (*Group, error) {
	if group.DisplayName == "" {
		return nil, NewError("400", "invalidValue", "displayName is required")
	}

	if err := m.storage.CreateScimGroup(ctx, group); err != nil {
		return nil, err
	}
	return group, nil
}

func (m *Manager) GetGroup(ctx context.Context, id string) (*Group, error) {
	group, err := m.storage.GetScimGroup(ctx, id)
	if err != nil {
		return nil, NewError("404", "", "Group not found")
	}
	return group, nil
}

func (m *Manager) UpdateGroup(ctx context.Context, id string, group *Group) (*Group, error) {
	group.ID = id
	if err := m.storage.UpdateScimGroup(ctx, group); err != nil {
		return nil, err
	}
	return group, nil
}

func (m *Manager) DeleteGroup(ctx context.Context, id string) error {
	return m.storage.DeleteScimGroup(ctx, id)
}

func (m *Manager) ListGroups(ctx context.Context, filter string, startIndex, count int) (*ListResponse, error) {
	resources, total, err := m.storage.ListScimGroups(ctx, filter, startIndex, count)
	if err != nil {
		return nil, err
	}

	resp := &ListResponse{
		Schemas:      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
		TotalResults: total,
		ItemsPerPage: len(resources),
		StartIndex:   startIndex,
		Resources:    make([]any, len(resources)),
	}

	for i, r := range resources {
		resp.Resources[i] = r
	}

	return resp, nil
}
