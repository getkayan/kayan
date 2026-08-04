package scim

import (
	"context"
)

// ScimStorage defines the interface for SCIM-compliant persistence operations.
type ScimStorage interface {
	// User operations
	CreateScimUser(ctx context.Context, user *User) error
	GetScimUser(ctx context.Context, id string) (*User, error)
	FindScimUserByUserName(ctx context.Context, userName string) (*User, error)
	UpdateScimUser(ctx context.Context, user *User) error
	DeleteScimUser(ctx context.Context, id string) error
	ListScimUsers(ctx context.Context, filter string, startIndex, count int) ([]*User, int, error)

	// Group operations
	CreateScimGroup(ctx context.Context, group *Group) error
	GetScimGroup(ctx context.Context, id string) (*Group, error)
	UpdateScimGroup(ctx context.Context, group *Group) error
	DeleteScimGroup(ctx context.Context, id string) error
	ListScimGroups(ctx context.Context, filter string, startIndex, count int) ([]*Group, int, error)
}
