package scim

import (
	"context"
	"fmt"
	"sync"
	"testing"
)

// mockScimStorage is an in-memory implementation of ScimStorage for testing.
type mockScimStorage struct {
	mu     sync.Mutex
	users  map[string]*User
	groups map[string]*Group
	nextID int
}

func newMockScimStorage() *mockScimStorage {
	return &mockScimStorage{
		users:  make(map[string]*User),
		groups: make(map[string]*Group),
	}
}

func (s *mockScimStorage) genID() string {
	s.nextID++
	return fmt.Sprintf("id-%d", s.nextID)
}

func (s *mockScimStorage) CreateScimUser(ctx context.Context, user *User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if user.ID == "" {
		user.ID = s.genID()
	}
	s.users[user.ID] = user
	return nil
}

func (s *mockScimStorage) GetScimUser(ctx context.Context, id string) (*User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[id]
	if !ok {
		return nil, ErrNotFound
	}
	return u, nil
}

func (s *mockScimStorage) FindScimUserByUserName(ctx context.Context, userName string) (*User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range s.users {
		if u.UserName == userName {
			return u, nil
		}
	}
	return nil, ErrNotFound
}

func (s *mockScimStorage) UpdateScimUser(ctx context.Context, user *User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[user.ID]; !ok {
		return ErrNotFound
	}
	s.users[user.ID] = user
	return nil
}

func (s *mockScimStorage) DeleteScimUser(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[id]; !ok {
		return ErrNotFound
	}
	delete(s.users, id)
	return nil
}

func (s *mockScimStorage) ListScimUsers(ctx context.Context, filter string, startIndex, count int) ([]*User, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	all := make([]*User, 0, len(s.users))
	for _, u := range s.users {
		all = append(all, u)
	}
	total := len(all)
	start := startIndex - 1
	if start < 0 {
		start = 0
	}
	if start >= total {
		return nil, total, nil
	}
	end := start + count
	if end > total {
		end = total
	}
	return all[start:end], total, nil
}

func (s *mockScimStorage) CreateScimGroup(ctx context.Context, group *Group) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if group.ID == "" {
		group.ID = s.genID()
	}
	s.groups[group.ID] = group
	return nil
}

func (s *mockScimStorage) GetScimGroup(ctx context.Context, id string) (*Group, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.groups[id]
	if !ok {
		return nil, ErrNotFound
	}
	return g, nil
}

func (s *mockScimStorage) UpdateScimGroup(ctx context.Context, group *Group) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.groups[group.ID]; !ok {
		return ErrNotFound
	}
	s.groups[group.ID] = group
	return nil
}

func (s *mockScimStorage) DeleteScimGroup(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.groups[id]; !ok {
		return ErrNotFound
	}
	delete(s.groups, id)
	return nil
}

func (s *mockScimStorage) ListScimGroups(ctx context.Context, filter string, startIndex, count int) ([]*Group, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	all := make([]*Group, 0, len(s.groups))
	for _, g := range s.groups {
		all = append(all, g)
	}
	total := len(all)
	start := startIndex - 1
	if start < 0 {
		start = 0
	}
	if start >= total {
		return nil, total, nil
	}
	end := start + count
	if end > total {
		end = total
	}
	return all[start:end], total, nil
}

func TestManager_CreateUser(t *testing.T) {
	store := newMockScimStorage()
	mgr := NewManager(store, nil)
	ctx := context.Background()

	user := NewUser()
	user.UserName = "alice"
	user.DisplayName = "Alice Smith"

	created, err := mgr.CreateUser(ctx, user)
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}
	if created.ID == "" {
		t.Error("expected ID to be assigned")
	}
	if created.UserName != "alice" {
		t.Errorf("expected UserName alice, got %s", created.UserName)
	}
}

func TestManager_CreateUser_DuplicateUserName(t *testing.T) {
	store := newMockScimStorage()
	mgr := NewManager(store, nil)
	ctx := context.Background()

	user1 := NewUser()
	user1.UserName = "alice"
	mgr.CreateUser(ctx, user1)

	user2 := NewUser()
	user2.UserName = "alice"
	_, err := mgr.CreateUser(ctx, user2)
	if err == nil {
		t.Error("expected error for duplicate userName")
	}
}

func TestManager_CreateUser_EmptyUserName(t *testing.T) {
	store := newMockScimStorage()
	mgr := NewManager(store, nil)
	ctx := context.Background()

	user := NewUser()
	_, err := mgr.CreateUser(ctx, user)
	if err == nil {
		t.Error("expected error for empty userName")
	}
}

func TestManager_GetUser(t *testing.T) {
	store := newMockScimStorage()
	mgr := NewManager(store, nil)
	ctx := context.Background()

	user := NewUser()
	user.UserName = "bob"
	created, _ := mgr.CreateUser(ctx, user)

	got, err := mgr.GetUser(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetUser failed: %v", err)
	}
	if got.UserName != "bob" {
		t.Errorf("expected bob, got %s", got.UserName)
	}
}

func TestManager_GetUser_NotFound(t *testing.T) {
	store := newMockScimStorage()
	mgr := NewManager(store, nil)
	ctx := context.Background()

	_, err := mgr.GetUser(ctx, "nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent user")
	}
}

func TestManager_UpdateUser(t *testing.T) {
	store := newMockScimStorage()
	mgr := NewManager(store, nil)
	ctx := context.Background()

	user := NewUser()
	user.UserName = "carol"
	created, _ := mgr.CreateUser(ctx, user)

	updated := NewUser()
	updated.UserName = "carol"
	updated.DisplayName = "Carol Updated"
	result, err := mgr.UpdateUser(ctx, created.ID, updated)
	if err != nil {
		t.Fatalf("UpdateUser failed: %v", err)
	}
	if result.DisplayName != "Carol Updated" {
		t.Errorf("expected updated display name, got %s", result.DisplayName)
	}
}

func TestManager_DeleteUser(t *testing.T) {
	store := newMockScimStorage()
	mgr := NewManager(store, nil)
	ctx := context.Background()

	user := NewUser()
	user.UserName = "dave"
	created, _ := mgr.CreateUser(ctx, user)

	if err := mgr.DeleteUser(ctx, created.ID); err != nil {
		t.Fatalf("DeleteUser failed: %v", err)
	}

	_, err := mgr.GetUser(ctx, created.ID)
	if err == nil {
		t.Error("expected error after delete")
	}
}

func TestManager_DeleteUser_NotFound(t *testing.T) {
	store := newMockScimStorage()
	mgr := NewManager(store, nil)
	ctx := context.Background()

	err := mgr.DeleteUser(ctx, "nonexistent")
	if err == nil {
		t.Error("expected error for deleting nonexistent user")
	}
}

func TestManager_ListUsers(t *testing.T) {
	store := newMockScimStorage()
	mgr := NewManager(store, nil)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		u := NewUser()
		u.UserName = fmt.Sprintf("user-%d", i)
		mgr.CreateUser(ctx, u)
	}

	resp, err := mgr.ListUsers(ctx, "", 1, 3)
	if err != nil {
		t.Fatalf("ListUsers failed: %v", err)
	}
	if resp.TotalResults != 5 {
		t.Errorf("expected 5 total, got %d", resp.TotalResults)
	}
	if resp.ItemsPerPage != 3 {
		t.Errorf("expected 3 items per page, got %d", resp.ItemsPerPage)
	}
	if resp.StartIndex != 1 {
		t.Errorf("expected startIndex 1, got %d", resp.StartIndex)
	}
}

func TestManager_CreateGroup(t *testing.T) {
	store := newMockScimStorage()
	mgr := NewManager(store, nil)
	ctx := context.Background()

	group := NewGroup()
	group.DisplayName = "Engineering"

	created, err := mgr.CreateGroup(ctx, group)
	if err != nil {
		t.Fatalf("CreateGroup failed: %v", err)
	}
	if created.ID == "" {
		t.Error("expected ID to be assigned")
	}
	if created.DisplayName != "Engineering" {
		t.Errorf("expected Engineering, got %s", created.DisplayName)
	}
}

func TestManager_CreateGroup_EmptyDisplayName(t *testing.T) {
	store := newMockScimStorage()
	mgr := NewManager(store, nil)
	ctx := context.Background()

	group := NewGroup()
	_, err := mgr.CreateGroup(ctx, group)
	if err == nil {
		t.Error("expected error for empty displayName")
	}
}

func TestManager_GetGroup(t *testing.T) {
	store := newMockScimStorage()
	mgr := NewManager(store, nil)
	ctx := context.Background()

	group := NewGroup()
	group.DisplayName = "DevOps"
	created, _ := mgr.CreateGroup(ctx, group)

	got, err := mgr.GetGroup(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetGroup failed: %v", err)
	}
	if got.DisplayName != "DevOps" {
		t.Errorf("expected DevOps, got %s", got.DisplayName)
	}
}

func TestManager_GetGroup_NotFound(t *testing.T) {
	store := newMockScimStorage()
	mgr := NewManager(store, nil)
	ctx := context.Background()

	_, err := mgr.GetGroup(ctx, "nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent group")
	}
}

func TestManager_UpdateGroup(t *testing.T) {
	store := newMockScimStorage()
	mgr := NewManager(store, nil)
	ctx := context.Background()

	group := NewGroup()
	group.DisplayName = "Old Name"
	created, _ := mgr.CreateGroup(ctx, group)

	updated := NewGroup()
	updated.DisplayName = "New Name"
	result, err := mgr.UpdateGroup(ctx, created.ID, updated)
	if err != nil {
		t.Fatalf("UpdateGroup failed: %v", err)
	}
	if result.DisplayName != "New Name" {
		t.Errorf("expected New Name, got %s", result.DisplayName)
	}
}

func TestManager_DeleteGroup(t *testing.T) {
	store := newMockScimStorage()
	mgr := NewManager(store, nil)
	ctx := context.Background()

	group := NewGroup()
	group.DisplayName = "ToDelete"
	created, _ := mgr.CreateGroup(ctx, group)

	if err := mgr.DeleteGroup(ctx, created.ID); err != nil {
		t.Fatalf("DeleteGroup failed: %v", err)
	}

	_, err := mgr.GetGroup(ctx, created.ID)
	if err == nil {
		t.Error("expected error after delete")
	}
}

func TestManager_ListGroups(t *testing.T) {
	store := newMockScimStorage()
	mgr := NewManager(store, nil)
	ctx := context.Background()

	for i := 0; i < 4; i++ {
		g := NewGroup()
		g.DisplayName = fmt.Sprintf("group-%d", i)
		mgr.CreateGroup(ctx, g)
	}

	resp, err := mgr.ListGroups(ctx, "", 1, 10)
	if err != nil {
		t.Fatalf("ListGroups failed: %v", err)
	}
	if resp.TotalResults != 4 {
		t.Errorf("expected 4 total, got %d", resp.TotalResults)
	}
	if len(resp.Resources) != 4 {
		t.Errorf("expected 4 resources, got %d", len(resp.Resources))
	}
}
