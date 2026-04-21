package tenant

import (
	"context"
	"fmt"
	"net/http/httptest"
	"testing"
)

// --- Mocks ---

type mockStore struct {
	tenants map[string]*Tenant
}

func newMockStore() *mockStore {
	return &mockStore{
		tenants: make(map[string]*Tenant),
	}
}

func (m *mockStore) Get(ctx context.Context, id string) (*Tenant, error) {
	if t, ok := m.tenants[id]; ok {
		return t, nil
	}
	return nil, fmt.Errorf("tenant not found")
}

func (m *mockStore) GetByDomain(ctx context.Context, domain string) (*Tenant, error) {
	for _, t := range m.tenants {
		if t.Domain == domain {
			return t, nil
		}
	}
	return nil, fmt.Errorf("tenant not found")
}

func (m *mockStore) Create(ctx context.Context, t *Tenant) error {
	m.tenants[t.ID] = t
	return nil
}
func (m *mockStore) Update(ctx context.Context, t *Tenant) error { return nil }
func (m *mockStore) Delete(ctx context.Context, id string) error { return nil }
func (m *mockStore) GetBySlug(ctx context.Context, slug string) (*Tenant, error) {
	return nil, fmt.Errorf("not implemented")
}
func (m *mockStore) List(ctx context.Context, f ListFilter) ([]*Tenant, error) { return nil, nil }

type mockResolver struct {
	resolveFunc func(info ResolveInfo) (string, error)
}

func (m *mockResolver) Resolve(ctx context.Context, info ResolveInfo) (string, error) {
	if m.resolveFunc != nil {
		return m.resolveFunc(info)
	}
	return "", nil
}

// --- Tests ---

func TestNewManager(t *testing.T) {
	store := newMockStore()
	resolver := &mockResolver{}
	m := NewManager(store, resolver)
	if m == nil {
		t.Fatal("NewManager returned nil")
	}
	if !m.RequireTenant {
		t.Error("Default RequireTenant should be true")
	}
}

func TestResolveFromRequest_Success(t *testing.T) {
	store := newMockStore()
	store.Create(context.Background(), &Tenant{ID: "t1", Active: true})

	resolver := &mockResolver{
		resolveFunc: func(info ResolveInfo) (string, error) {
			return "t1", nil
		},
	}

	m := NewManager(store, resolver)
	tenant, ctx, err := m.Resolve(context.Background(), ResolveInfo{Host: "tenant.example.com"})

	if err != nil {
		t.Fatalf("ResolveFromRequest failed: %v", err)
	}
	if tenant == nil {
		t.Fatal("Returned tenant is nil")
	}
	if tenant.ID != "t1" {
		t.Errorf("Expected tenant t1, got %s", tenant.ID)
	}

	// Check context
	if loadedTenant := FromContext(ctx); loadedTenant == nil {
		t.Error("Tenant not loaded into context")
	}
}

func TestResolveFromRequest_NotFound(t *testing.T) {
	store := newMockStore()
	resolver := &mockResolver{
		resolveFunc: func(info ResolveInfo) (string, error) {
			return "t1", nil // Resolver finds ID, but store doesn't have it
		},
	}

	m := NewManager(store, resolver)
	_, _, err := m.Resolve(context.Background(), ResolveInfo{})

	if err == nil {
		t.Error("Expected error for non-existent tenant")
	}
}

func TestResolveFromRequest_Optional(t *testing.T) {
	store := newMockStore()
	resolver := &mockResolver{
		resolveFunc: func(info ResolveInfo) (string, error) {
			return "", nil // No tenant found
		},
	}

	m := NewManager(store, resolver, WithOptionalTenant())
	tenant, _, err := m.Resolve(context.Background(), ResolveInfo{})

	if err != nil {
		t.Fatalf("Unexpected error for optional tenant: %v", err)
	}
	if tenant != nil {
		t.Error("Expected nil tenant")
	}
}

func TestResolveFromRequest_Hook(t *testing.T) {
	store := newMockStore()
	store.Create(context.Background(), &Tenant{ID: "hook-tenant", Active: true})

	resolver := &mockResolver{}
	m := NewManager(store, resolver)

	m.hooks.BeforeResolve = func(ctx context.Context, info ResolveInfo) (string, bool) {
		return "hook-tenant", true
	}

	req := httptest.NewRequest("GET", "/", nil)
	tenant, _, err := m.ResolveFromRequest(context.Background(), req)

	if err != nil {
		t.Fatalf("ResolveFromRequest failed: %v", err)
	}
	if tenant.ID != "hook-tenant" {
		t.Errorf("Expected hook-tenant, got %s", tenant.ID)
	}
}

func TestResolveFromRequest_AdaptsRequest(t *testing.T) {
	store := newMockStore()
	store.Create(context.Background(), &Tenant{ID: "header-tenant", Active: true})

	resolver := &mockResolver{
		resolveFunc: func(info ResolveInfo) (string, error) {
			if info.Host != "app.example.com" {
				t.Fatalf("expected host app.example.com, got %q", info.Host)
			}
			if info.Path != "/tenants/header-tenant" {
				t.Fatalf("expected path /tenants/header-tenant, got %q", info.Path)
			}
			if info.HeaderValue("X-Tenant-ID") != "header-tenant" {
				t.Fatalf("expected X-Tenant-ID header to be propagated")
			}
			if info.QueryValue("tenant") != "query-tenant" {
				t.Fatalf("expected tenant query to be propagated")
			}
			return info.HeaderValue("X-Tenant-ID"), nil
		},
	}

	m := NewManager(store, resolver)
	req := httptest.NewRequest("GET", "http://app.example.com/tenants/header-tenant?tenant=query-tenant", nil)
	req.Header.Set("X-Tenant-ID", "header-tenant")

	tenant, ctx, err := m.ResolveFromRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("ResolveFromRequest failed: %v", err)
	}
	if tenant == nil || tenant.ID != "header-tenant" {
		t.Fatalf("expected header-tenant, got %#v", tenant)
	}
	if IDFromContext(ctx) != "header-tenant" {
		t.Fatalf("expected tenant id in context, got %q", IDFromContext(ctx))
	}
}
