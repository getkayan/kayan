package tenant

import (
	"context"
	"fmt"
	"testing"
)

type memoryCache struct {
	values map[string]string
}

func (m *memoryCache) Get(ctx context.Context, key string) (string, bool) {
	value, ok := m.values[key]
	return value, ok
}

func (m *memoryCache) Set(ctx context.Context, key string, value string, ttlSeconds int) error {
	m.values[key] = value
	return nil
}

func TestResolveInfoFromRequest(t *testing.T) {
	info := ResolveInfo{
		Headers: map[string][]string{"X-Tenant-ID": {"tenant-1"}},
		Query:   map[string][]string{"tenant": {"tenant-2"}},
	}

	if got := info.HeaderValue("x-tenant-id"); got != "tenant-1" {
		t.Fatalf("expected tenant-1 header, got %q", got)
	}
	if got := info.QueryValue("tenant"); got != "tenant-2" {
		t.Fatalf("expected tenant-2 query value, got %q", got)
	}
}

func TestBuiltInResolvers(t *testing.T) {
	ctx := context.Background()
	info := ResolveInfo{
		Host:    "acme.example.com:8443",
		Path:    "/api/v1/tenants/acme/users",
		Headers: map[string][]string{"X-Tenant-ID": {"header-acme"}},
		Query:   map[string][]string{"tenant": {"query-acme"}},
	}

	tests := []struct {
		name     string
		resolver Resolver
		want     string
	}{
		{name: "subdomain", resolver: NewSubdomainResolver("example.com"), want: "acme"},
		{name: "header", resolver: NewHeaderResolver("X-Tenant-ID"), want: "header-acme"},
		{name: "path", resolver: NewPathResolver("/api/v1/tenants/", 0), want: "acme"},
		{name: "query", resolver: NewQueryResolver("tenant"), want: "query-acme"},
		{name: "static", resolver: NewStaticResolver("static-acme"), want: "static-acme"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := test.resolver.Resolve(ctx, info)
			if err != nil {
				t.Fatalf("Resolve failed: %v", err)
			}
			if got != test.want {
				t.Fatalf("expected %q, got %q", test.want, got)
			}
		})
	}
}

func TestJWTClaimResolver(t *testing.T) {
	ctx := context.WithValue(context.Background(), "claims", map[string]any{"tenant_id": "claim-acme"})
	resolver := NewJWTClaimResolver("tenant_id", "claims")

	got, err := resolver.Resolve(ctx, ResolveInfo{})
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}
	if got != "claim-acme" {
		t.Fatalf("expected claim-acme, got %q", got)
	}
}

func TestChainResolver(t *testing.T) {
	resolver := NewChainResolver(
		ResolverFunc(func(ctx context.Context, info ResolveInfo) (string, error) { return "", nil }),
		ResolverFunc(func(ctx context.Context, info ResolveInfo) (string, error) { return "chain-acme", nil }),
	)

	got, err := resolver.Resolve(context.Background(), ResolveInfo{})
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}
	if got != "chain-acme" {
		t.Fatalf("expected chain-acme, got %q", got)
	}
}

func TestCacheResolver(t *testing.T) {
	cache := &memoryCache{values: make(map[string]string)}
	called := 0
	resolver := NewCacheResolver(
		ResolverFunc(func(ctx context.Context, info ResolveInfo) (string, error) {
			called++
			return "cached-acme", nil
		}),
		cache,
		nil,
	)

	info := ResolveInfo{Host: "app.example.com"}
	for range 2 {
		got, err := resolver.Resolve(context.Background(), info)
		if err != nil {
			t.Fatalf("Resolve failed: %v", err)
		}
		if got != "cached-acme" {
			t.Fatalf("expected cached-acme, got %q", got)
		}
	}

	if called != 1 {
		t.Fatalf("expected inner resolver to be called once, got %d", called)
	}
}

func TestValidatingResolver(t *testing.T) {
	store := newMockStore()
	store.tenants["tenant-1"] = &Tenant{ID: "tenant-1", Active: true}

	resolver := NewValidatingResolver(
		ResolverFunc(func(ctx context.Context, info ResolveInfo) (string, error) {
			return "tenant-1", nil
		}),
		store,
	)

	got, err := resolver.Resolve(context.Background(), ResolveInfo{})
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}
	if got != "tenant-1" {
		t.Fatalf("expected tenant-1, got %q", got)
	}
}

func TestValidatingResolver_Inactive(t *testing.T) {
	store := newMockStore()
	store.tenants["tenant-1"] = &Tenant{ID: "tenant-1", Active: false}

	resolver := NewValidatingResolver(
		ResolverFunc(func(ctx context.Context, info ResolveInfo) (string, error) {
			return "tenant-1", nil
		}),
		store,
	)

	_, err := resolver.Resolve(context.Background(), ResolveInfo{})
	if err == nil || err.Error() != "tenant is inactive: tenant-1" {
		t.Fatalf("expected inactive tenant error, got %v", err)
	}
}

func TestValidatingResolver_InnerError(t *testing.T) {
	wantErr := fmt.Errorf("boom")
	resolver := NewValidatingResolver(
		ResolverFunc(func(ctx context.Context, info ResolveInfo) (string, error) {
			return "", wantErr
		}),
		newMockStore(),
	)

	_, err := resolver.Resolve(context.Background(), ResolveInfo{})
	if err != wantErr {
		t.Fatalf("expected %v, got %v", wantErr, err)
	}
}
