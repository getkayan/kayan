package flow

import (
	"context"
	"sync"
	"testing"

	"github.com/getkayan/kayan/core/domain"
	"github.com/getkayan/kayan/core/identity"
)

type stubLoginStrategy struct {
	id string
}

func (s *stubLoginStrategy) ID() string { return s.id }
func (s *stubLoginStrategy) Authenticate(_ context.Context, _, _ string) (any, error) {
	return nil, nil
}

type stubRegStrategy struct {
	id string
}

func (s *stubRegStrategy) ID() string { return s.id }
func (s *stubRegStrategy) Register(_ context.Context, _ identity.JSON, _ string) (any, error) {
	return nil, nil
}

func TestRegistry_RegisterAndBuildLogin(t *testing.T) {
	reg := NewStrategyRegistry()
	reg.RegisterFactory("password", func(config *domain.StrategyConfig) (LoginStrategy, error) {
		return &stubLoginStrategy{id: config.ID}, nil
	})

	s, err := reg.Build(&domain.StrategyConfig{ID: "pw1", Type: "password"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.ID() != "pw1" {
		t.Fatalf("expected ID 'pw1', got %q", s.ID())
	}
}

func TestRegistry_RegisterAndBuildRegistration(t *testing.T) {
	reg := NewStrategyRegistry()
	reg.RegisterRegistrationFactory("password", func(config *domain.StrategyConfig) (RegistrationStrategy, error) {
		return &stubRegStrategy{id: config.ID}, nil
	})

	s, err := reg.BuildRegistration(&domain.StrategyConfig{ID: "reg1", Type: "password"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.ID() != "reg1" {
		t.Fatalf("expected ID 'reg1', got %q", s.ID())
	}
}

func TestRegistry_BuildUnknown(t *testing.T) {
	reg := NewStrategyRegistry()
	_, err := reg.Build(&domain.StrategyConfig{Type: "nonexistent"})
	if err == nil {
		t.Fatal("expected error for unknown type")
	}
	_, err = reg.BuildRegistration(&domain.StrategyConfig{Type: "nonexistent"})
	if err == nil {
		t.Fatal("expected error for unknown registration type")
	}
}

func TestRegistry_ListFactories(t *testing.T) {
	reg := NewStrategyRegistry()
	reg.RegisterFactory("oidc", func(config *domain.StrategyConfig) (LoginStrategy, error) {
		return nil, nil
	})
	reg.RegisterFactory("password", func(config *domain.StrategyConfig) (LoginStrategy, error) {
		return nil, nil
	})
	reg.RegisterRegistrationFactory("magic_link", func(config *domain.StrategyConfig) (RegistrationStrategy, error) {
		return nil, nil
	})
	// password appears in both — should be deduplicated
	reg.RegisterRegistrationFactory("password", func(config *domain.StrategyConfig) (RegistrationStrategy, error) {
		return nil, nil
	})

	keys := reg.ListFactories()
	expected := []string{"magic_link", "oidc", "password"}
	if len(keys) != len(expected) {
		t.Fatalf("expected %d keys, got %d: %v", len(expected), len(keys), keys)
	}
	for i, k := range keys {
		if k != expected[i] {
			t.Fatalf("expected keys[%d] = %q, got %q", i, expected[i], k)
		}
	}
}

func TestRegistry_Concurrent(t *testing.T) {
	reg := NewStrategyRegistry()
	var wg sync.WaitGroup

	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func(n int) {
			defer wg.Done()
			reg.RegisterFactory("type", func(config *domain.StrategyConfig) (LoginStrategy, error) {
				return &stubLoginStrategy{id: "s"}, nil
			})
		}(i)
		go func(n int) {
			defer wg.Done()
			reg.Build(&domain.StrategyConfig{Type: "type"})
		}(i)
	}

	wg.Wait()
	keys := reg.ListFactories()
	if len(keys) == 0 {
		t.Fatal("expected at least one factory registered")
	}
}
