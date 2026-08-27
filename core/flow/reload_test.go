package flow

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/getkayan/kayan/core/domain"
	"github.com/getkayan/kayan/core/identity"
)

// staticStrategyStore serves a fixed set of strategy configs.
type staticStrategyStore struct {
	configs []*domain.StrategyConfig
}

func (s *staticStrategyStore) GetStrategies(context.Context) ([]*domain.StrategyConfig, error) {
	return s.configs, nil
}
func (s *staticStrategyStore) GetStrategy(context.Context, string) (*domain.StrategyConfig, error) {
	return nil, errors.New("not implemented")
}
func (s *staticStrategyStore) SaveStrategy(context.Context, *domain.StrategyConfig) error {
	return nil
}
func (s *staticStrategyStore) DeleteStrategy(context.Context, string) error { return nil }

// namedStrategy is a stand-in whose identity a test can check.
type namedStrategy struct{ name string }

func (s *namedStrategy) ID() string { return "reloadable" }
func (s *namedStrategy) Authenticate(context.Context, string, string) (any, error) {
	return &identity.Identity{ID: s.name}, nil
}

// TestReloadStrategiesReportsBuildFailures covers a misconfiguration that
// looked like it had been applied.
//
// A strategy that failed to build was written to the process's stderr with the
// standard library logger and skipped. The map was never cleared, so the
// previous definition stayed live and serving logins: an operator who
// tightened a strategy and reloaded got the old, looser one, with the only
// evidence in a log line the library gave them no way to intercept.
//
// A reload that could not apply what it was told to apply is an error.
func TestReloadStrategiesReportsBuildFailures(t *testing.T) {
	repo := &mockRepo{
		identities: make(map[string]any),
		creds:      make(map[string]*identity.Credential),
	}
	manager := NewLoginManager(repo, func() any { return &identity.Identity{} })

	// The strategy that is already serving logins.
	manager.RegisterStrategy(&namedStrategy{name: "original"})

	// The registry knows nothing about this type, so Build fails.
	store := &staticStrategyStore{configs: []*domain.StrategyConfig{
		{ID: "reloadable", Type: "a-type-no-factory-handles", Enabled: true},
	}}
	manager.SetStrategyStore(store)

	err := manager.ReloadStrategies(context.Background())
	if err == nil {
		t.Fatal("ReloadStrategies reported success although a strategy failed to build")
	}
	if !strings.Contains(err.Error(), "reloadable") {
		t.Errorf("error = %v, want it to name the strategy that failed", err)
	}
}

// TestReloadStrategiesKeepsWorkingStrategies makes sure the error does not
// come at the cost of a partial reload being silently discarded: strategies
// that did build must still be applied, so one bad config does not take down
// every other login method.
func TestReloadStrategiesKeepsWorkingStrategies(t *testing.T) {
	repo := &mockRepo{
		identities: make(map[string]any),
		creds:      make(map[string]*identity.Credential),
	}
	manager := NewLoginManager(repo, func() any { return &identity.Identity{} })

	manager.Registry().RegisterFactory("known-type", func(*domain.StrategyConfig) (LoginStrategy, error) {
		return &namedStrategy{name: "rebuilt"}, nil
	})

	store := &staticStrategyStore{configs: []*domain.StrategyConfig{
		{ID: "reloadable", Type: "known-type", Enabled: true},
		{ID: "broken", Type: "a-type-no-factory-handles", Enabled: true},
	}}
	manager.SetStrategyStore(store)

	if err := manager.ReloadStrategies(context.Background()); err == nil {
		t.Fatal("ReloadStrategies hid the failing strategy")
	}

	ident, err := manager.Authenticate(context.Background(), "reloadable", "user", "secret")
	if err != nil {
		t.Fatalf("the strategy that built successfully is not usable: %v", err)
	}
	if got := ident.(*identity.Identity).ID; got != "rebuilt" {
		t.Errorf("authenticated through %q, want the rebuilt strategy", got)
	}
}

// TestReloadStrategiesSucceedsWhenEverythingBuilds keeps the ordinary path
// quiet: a reload where every config builds is not an error.
func TestReloadStrategiesSucceedsWhenEverythingBuilds(t *testing.T) {
	repo := &mockRepo{
		identities: make(map[string]any),
		creds:      make(map[string]*identity.Credential),
	}
	manager := NewLoginManager(repo, func() any { return &identity.Identity{} })
	manager.Registry().RegisterFactory("known-type", func(*domain.StrategyConfig) (LoginStrategy, error) {
		return &namedStrategy{name: "rebuilt"}, nil
	})
	manager.SetStrategyStore(&staticStrategyStore{configs: []*domain.StrategyConfig{
		{ID: "reloadable", Type: "known-type", Enabled: true},
	}})

	if err := manager.ReloadStrategies(context.Background()); err != nil {
		t.Errorf("a reload where everything built returned an error: %v", err)
	}
}
