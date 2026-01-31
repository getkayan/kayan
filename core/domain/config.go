package domain

import (
	"context"
)

// StrategyConfig represents the persisted configuration for a login strategy.
type StrategyConfig struct {
	ID       string         `json:"id"`       // Unique identifier (e.g. "google-marketing", "otp-sms")
	Type     string         `json:"type"`     // Strategy implementation type (e.g. "oauth2", "oidc", "password", "magic_link")
	Provider string         `json:"provider"` // Provider identifier (e.g. "google", "github")
	Enabled  bool           `json:"enabled"`  // Is this strategy active?
	Settings map[string]any `json:"settings"` // Type-specific settings (client_id, etc.)
}

// StrategyStore defines the interface for persisting strategy configurations.
type StrategyStore interface {
	GetStrategies(ctx context.Context) ([]*StrategyConfig, error)
	GetStrategy(ctx context.Context, id string) (*StrategyConfig, error)
	SaveStrategy(ctx context.Context, config *StrategyConfig) error
	DeleteStrategy(ctx context.Context, id string) error
}
