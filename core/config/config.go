// Package config provides environment-based configuration for Kayan IAM.
//
// Configuration is loaded from environment variables using Viper, with sensible
// defaults for development. This package handles database connection settings,
// logging levels, server ports, and OIDC provider configurations.
//
// # Environment Variables
//
//   - DB_TYPE: Database type (sqlite, postgres, mysql). Default: sqlite
//   - DSN: Database connection string. Default: kayan.db
//   - SKIP_AUTO_MIGRATE: Skip automatic database migrations. Default: false
//   - LOG_LEVEL: Logging level (debug, info, warn, error). Default: info
//   - PORT: HTTP server port. Default: 8080
//
// # OIDC Provider Configuration
//
// OIDC providers are configured via the OIDC_PROVIDERS map:
//
//	OIDC_PROVIDERS_GOOGLE_ISSUER=https://accounts.google.com
//	OIDC_PROVIDERS_GOOGLE_CLIENT_ID=your-client-id
//	OIDC_PROVIDERS_GOOGLE_CLIENT_SECRET=your-secret
//
// # Example Usage
//
//	cfg, err := config.LoadConfig()
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Starting on port %d with %s database\n", cfg.Port, cfg.DBType)
package config

import (
	"strings"

	"github.com/spf13/viper"
)

type Config struct {
	DBType          string                  `mapstructure:"DB_TYPE"` // sqlite, postgres, mysql
	DSN             string                  `mapstructure:"DSN"`
	SkipAutoMigrate bool                    `mapstructure:"SKIP_AUTO_MIGRATE"`
	LogLevel        string                  `mapstructure:"LOG_LEVEL"`
	Port            int                     `mapstructure:"PORT"`
	OIDCProviders   map[string]OIDCProvider `mapstructure:"OIDC_PROVIDERS"`
}

type OIDCProvider struct {
	Issuer       string `mapstructure:"issuer"`
	ClientID     string `mapstructure:"client_id"`
	ClientSecret string `mapstructure:"client_secret"`
	RedirectURL  string `mapstructure:"redirect_url"`
}

func LoadConfig() (*Config, error) {
	viper.SetDefault("LOG_LEVEL", "info")
	viper.SetDefault("PORT", 8080)
	viper.SetDefault("DB_TYPE", "sqlite")
	viper.SetDefault("DSN", "kayan.db") // Default to sqlite if not provided
	viper.SetDefault("SKIP_AUTO_MIGRATE", false)

	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()

	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}
