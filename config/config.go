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

