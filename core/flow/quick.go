package flow

import (
	"github.com/getkayan/kayan/core/domain"
	"github.com/getkayan/kayan/core/events"
	"github.com/google/uuid"
)

// PasswordAuth creates a ready-to-use registration and login manager pair
// for password-based authentication. It wires a BcryptHasher, PasswordStrategy,
// and UUID ID generator, reducing typical setup from ~8 lines to one call.
//
// Usage:
//
//	reg, login := flow.PasswordAuth(repo, func() any { return &User{} }, "email")
func PasswordAuth(repo IdentityRepository, factory func() any, identifierField string, opts ...QuickOption) (*RegistrationManager, *LoginManager) {
	cfg := &quickConfig{
		hasherCost:      10,
		identifierField: identifierField,
		idGenerator:     func() any { return uuid.New().String() },
	}
	for _, opt := range opts {
		opt(cfg)
	}

	if cfg.identifierField == "" {
		cfg.identifierField = "email"
	}

	hasher := NewBcryptHasher(cfg.hasherCost)
	pwStrategy := NewPasswordStrategy(repo, hasher, cfg.identifierField, factory)
	pwStrategy.SetIDGenerator(cfg.idGenerator)
	if cfg.passwordPolicy != nil {
		pwStrategy.SetPasswordPolicy(cfg.passwordPolicy)
	}

	var regOpts []RegistrationOption
	var loginOpts []LoginOption

	if cfg.dispatcher != nil {
		regOpts = append(regOpts, WithRegDispatcher(cfg.dispatcher))
		loginOpts = append(loginOpts, WithLoginDispatcher(cfg.dispatcher))
	}
	for _, h := range cfg.regPreHooks {
		regOpts = append(regOpts, WithRegPreHook(h))
	}
	for _, h := range cfg.regPostHooks {
		regOpts = append(regOpts, WithRegPostHook(h))
	}
	for _, h := range cfg.loginPreHooks {
		loginOpts = append(loginOpts, WithLoginPreHook(h))
	}
	for _, h := range cfg.loginPostHooks {
		loginOpts = append(loginOpts, WithLoginPostHook(h))
	}

	reg := NewRegistrationManager(repo, factory, regOpts...)
	login := NewLoginManager(repo, factory, loginOpts...)

	reg.RegisterStrategy(pwStrategy)
	login.RegisterStrategy(pwStrategy)

	return reg, login
}

type quickConfig struct {
	hasherCost      int
	identifierField string
	idGenerator     domain.IDGenerator
	dispatcher      events.Dispatcher
	regPreHooks     []Hook
	regPostHooks    []Hook
	loginPreHooks   []Hook
	loginPostHooks  []Hook
	passwordPolicy  *PasswordPolicy
}

// QuickOption configures the PasswordAuth convenience constructor.
type QuickOption func(*quickConfig)

// WithHasherCost sets the bcrypt cost for password hashing. Default is 10.
func WithHasherCost(cost int) QuickOption {
	return func(c *quickConfig) { c.hasherCost = cost }
}

// WithIDGenerator sets the ID generator for new identities.
func WithIDGenerator(gen domain.IDGenerator) QuickOption {
	return func(c *quickConfig) { c.idGenerator = gen }
}

// WithQuickDispatcher sets the event dispatcher on both managers.
func WithQuickDispatcher(d events.Dispatcher) QuickOption {
	return func(c *quickConfig) { c.dispatcher = d }
}

// WithRegHook adds pre and post hooks to the registration manager.
func WithRegHook(pre, post Hook) QuickOption {
	return func(c *quickConfig) {
		if pre != nil {
			c.regPreHooks = append(c.regPreHooks, pre)
		}
		if post != nil {
			c.regPostHooks = append(c.regPostHooks, post)
		}
	}
}

// WithLoginHook adds pre and post hooks to the login manager.
func WithLoginHook(pre, post Hook) QuickOption {
	return func(c *quickConfig) {
		if pre != nil {
			c.loginPreHooks = append(c.loginPreHooks, pre)
		}
		if post != nil {
			c.loginPostHooks = append(c.loginPostHooks, post)
		}
	}
}

// WithPasswordPolicy sets the password validation policy for the password strategy.
func WithPasswordPolicy(p *PasswordPolicy) QuickOption {
	return func(c *quickConfig) { c.passwordPolicy = p }
}
