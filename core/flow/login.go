package flow

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"

	"github.com/getkayan/kayan/core/audit"
	"github.com/getkayan/kayan/core/domain"
	"github.com/getkayan/kayan/core/events"
)

// Attacher is an optional interface for strategies that support linking to an existing identity.
type Attacher interface {
	Attach(ctx context.Context, ident any, identifier, secret string) error
}

type LoginManager struct {
	repo       IdentityRepository
	auditSink  *auditSink
	dispatcher events.Dispatcher

	// Dynamic Config
	strategyStore    domain.StrategyStore
	strategyRegistry *StrategyRegistry

	mu         sync.RWMutex
	strategies map[string]LoginStrategy
	preHooks   []Hook
	postHooks  []Hook
	factory    func() any
}

// LoginOption configures a LoginManager.
type LoginOption func(*LoginManager)

// WithLoginDispatcher sets the event dispatcher.
func WithLoginDispatcher(d events.Dispatcher) LoginOption {
	return func(m *LoginManager) { m.dispatcher = d }
}

// WithLoginAudit explicitly enables audit persistence and error reporting.
func WithLoginAudit(store audit.AuditStore, onError AuditErrorHandler) LoginOption {
	return func(m *LoginManager) { m.auditSink = newAuditSink(store, onError) }
}

// WithStrategyStore sets the dynamic strategy configuration store.
func WithStrategyStore(s domain.StrategyStore) LoginOption {
	return func(m *LoginManager) { m.strategyStore = s }
}

// WithLoginPreHook adds a pre-authentication hook.
func WithLoginPreHook(h Hook) LoginOption {
	return func(m *LoginManager) { m.preHooks = append(m.preHooks, h) }
}

// WithLoginPostHook adds a post-authentication hook.
func WithLoginPostHook(h Hook) LoginOption {
	return func(m *LoginManager) { m.postHooks = append(m.postHooks, h) }
}

var ErrMFARequired = errors.New("login: mfa required")

// MFARequiredError reports that the first factor succeeded and a second is
// outstanding. It carries the identity so the caller can drive the challenge
// and pass it to VerifyMFA.
//
// The identity travels on the error rather than as Authenticate's first return
// value on purpose. Returning a usable identity alongside a non-nil error let
// a caller who wrote `ident, _ := Authenticate(...)` mint a session with no
// second factor ever presented. Reaching the identity now requires
// acknowledging the error that explains why it is not yet authenticated.
type MFARequiredError struct {
	// Identity is the partially authenticated identity. It has passed the
	// first factor only and must not be treated as logged in.
	Identity any
}

func (e *MFARequiredError) Error() string { return ErrMFARequired.Error() }

// Unwrap lets errors.Is(err, ErrMFARequired) keep working.
func (e *MFARequiredError) Unwrap() error { return ErrMFARequired }

// MFAIdentityFrom returns the pending identity from an MFA-required error.
func MFAIdentityFrom(err error) (any, bool) {
	var mfaErr *MFARequiredError
	if errors.As(err, &mfaErr) && mfaErr.Identity != nil {
		return mfaErr.Identity, true
	}
	return nil, false
}

func NewLoginManager(repo IdentityRepository, factory func() any, opts ...LoginOption) *LoginManager {
	m := &LoginManager{
		repo:             repo,
		strategies:       make(map[string]LoginStrategy),
		strategyRegistry: NewStrategyRegistry(),
		factory:          factory,
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// Deprecated: Use WithStrategyStore option instead.
func (m *LoginManager) SetStrategyStore(store domain.StrategyStore) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.strategyStore = store
}

func (m *LoginManager) Registry() *StrategyRegistry {
	return m.strategyRegistry
}

// Deprecated: Use WithLoginDispatcher option instead.
func (m *LoginManager) SetDispatcher(d events.Dispatcher) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.dispatcher = d
}

// ReloadStrategies fetches configs from the store and rebuilds strategies.
func (m *LoginManager) ReloadStrategies(ctx context.Context) error {
	m.mu.RLock()
	store := m.strategyStore
	m.mu.RUnlock()

	if store == nil {
		return nil
	}

	configs, err := store.GetStrategies(ctx)
	if err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Clear existing (dynamic ones)? Or just overwrite.
	// For safety, let's keep manually registered ones if they don't collide.
	// But usually dynamic overrides static.

	for _, cfg := range configs {
		if !cfg.Enabled {
			delete(m.strategies, cfg.ID)
			continue
		}

		strategy, err := m.strategyRegistry.Build(cfg)
		if err != nil {
			// Log error but continue?
			log.Printf("login: failed to build strategy %s: %v", cfg.ID, err)
			continue
		}
		m.strategies[cfg.ID] = strategy
	}
	return nil
}

func (m *LoginManager) FindIdentity(ctx context.Context, identifier string) (any, error) {
	if m.factory == nil {
		return nil, fmt.Errorf("login: factory not set")
	}
	return m.repo.FindIdentity(ctx, m.factory, map[string]any{"identifier": identifier})
}

// VerifyMFA checks the second factor (e.g. TOTP) for an identity.
func (m *LoginManager) VerifyMFA(ctx context.Context, ident any, code string) (bool, error) {
	mfaIdent, ok := ident.(MFAIdentity)
	if !ok {
		return false, fmt.Errorf("login: invalid identity type for MFA")
	}

	enabled, secret := mfaIdent.MFAConfig()
	if !enabled {
		return true, nil
	}

	strategy := &TOTPStrategy{}
	return strategy.Verify(secret, code), nil
}

func (m *LoginManager) RegisterStrategy(s LoginStrategy) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.strategies[s.ID()] = s
}

func (m *LoginManager) AddPreHook(h Hook) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.preHooks = append(m.preHooks, h)
}

func (m *LoginManager) AddPostHook(h Hook) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.postHooks = append(m.postHooks, h)
}

func (m *LoginManager) InitiateLogin(ctx context.Context, method, identifier string) (any, error) {
	m.mu.RLock()
	strategy, ok := m.strategies[method]
	auditSink := m.auditSink
	dispatcher := m.dispatcher
	m.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("login: unknown method %q", method)
	}

	initiator, ok := strategy.(Initiator)
	if !ok {
		return nil, fmt.Errorf("login: method %q does not support initiation", method)
	}

	result, err := initiator.Initiate(ctx, identifier)
	if err != nil {
		return nil, err
	}

	if auditSink != nil {
		auditSink.save(ctx, &audit.AuditEvent{
			Type:    string(events.TopicLoginInitiated),
			ActorID: identifier,
			Status:  "success",
			Message: fmt.Sprintf("Initiated login using %s", method),
		})
	}

	if dispatcher != nil {
		event := events.NewEvent(events.TopicLoginInitiated, events.CodeAccepted)
		event.ActorID = identifier
		// #nosec G104 -- domain events are best-effort and cannot change auth outcome.
		dispatcher.Dispatch(ctx, event)
	}

	return result, nil
}

func (m *LoginManager) Authenticate(ctx context.Context, method, identifier, secret string) (any, error) {
	m.mu.RLock()
	strategy, ok := m.strategies[method]
	preHooks := append([]Hook(nil), m.preHooks...)
	postHooks := append([]Hook(nil), m.postHooks...)
	auditSink := m.auditSink
	dispatcher := m.dispatcher
	m.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("login: unknown method %q", method)
	}

	// 1. Pre-hooks
	for _, h := range preHooks {
		if err := h(ctx, nil); err != nil {
			return nil, err
		}
	}

	// 2. Delegate to strategy
	ident, err := strategy.Authenticate(ctx, identifier, secret)
	if err != nil {
		if auditSink != nil {
			auditSink.save(ctx, &audit.AuditEvent{
				Type:    string(events.TopicLoginFailure),
				ActorID: identifier,
				Status:  "failure",
				Message: err.Error(),
			})
		}
		if dispatcher != nil {
			event := events.NewEvent(events.TopicLoginFailure, events.CodeUnauthorized)
			event.ActorID = identifier
			// #nosec G104 -- domain events are best-effort and cannot change auth outcome.
			dispatcher.Dispatch(ctx, event)
		}
		return nil, err
	}

	// Check if MFA required
	if mfaIdent, ok := ident.(MFAIdentity); ok {
		enabled, _ := mfaIdent.MFAConfig()
		if enabled {
			if auditSink != nil {
				auditSink.save(ctx, &audit.AuditEvent{
					Type:    string(events.TopicLoginMFARequired),
					ActorID: identifier,
					Status:  "success",
					Message: "First step success, MFA required",
				})
			}
			if dispatcher != nil {
				event := events.NewEvent(events.TopicLoginMFARequired, events.CodeAccepted)
				event.ActorID = identifier
				// #nosec G104 -- domain events are best-effort and cannot change auth outcome.
				dispatcher.Dispatch(ctx, event)
			}
			// The identity travels on the error, not as the first return
			// value: the first factor succeeding is not authentication while
			// a second is outstanding, and `ident, _ :=` must not yield
			// something a session can be minted from.
			return nil, &MFARequiredError{Identity: ident}
		}
	}

	// 3. Post-hooks run before success is recorded. A hook that returns an
	// error denies the login, so emitting the success event first told the
	// audit trail and every subscriber about a login that did not happen --
	// and the audit trail is what an incident is reconstructed from.
	for _, h := range postHooks {
		if err := h(ctx, ident); err != nil {
			if auditSink != nil {
				auditSink.save(ctx, &audit.AuditEvent{
					Type:    string(events.TopicLoginFailure),
					ActorID: identifier,
					Status:  "failure",
					Message: "Login denied by a post-hook: " + err.Error(),
				})
			}
			if dispatcher != nil {
				event := events.NewEvent(events.TopicLoginFailure, events.CodeUnauthorized)
				event.ActorID = identifier
				// #nosec G104 -- domain events are best-effort and cannot change auth outcome.
				dispatcher.Dispatch(ctx, event)
			}
			return nil, err
		}
	}

	if auditSink != nil {
		auditSink.save(ctx, &audit.AuditEvent{
			Type:    string(events.TopicLoginSuccess),
			ActorID: identifier,
			Status:  "success",
			Message: "Login successful",
		})
	}

	if dispatcher != nil {
		event := events.NewEvent(events.TopicLoginSuccess, events.CodeOK)
		event.ActorID = identifier
		if fi, ok := ident.(FlowIdentity); ok {
			event.SubjectID = fi.GetID()
		}
		// #nosec G104 -- domain events are best-effort and cannot change auth outcome.
		dispatcher.Dispatch(ctx, event)
	}

	return ident, nil
}

// LinkMethod links a new authentication method to an existing authenticated identity.
func (m *LoginManager) LinkMethod(ctx context.Context, ident any, method, identifier, secret string) error {
	m.mu.RLock()
	strategy, ok := m.strategies[method]
	m.mu.RUnlock()

	if !ok {
		return fmt.Errorf("login: unknown method %q", method)
	}

	attacher, ok := strategy.(Attacher)
	if !ok {
		return fmt.Errorf("login: method %q does not support linking to existing account", method)
	}

	// 1. Audit link attempt
	if m.auditSink != nil {
		m.auditSink.save(ctx, &audit.AuditEvent{
			Type:    "identity.link.initiate",
			ActorID: identifier,
			Status:  "success",
			Message: fmt.Sprintf("Initiated linking for %s", method),
		})
	}

	// 2. Perform linking
	if err := attacher.Attach(ctx, ident, identifier, secret); err != nil {
		if m.auditSink != nil {
			m.auditSink.save(ctx, &audit.AuditEvent{
				Type:    string(events.TopicIdentityFailure),
				ActorID: identifier,
				Status:  "failure",
				Message: err.Error(),
			})
		}
		return err
	}

	if m.auditSink != nil {
		m.auditSink.save(ctx, &audit.AuditEvent{
			Type:    string(events.TopicIdentityCreated),
			ActorID: identifier,
			Status:  "success",
			Message: fmt.Sprintf("Successfully linked %s", method),
		})
	}

	return nil
}
