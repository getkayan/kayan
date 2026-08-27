package telemetry

import (
	"context"
	"encoding/json"

	"github.com/getkayan/kayan/core/events"
)

// Subscribe wires a Provider's metrics to the domain events core/flow already
// emits, so a deployment gets login, MFA, session, and throttling metrics
// without any Kayan package importing this one.
//
//	provider, err := telemetry.NewProvider(cfg)
//	dispatcher := events.NewDispatcher()
//	telemetry.Subscribe(dispatcher, provider)
//	login := flow.NewLoginManager(repo, factory, flow.WithLoginDispatcher(dispatcher))
//
// The direction matters. Importing telemetry into core/flow would put the
// OpenTelemetry SDK back into every consumer's build for a feature most of them
// do not use, which is what moving this module out of core was for. The event
// dispatcher is the seam that already exists for exactly this, and it costs
// core nothing.
//
// A nil provider or dispatcher is a no-op rather than a panic: a caller that
// builds its telemetry conditionally should not have to guard every call.
func Subscribe(dispatcher events.Dispatcher, provider *Provider) {
	if dispatcher == nil || provider == nil {
		return
	}

	dispatcher.Subscribe(events.TopicLoginSuccess, func(ctx context.Context, e events.Event) error {
		provider.RecordLogin(ctx, strategyOf(e), true, e.TenantID)
		return nil
	})
	dispatcher.Subscribe(events.TopicLoginFailure, func(ctx context.Context, e events.Event) error {
		provider.RecordLogin(ctx, strategyOf(e), false, e.TenantID)
		return nil
	})

	// A blocked login is a lockout taking effect, not an ordinary failure.
	// Recording it as a failure would leave an operator unable to tell a wave
	// of wrong passwords from a wave of already-locked accounts.
	dispatcher.Subscribe(events.TopicLoginBlocked, func(ctx context.Context, e events.Event) error {
		provider.RecordLockout(ctx, strategyOf(e))
		return nil
	})
	dispatcher.Subscribe(events.TopicSecurityRateLimited, func(ctx context.Context, e events.Event) error {
		// The rate-limit key is deliberately not passed through as a label.
		// Limiters count whatever identifier the request supplied, which on an
		// unauthenticated endpoint is attacker-controlled -- one metric series
		// per guessed username is a cardinality explosion in the backend, and
		// it puts identifiers into a metrics pipeline that is rarely treated
		// as holding personal data. The strategy is enough to alert on.
		provider.RecordRateLimit(ctx, strategyOf(e), "")
		return nil
	})

	dispatcher.Subscribe(events.TopicLoginMFARequired, func(ctx context.Context, e events.Event) error {
		// The challenge was issued; whether it is answered correctly is a
		// separate event, so this is not yet a success or a failure.
		provider.RecordMFA(ctx, strategyOf(e), false)
		return nil
	})

	dispatcher.Subscribe(events.TopicIdentityCreated, func(ctx context.Context, e events.Event) error {
		provider.RecordRegistration(ctx, strategyOf(e), true, e.TenantID)
		return nil
	})
	dispatcher.Subscribe(events.TopicIdentityFailure, func(ctx context.Context, e events.Event) error {
		provider.RecordRegistration(ctx, strategyOf(e), false, e.TenantID)
		return nil
	})

	dispatcher.Subscribe(events.TopicSessionCreated, func(ctx context.Context, e events.Event) error {
		provider.SessionCreated(ctx, e.TenantID)
		return nil
	})
	for _, topic := range []events.Topic{events.TopicSessionRevoked, events.TopicSessionExpired, events.TopicLogout} {
		dispatcher.Subscribe(topic, func(ctx context.Context, e events.Event) error {
			provider.SessionDestroyed(ctx, e.TenantID)
			return nil
		})
	}
}

// strategyOf reads the authentication strategy from an event's metadata,
// falling back to the topic so a metric is never emitted with an empty label.
func strategyOf(e events.Event) string {
	if len(e.Metadata) > 0 {
		var meta map[string]any
		if err := json.Unmarshal(e.Metadata, &meta); err == nil {
			for _, key := range []string{"strategy", "method", "type"} {
				if value, ok := meta[key].(string); ok && value != "" {
					return value
				}
			}
		}
	}
	return string(e.Topic)
}
