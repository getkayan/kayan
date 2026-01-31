package consent

import (
	"context"
	"fmt"
	"net/http"
)

// ---- Middleware ----

// MiddlewareConfig configures consent checking middleware.
type MiddlewareConfig struct {
	// Manager is the consent manager to use.
	Manager *Manager

	// IdentityExtractor extracts the identity ID from the request context.
	IdentityExtractor func(ctx context.Context) (string, error)

	// Purpose is the consent purpose to check.
	Purpose Purpose

	// OnMissing is called when consent is missing.
	// Return nil to allow the request, or an error to block.
	OnMissing func(ctx context.Context, identityID string, purpose Purpose) error

	// Optional: Skip checks for certain conditions.
	Skip func(ctx context.Context, r *http.Request) bool
}

// RequireConsent returns HTTP middleware that blocks requests without consent.
func RequireConsent(cfg MiddlewareConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			// Check skip condition
			if cfg.Skip != nil && cfg.Skip(ctx, r) {
				next.ServeHTTP(w, r)
				return
			}

			// Extract identity
			identityID, err := cfg.IdentityExtractor(ctx)
			if err != nil {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			// Check consent
			granted, err := cfg.Manager.Check(ctx, identityID, cfg.Purpose)
			if err != nil {
				http.Error(w, "consent check failed", http.StatusInternalServerError)
				return
			}

			if !granted {
				if cfg.OnMissing != nil {
					if err := cfg.OnMissing(ctx, identityID, cfg.Purpose); err != nil {
						http.Error(w, err.Error(), http.StatusForbidden)
						return
					}
				} else {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusForbidden)
					w.Write([]byte(fmt.Sprintf(`{"error":"consent_required","purpose":"%s"}`, cfg.Purpose)))
					return
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

// ---- Context Helpers ----

type consentContextKey struct{}

// WithConsents adds consent data to context.
func WithConsents(ctx context.Context, consents map[Purpose]bool) context.Context {
	return context.WithValue(ctx, consentContextKey{}, consents)
}

// ConsentsFromContext retrieves consents from context.
func ConsentsFromContext(ctx context.Context) map[Purpose]bool {
	if c, ok := ctx.Value(consentContextKey{}).(map[Purpose]bool); ok {
		return c
	}
	return nil
}

// HasConsent checks if a purpose is consented in context.
func HasConsent(ctx context.Context, purpose Purpose) bool {
	consents := ConsentsFromContext(ctx)
	if consents == nil {
		return false
	}
	return consents[purpose]
}

// ---- Preload Middleware ----

// PreloadConfig configures consent preloading middleware.
type PreloadConfig struct {
	Manager           *Manager
	IdentityExtractor func(ctx context.Context) (string, error)
	Purposes          []Purpose // Purposes to preload (nil = all)
}

// PreloadConsents middleware loads consent data into context for downstream use.
func PreloadConsents(cfg PreloadConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			identityID, err := cfg.IdentityExtractor(ctx)
			if err != nil {
				// No identity, continue without consents
				next.ServeHTTP(w, r)
				return
			}

			consents := make(map[Purpose]bool)

			if len(cfg.Purposes) > 0 {
				// Check specific purposes
				for _, purpose := range cfg.Purposes {
					granted, _ := cfg.Manager.Check(ctx, identityID, purpose)
					consents[purpose] = granted
				}
			} else {
				// Load all consents
				all, err := cfg.Manager.GetAll(ctx, identityID)
				if err == nil {
					for _, c := range all {
						consents[c.Purpose] = c.Granted
					}
				}
			}

			ctx = WithConsents(ctx, consents)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// ---- Decorator Pattern for Functions ----

// RequireConsentFunc wraps a function to check consent before execution.
func RequireConsentFunc[T any](
	manager *Manager,
	purpose Purpose,
	fn func(ctx context.Context, identityID string) (T, error),
) func(ctx context.Context, identityID string) (T, error) {
	return func(ctx context.Context, identityID string) (T, error) {
		var zero T

		granted, err := manager.Check(ctx, identityID, purpose)
		if err != nil {
			return zero, err
		}
		if !granted {
			return zero, fmt.Errorf("consent required for purpose: %s", purpose)
		}

		return fn(ctx, identityID)
	}
}
