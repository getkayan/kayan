package flow

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/getkayan/kayan/core/identity"
)

// Linker handles account linking and identity unification.
type Linker interface {
	// FindExisting searches for an identity that matches the provided traits.
	// Typically checks for verified emails or phone numbers.
	FindExisting(ctx context.Context, traits identity.JSON) (any, error)

	// Link attaches a new authentication method to an existing identity.
	Link(ctx context.Context, ident any, method string, identifier, secret string) error
}

type defaultLinker struct {
	repo       IdentityRepository
	factory    func() any
	strategies map[string]LoginStrategy
}

// NewDefaultLinker creates a linker for account unification.
// An optional strategies map can be passed to enable Link() method support.
func NewDefaultLinker(repo IdentityRepository, factory func() any, strategies ...map[string]LoginStrategy) Linker {
	l := &defaultLinker{
		repo:       repo,
		factory:    factory,
		strategies: make(map[string]LoginStrategy),
	}
	if len(strategies) > 0 && strategies[0] != nil {
		l.strategies = strategies[0]
	}
	return l
}

func (l *defaultLinker) FindExisting(ctx context.Context, traits identity.JSON) (any, error) {
	var traitsMap map[string]any
	if err := json.Unmarshal(traits, &traitsMap); err != nil {
		return nil, nil
	}

	// Look for standard high-confidence markers like "email" and "email_verified"
	// This relies on the convention that OIDC factors return these.
	email, ok := traitsMap["email"].(string)
	if !ok || email == "" {
		return nil, nil
	}

	verified, _ := traitsMap["email_verified"].(bool)
	if !verified {
		// We only auto-link verified emails to prevent account hijacking
		return nil, nil
	}

	// Search in the repo.
	// NOTE: This assumes the repo knows how to search by traits/email.
	// For BYOS models, the Repo might need a custom FindIdentity implementation.
	ident, err := l.repo.FindIdentity(l.factory, map[string]any{"email": email})
	if err == nil && ident != nil {
		return ident, nil
	}

	idents, listErr := l.repo.ListIdentities(l.factory, 0, 0)
	if listErr != nil {
		return nil, listErr
	}

	for _, ident := range idents {
		if emailMatchesIdentity(ident, email) {
			return ident, nil
		}
	}

	return nil, nil
}

func (l *defaultLinker) Link(ctx context.Context, ident any, method string, identifier, secret string) error {
	strategy, ok := l.strategies[method]
	if !ok {
		return fmt.Errorf("unification: unknown method %q for linking", method)
	}

	attacher, ok := strategy.(Attacher)
	if !ok {
		return fmt.Errorf("unification: method %q does not support Attach", method)
	}

	return attacher.Attach(ctx, ident, identifier, secret)
}

func emailMatchesIdentity(ident any, email string) bool {
	if ts, ok := ident.(TraitSource); ok {
		var traits map[string]any
		if err := json.Unmarshal(ts.GetTraits(), &traits); err == nil {
			if traitEmail, ok := traits["email"].(string); ok {
				return traitEmail == email
			}
		}
	}

	v := reflect.ValueOf(ident)
	if !v.IsValid() {
		return false
	}
	if v.Kind() == reflect.Ptr {
		if v.IsNil() {
			return false
		}
		v = v.Elem()
	}

	field := v.FieldByName("Email")
	return field.IsValid() && field.Kind() == reflect.String && fmt.Sprintf("%v", field.Interface()) == email
}
