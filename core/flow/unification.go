package flow

import (
	"context"
	"encoding/json"
	"errors"

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
	repo    IdentityRepository
	factory func() any
}

func NewDefaultLinker(repo IdentityRepository, factory func() any) Linker {
	return &defaultLinker{
		repo:    repo,
		factory: factory,
	}
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
	return l.repo.FindIdentity(l.factory, map[string]any{"email": email})
}

func (l *defaultLinker) Link(ctx context.Context, ident any, method string, identifier, secret string) error {
	// 1. Get the strategy
	// This linkage happens inside the strategy implementations usually, 
	// but can be orchestrated here if strategies expose an "Attach" method.
	return errors.New("unification: linker.Link not fully implemented yet - strategies need Attach support")
}
