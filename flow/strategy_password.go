package flow

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/getkayan/kayan/domain"
	"github.com/getkayan/kayan/identity"
)

type PasswordStrategy[T any] struct {
	repo            IdentityRepository[T]
	hasher          domain.Hasher
	identifierField string
	generator       domain.IDGenerator[T]
}

func NewPasswordStrategy[T any](repo IdentityRepository[T], hasher domain.Hasher, identifierField string) *PasswordStrategy[T] {
	return &PasswordStrategy[T]{
		repo:            repo,
		hasher:          hasher,
		identifierField: identifierField,
	}
}

func (s *PasswordStrategy[T]) SetIDGenerator(g domain.IDGenerator[T]) {
	s.generator = g
}

func (s *PasswordStrategy[T]) ID() string { return "password" }

func (s *PasswordStrategy[T]) Register(ctx context.Context, traits identity.JSON, password string) (*identity.Identity[T], error) {
	if len(traits) == 0 {
		return nil, errors.New("traits are required")
	}

	newIdentity := &identity.Identity[T]{
		Traits: traits,
	}

	// Use generator if provided
	if s.generator != nil {
		newIdentity.ID = s.generator()
	}

	hashed, err := s.hasher.Hash(password)
	if err != nil {
		return nil, err
	}

	var identifier string
	if s.identifierField != "" {
		var traitsMap map[string]interface{}
		if err := json.Unmarshal(traits, &traitsMap); err != nil {
			return nil, fmt.Errorf("failed to unmarshal traits: %w", err)
		}
		val, ok := traitsMap[s.identifierField]
		if !ok {
			return nil, fmt.Errorf("identifier field %q not found in traits", s.identifierField)
		}
		identifier = fmt.Sprintf("%v", val)
	} else {
		identifier = string(traits)
	}

	cred := identity.Credential[T]{
		IdentityID: newIdentity.ID,
		Type:       "password",
		Identifier: identifier,
		Secret:     hashed,
	}
	// Use generator for credential ID as well if needed
	if s.generator != nil {
		cred.ID = s.generator()
	}
	newIdentity.Credentials = append(newIdentity.Credentials, cred)

	if err := s.repo.CreateIdentity(newIdentity); err != nil {
		return nil, err
	}

	return newIdentity, nil
}

func (s *PasswordStrategy[T]) Authenticate(ctx context.Context, identifier, password string) (*identity.Identity[T], error) {
	cred, err := s.repo.GetCredentialByIdentifier(identifier, "password")
	if err != nil || cred == nil {
		return nil, errors.New("invalid identifier or password")
	}

	if !s.hasher.Compare(password, cred.Secret) {
		return nil, errors.New("invalid identifier or password")
	}

	return s.repo.GetIdentity(fmt.Sprintf("%v", cred.IdentityID))
}
