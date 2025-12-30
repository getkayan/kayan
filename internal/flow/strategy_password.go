package flow

import (
	"context"
	"errors"

	"github.com/getkayan/kayan/internal/domain"
	"github.com/getkayan/kayan/internal/identity"
	"github.com/google/uuid"
)

type PasswordStrategy struct {
	repo   IdentityRepository
	hasher domain.Hasher
}

func NewPasswordStrategy(repo IdentityRepository, hasher domain.Hasher) *PasswordStrategy {
	return &PasswordStrategy{
		repo:   repo,
		hasher: hasher,
	}
}

func (s *PasswordStrategy) ID() string { return "password" }

func (s *PasswordStrategy) Register(ctx context.Context, traits identity.JSON, password string) (*identity.Identity, error) {
	if len(traits) == 0 {
		return nil, errors.New("traits are required")
	}

	newIdentity := &identity.Identity{
		ID:     uuid.New(),
		Traits: traits,
	}

	hashed, err := s.hasher.Hash(password)
	if err != nil {
		return nil, err
	}

	cred := identity.Credential{
		ID:         uuid.New(),
		IdentityID: newIdentity.ID,
		Type:       "password",
		Identifier: string(traits),
		Secret:     hashed,
	}
	newIdentity.Credentials = append(newIdentity.Credentials, cred)

	if err := s.repo.CreateIdentity(newIdentity); err != nil {
		return nil, err
	}

	return newIdentity, nil
}

func (s *PasswordStrategy) Authenticate(ctx context.Context, identifier, password string) (*identity.Identity, error) {
	cred, err := s.repo.GetCredentialByIdentifier(identifier, "password")
	if err != nil || cred == nil {
		return nil, errors.New("invalid identifier or password")
	}

	if !s.hasher.Compare(password, cred.Secret) {
		return nil, errors.New("invalid identifier or password")
	}

	return &identity.Identity{ID: cred.IdentityID}, nil
}
