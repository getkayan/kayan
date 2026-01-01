package flow

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"

	"github.com/getkayan/kayan/domain"
	"github.com/getkayan/kayan/identity"
)

type PasswordStrategy struct {
	repo             IdentityRepository
	hasher           domain.Hasher
	identifierFields []string
	passwordField    string
	generator        domain.IDGenerator
	factory          func() any
}

func NewPasswordStrategy(repo IdentityRepository, hasher domain.Hasher, identifierField string, factory func() any) *PasswordStrategy {
	s := &PasswordStrategy{
		repo:    repo,
		hasher:  hasher,
		factory: factory,
	}
	if identifierField != "" {
		s.identifierFields = []string{identifierField}
	}
	return s
}

func (s *PasswordStrategy) MapFields(identifiers []string, password string) {
	s.identifierFields = identifiers
	s.passwordField = password
}

func (s *PasswordStrategy) SetIDGenerator(g domain.IDGenerator) {
	s.generator = g
}

func (s *PasswordStrategy) ID() string { return "password" }

func (s *PasswordStrategy) Register(ctx context.Context, traits identity.JSON, password string) (any, error) {
	if len(traits) == 0 {
		return nil, errors.New("traits are required")
	}

	ident := s.factory()

	hashed, err := s.hasher.Hash(password)
	if err != nil {
		return nil, err
	}

	// Case 1: BYOS with field mapping
	if s.passwordField != "" {
		if err := s.setField(ident, s.passwordField, hashed); err != nil {
			return nil, fmt.Errorf("failed to set password field: %w", err)
		}

		var traitsMap map[string]any
		if err := json.Unmarshal(traits, &traitsMap); err != nil {
			return nil, fmt.Errorf("failed to unmarshal traits: %w", err)
		}

		for _, field := range s.identifierFields {
			if val, ok := traitsMap[field]; ok {
				if err := s.setField(ident, field, val); err != nil {
					return nil, fmt.Errorf("failed to set identifier field %q: %w", field, err)
				}
			}
		}
	}

	// Always handle ID if generator exists and ID methods are available
	if fi, ok := ident.(FlowIdentity); ok {
		id := fi.GetID()
		if s.generator != nil && (id == nil || id == "") {
			fi.SetID(s.generator())
		}
	}

	// Case 2: Classic Kayan with separate Credentials table (if no passwordField mapping)
	if s.passwordField == "" {
		if ts, ok := ident.(TraitSource); ok {
			ts.SetTraits(traits)
		}

		if cs, ok := ident.(CredentialSource); ok {
			var identifier string
			if len(s.identifierFields) > 0 {
				var traitsMap map[string]any
				json.Unmarshal(traits, &traitsMap)
				identifier = fmt.Sprintf("%v", traitsMap[s.identifierFields[0]])
			} else {
				identifier = string(traits)
			}

			fi, _ := ident.(FlowIdentity)
			cred := identity.Credential{
				IdentityID: fmt.Sprintf("%v", fi.GetID()),
				Type:       "password",
				Identifier: identifier,
				Secret:     hashed,
			}
			if s.generator != nil {
				cred.ID = fmt.Sprintf("%v", s.generator())
			}
			cs.SetCredentials(append(cs.GetCredentials(), cred))
		}
	}

	if err := s.repo.CreateIdentity(ident); err != nil {
		return nil, err
	}

	return ident, nil
}

func (s *PasswordStrategy) Authenticate(ctx context.Context, identifier, password string) (any, error) {
	// Case 1: BYOS (Direct Query)
	if s.passwordField != "" {
		for _, field := range s.identifierFields {
			query := map[string]any{field: identifier}
			ident, err := s.repo.FindIdentity(s.factory, query)
			if err == nil && ident != nil {
				// Check password
				hash := s.getField(ident, s.passwordField)
				if s.hasher.Compare(password, fmt.Sprintf("%v", hash)) {
					return ident, nil
				}
			}
		}
		return nil, errors.New("invalid identifier or password")
	}

	// Case 2: Classic
	cred, err := s.repo.GetCredentialByIdentifier(identifier, "password")
	if err != nil || cred == nil {
		return nil, errors.New("invalid identifier or password")
	}

	if !s.hasher.Compare(password, cred.Secret) {
		return nil, errors.New("invalid identifier or password")
	}

	return s.repo.GetIdentity(s.factory, cred.IdentityID)
}

func (s *PasswordStrategy) setField(obj any, field string, value any) error {
	v := reflect.ValueOf(obj)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	f := v.FieldByName(field)
	if !f.IsValid() {
		return fmt.Errorf("field %s not found", field)
	}
	if !f.CanSet() {
		return fmt.Errorf("field %s cannot be set", field)
	}
	f.Set(reflect.ValueOf(value))
	return nil
}

func (s *PasswordStrategy) getField(obj any, field string) any {
	v := reflect.ValueOf(obj)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	f := v.FieldByName(field)
	if !f.IsValid() {
		return nil
	}
	return f.Interface()
}
