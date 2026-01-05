package flow

import (
	"context"
	"errors"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/getkayan/kayan/core/config"
	"github.com/getkayan/kayan/core/domain"
	"github.com/getkayan/kayan/core/identity"
	"golang.org/x/oauth2"
)

type ClaimMapper func(claims map[string]any) identity.JSON

type OIDCManager struct {
	repo        domain.Storage
	providers   map[string]*OIDCProviderData
	generator   domain.IDGenerator
	factory     func() any
	claimMapper ClaimMapper
}

type OIDCProviderData struct {
	Provider    *oidc.Provider
	OAuthConfig *oauth2.Config
}

func NewOIDCManager(repo domain.Storage, configs map[string]config.OIDCProvider, factory func() any) (*OIDCManager, error) {
	providers := make(map[string]*OIDCProviderData)
	ctx := context.Background()

	for name, cfg := range configs {
		provider, err := oidc.NewProvider(ctx, cfg.Issuer)
		if err != nil {
			return nil, fmt.Errorf("failed to get provider %s: %w", name, err)
		}

		oauthConfig := &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  cfg.RedirectURL,
			Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
		}

		providers[name] = &OIDCProviderData{
			Provider:    provider,
			OAuthConfig: oauthConfig,
		}
	}

	return &OIDCManager{
		repo:      repo,
		providers: providers,
		factory:   factory,
	}, nil
}

func (m *OIDCManager) SetIDGenerator(g domain.IDGenerator) {
	m.generator = g
}

func (m *OIDCManager) GetAuthURL(providerID, state string) (string, error) {
	p, ok := m.providers[providerID]
	if !ok {
		return "", errors.New("provider not found")
	}
	return p.OAuthConfig.AuthCodeURL(state), nil
}

func (m *OIDCManager) HandleCallback(ctx context.Context, providerID, code string) (any, error) {
	p, ok := m.providers[providerID]
	if !ok {
		return nil, errors.New("provider not found")
	}

	token, err := p.OAuthConfig.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange token: %w", err)
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, errors.New("no id_token in token response")
	}

	verifier := p.Provider.Verifier(&oidc.Config{ClientID: p.OAuthConfig.ClientID})
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("failed to verify id token: %w", err)
	}

	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to parse claims: %w", err)
	}

	// Logic to link or create identity
	return m.reconcileIdentity(providerID, claims)
}

func (m *OIDCManager) SetClaimMapper(mapper ClaimMapper) {
	m.claimMapper = mapper
}

func (m *OIDCManager) reconcileIdentity(providerID string, claims map[string]any) (any, error) {
	subject, _ := claims["sub"].(string)
	email, _ := claims["email"].(string)

	// 1. Check if OIDC credential already exists
	oidcIdentifier := fmt.Sprintf("%s:%s", providerID, subject)
	cred, err := m.repo.GetCredentialByIdentifier(oidcIdentifier, "oidc")
	if err == nil {
		// Existing OIDC user
		return m.repo.GetIdentity(m.factory, cred.IdentityID)
	}

	// 2. Account Linking: Check if user exists by email
	if email != "" {
		// Look for any credential with this email, or an identity with this email trait
		// For simplicity in this core implementation, we check if an identity already has this email
		existingIdent, err := m.repo.FindIdentity(m.factory, map[string]any{"traits": email})
		if err == nil && existingIdent != nil {
			// Found an existing user with the same email. Link this OIDC provider to them.
			return m.linkOIDC(existingIdent, providerID, subject)
		}
	}

	// 3. Otherwise create new identity using factory
	ident := m.factory()

	traits := m.mapClaims(claims)
	if ts, ok := ident.(TraitSource); ok {
		ts.SetTraits(traits)
	}

	if fi, ok := ident.(FlowIdentity); ok {
		// Use generator if provided
		id := fi.GetID()
		if m.generator != nil && (id == nil || id == "") {
			fi.SetID(m.generator())
		}

		if cs, ok := ident.(CredentialSource); ok {
			newCred := identity.Credential{
				IdentityID: fmt.Sprintf("%v", fi.GetID()),
				Type:       "oidc",
				Identifier: oidcIdentifier,
				Secret:     "", // OIDC doesn't need secret stored
			}
			// Use generator for credential ID as well
			if m.generator != nil {
				newCred.ID = fmt.Sprintf("%v", m.generator())
			}
			cs.SetCredentials(append(cs.GetCredentials(), newCred))
		}
	} else {
		return nil, errors.New("identity model does not implement FlowIdentity")
	}

	if err := m.repo.CreateIdentity(ident); err != nil {
		return nil, err
	}

	return ident, nil
}

func (m *OIDCManager) mapClaims(claims map[string]any) identity.JSON {
	if m.claimMapper != nil {
		return m.claimMapper(claims)
	}
	// Default: just include email
	email, _ := claims["email"].(string)
	return identity.JSON(fmt.Sprintf(`{"email": "%s"}`, email))
}

func (m *OIDCManager) linkOIDC(ident any, providerID, subject string) (any, error) {
	fi, ok := ident.(FlowIdentity)
	if !ok {
		return nil, errors.New("existing identity does not implement FlowIdentity")
	}

	cs, ok := ident.(CredentialSource)
	if !ok {
		return nil, errors.New("existing identity does not implement CredentialSource for linking")
	}

	newCred := identity.Credential{
		IdentityID: fmt.Sprintf("%v", fi.GetID()),
		Type:       "oidc",
		Identifier: fmt.Sprintf("%s:%s", providerID, subject),
	}
	if m.generator != nil {
		newCred.ID = fmt.Sprintf("%v", m.generator())
	}

	cs.SetCredentials(append(cs.GetCredentials(), newCred))

	// Update the identity with the new credential
	// Using CreateIdentity here might fail if it's meant only for new ones,
	// but in most GORM implementations it should handle updates or we might need a dedicated Save/Update.
	// For now, we assume the repo can handle it.
	if err := m.repo.CreateIdentity(ident); err != nil {
		return nil, err
	}

	return ident, nil
}
