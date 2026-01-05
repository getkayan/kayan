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

type OIDCManager struct {
	repo      domain.Storage
	providers map[string]*OIDCProviderData
	generator domain.IDGenerator
	factory   func() any
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

	var claims struct {
		Subject string `json:"sub"`
		Email   string `json:"email"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to parse claims: %w", err)
	}

	// Logic to link or create identity
	return m.reconcileIdentity(providerID, claims.Subject, claims.Email)
}

func (m *OIDCManager) reconcileIdentity(providerID, subject, email string) (any, error) {
	// 1. Check if credential already exists
	identifier := fmt.Sprintf("%s:%s", providerID, subject)
	cred, err := m.repo.GetCredentialByIdentifier(identifier, "oidc")
	if err == nil {
		// Existing user
		return m.repo.GetIdentity(m.factory, cred.IdentityID)
	}

	// 2. Otherwise create new identity using factory
	ident := m.factory()

	if ts, ok := ident.(TraitSource); ok {
		ts.SetTraits(identity.JSON(fmt.Sprintf(`{"email": "%s"}`, email)))
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
				Identifier: identifier,
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
