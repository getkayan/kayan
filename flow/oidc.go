package flow

import (
	"context"
	"errors"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/getkayan/kayan/config"
	"github.com/getkayan/kayan/domain"
	"github.com/getkayan/kayan/identity"
	"golang.org/x/oauth2"
)

type OIDCManager[T any] struct {
	repo      domain.Storage[T]
	providers map[string]*OIDCProviderData
	generator domain.IDGenerator[T]
}

type OIDCProviderData struct {
	Provider    *oidc.Provider
	OAuthConfig *oauth2.Config
}

func NewOIDCManager[T any](repo domain.Storage[T], configs map[string]config.OIDCProvider) (*OIDCManager[T], error) {
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

	return &OIDCManager[T]{
		repo:      repo,
		providers: providers,
	}, nil
}

func (m *OIDCManager[T]) SetIDGenerator(g domain.IDGenerator[T]) {
	m.generator = g
}

func (m *OIDCManager[T]) GetAuthURL(providerID, state string) (string, error) {
	p, ok := m.providers[providerID]
	if !ok {
		return "", errors.New("provider not found")
	}
	return p.OAuthConfig.AuthCodeURL(state), nil
}

func (m *OIDCManager[T]) HandleCallback(ctx context.Context, providerID, code string) (*identity.Identity[T], error) {
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

func (m *OIDCManager[T]) reconcileIdentity(providerID, subject, email string) (*identity.Identity[T], error) {
	// 1. Check if credential already exists
	identifier := fmt.Sprintf("%s:%s", providerID, subject)
	cred, err := m.repo.GetCredentialByIdentifier(identifier, "oidc")
	if err == nil {
		// Existing user
		return m.repo.GetIdentity(cred.IdentityID)
	}

	// 2. Otherwise create new identity
	newIdentity := &identity.Identity[T]{
		Traits: identity.JSON(fmt.Sprintf(`{"email": "%s"}`, email)),
	}

	// Use generator if provided
	if m.generator != nil {
		newIdentity.ID = m.generator()
	}

	newCred := identity.Credential[T]{
		IdentityID: newIdentity.ID,
		Type:       "oidc",
		Identifier: identifier,
		Secret:     "", // OIDC doesn't need secret stored
	}
	// Use generator for credential ID as well
	if m.generator != nil {
		newCred.ID = m.generator()
	}
	newIdentity.Credentials = append(newIdentity.Credentials, newCred)

	if err := m.repo.CreateIdentity(newIdentity); err != nil {
		return nil, err
	}

	return newIdentity, nil
}
