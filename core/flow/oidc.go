package flow

import (
	"context"
	"encoding/json"
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
	repo        IdentityRepository
	providers   map[string]*OIDCProviderData
	generator   domain.IDGenerator
	factory     func() any
	claimMapper ClaimMapper
	linker      Linker
}

type OIDCProviderData struct {
	Provider    *oidc.Provider
	OAuthConfig *oauth2.Config
}

func NewOIDCManager(repo IdentityRepository, configs map[string]config.OIDCProvider, factory func() any) (*OIDCManager, error) {
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

func (m *OIDCManager) SetLinker(l Linker) {
	m.linker = l
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
	return m.reconcileIdentity(ctx, providerID, claims)
}

func (m *OIDCManager) SetClaimMapper(mapper ClaimMapper) {
	m.claimMapper = mapper
}

func (m *OIDCManager) reconcileIdentity(ctx context.Context, providerID string, claims map[string]any) (any, error) {
	subject, _ := claims["sub"].(string)
	email, _ := claims["email"].(string)

	// 1. Check if OIDC credential already exists
	oidcIdentifier := fmt.Sprintf("%s:%s", providerID, subject)
	cred, err := m.repo.GetCredentialByIdentifier(ctx, oidcIdentifier, "oidc")
	if err == nil && cred != nil {
		// Existing OIDC user
		return m.repo.GetIdentity(ctx, m.factory, cred.IdentityID)
	}

	// 2. Account linking by email address.
	//
	// The address alone is not evidence. Linking on a bare email claim means
	// any provider that lets a user assert an arbitrary address -- public
	// self-registration, a permissive directory -- can mint a login as any
	// local account holding it, with no credential and no interaction with the
	// owner. Only a provider that vouches for the address may link.
	//
	// The claim must be a true boolean. A provider that sends the string
	// "false", or omits it, is not vouching for anything.
	verified, _ := claims["email_verified"].(bool)
	if email != "" && verified {
		if m.linker != nil {
			traits := m.mapClaims(claims)
			existingIdent, err := m.linker.FindExisting(ctx, traits)
			if err == nil && existingIdent != nil {
				return m.linkOIDC(ctx, existingIdent, providerID, subject)
			}
		} else {
			// Fallback to legacy email lookup if no linker is set
			existingIdent, err := m.repo.FindIdentity(ctx, m.factory, map[string]any{"email": email})
			if err == nil && existingIdent != nil {
				return m.linkOIDC(ctx, existingIdent, providerID, subject)
			}
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

	if err := m.repo.CreateIdentity(ctx, ident); err != nil {
		return nil, err
	}

	return ident, nil
}

func (m *OIDCManager) mapClaims(claims map[string]any) identity.JSON {
	if m.claimMapper != nil {
		return m.claimMapper(claims)
	}
	// Default: just include email.
	//
	// Built with the JSON encoder rather than string formatting. An address is
	// attacker-influenced data from a federated provider, and one containing a
	// quote would otherwise close the string and inject sibling keys into the
	// traits document -- letting the claim set fields the mapper never
	// intended to expose.
	email, _ := claims["email"].(string)
	encoded, err := json.Marshal(map[string]string{"email": email})
	if err != nil {
		// A map[string]string cannot fail to marshal; fall back to an empty
		// document rather than to a hand-built one.
		return identity.JSON(`{}`)
	}
	return identity.JSON(encoded)
}

func (m *OIDCManager) linkOIDC(ctx context.Context, ident any, providerID, subject string) (any, error) {
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

	if err := m.repo.UpdateIdentity(ctx, ident); err != nil {
		return nil, err
	}

	return ident, nil
}

// Attach implements the Attacher interface for OIDC.
// identifier = subject, secret = providerID
func (m *OIDCManager) Attach(ctx context.Context, ident any, identifier, secret string) error {
	_, err := m.linkOIDC(ctx, ident, secret, identifier)
	return err
}
