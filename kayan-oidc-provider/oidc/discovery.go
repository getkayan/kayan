package oidc

import (
	"context"
	"fmt"
	"slices"

	"github.com/getkayan/kayan/kayan-oidc-provider/oauth2"
)

// Endpoints locates the routes a deployment serves.
//
// Kayan does not choose URLs — it has no router. Supply the paths your service
// actually exposes; anything left empty is omitted from the document rather
// than guessed.
type Endpoints struct {
	Authorization string
	Token         string
	UserInfo      string
	JWKS          string
	Introspection string
	Revocation    string
	EndSession    string
}

// DiscoveryOptions describes what a deployment supports.
//
// Anything left unset is derived from the provider's actual configuration.
type DiscoveryOptions struct {
	Endpoints Endpoints

	// Scopes advertised. Defaults to openid, profile, email.
	Scopes []string

	// Claims advertised. Defaults to the claims the ID token always carries.
	Claims []string

	// GrantTypes advertised. Defaults to the grants the provider implements.
	GrantTypes []string
}

// BuildDiscovery assembles the OpenID Provider metadata document.
//
// The result is derived from configuration rather than written out by hand.
// The previous hardcoded document advertised the "id_token" response type
// although no implicit flow exists, and "RS256" regardless of the key in use.
// Advertising a capability that is not implemented is an interoperability bug
// that surfaces inside the relying party, where it is hard to diagnose.
//
// The caller serves the result:
//
//	doc, err := server.BuildDiscovery(ctx, opts)
//	json.NewEncoder(w).Encode(doc)
func (s *Server) BuildDiscovery(ctx context.Context, opts DiscoveryOptions) (Discovery, error) {
	// RP-initiated logout validates post_logout_redirect_uri against the
	// requesting client's allowlist, so without a client store the endpoint
	// refuses every request that carries one. Advertising it anyway is the
	// interoperability bug this function exists to prevent, in the direction
	// that matters most: a relying party that trusts the metadata builds a
	// logout flow the provider cannot complete.
	if opts.Endpoints.EndSession != "" && s.clients == nil {
		return Discovery{}, fmt.Errorf("oidc: an end-session endpoint is configured but no client "+
			"store is: RP-initiated logout cannot validate a redirect target, so the endpoint "+
			"must not be advertised (supply %s)", "WithClientStore")
	}

	doc := Discovery{
		Issuer:                s.issuer,
		AuthorizationEndpoint: opts.Endpoints.Authorization,
		TokenEndpoint:         opts.Endpoints.Token,
		UserinfoEndpoint:      opts.Endpoints.UserInfo,
		JwksURI:               opts.Endpoints.JWKS,
		IntrospectionEndpoint: opts.Endpoints.Introspection,
		RevocationEndpoint:    opts.Endpoints.Revocation,
		EndSessionEndpoint:    opts.Endpoints.EndSession,

		// Only the authorization code flow is implemented.
		ResponseTypesSupported: []string{oauth2.ResponseTypeCode},
		SubjectTypesSupported:  []string{"public"},

		ScopesSupported: defaultTo(opts.Scopes, []string{"openid", "profile", "email"}),
		ClaimsSupported: defaultTo(opts.Claims, []string{"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce"}),
		GrantTypesSupported: defaultTo(opts.GrantTypes, []string{
			oauth2.GrantAuthorizationCode,
			oauth2.GrantRefreshToken,
			oauth2.GrantClientCredentials,
		}),

		TokenEndpointAuthMethodsSupported: s.tokenEndpointAuthMethods(),
	}

	// Advertise the algorithms the configured keys actually sign with.
	algorithms, err := s.signingAlgorithms(ctx)
	if err != nil {
		return Discovery{}, err
	}
	doc.IDTokenSigningAlgValuesSupported = algorithms

	// PKCE methods follow the provider's policy; "plain" is advertised only
	// when it is genuinely accepted.
	doc.CodeChallengeMethodsSupported = s.codeChallengeMethods()

	return doc, nil
}

// signingAlgorithms lists the algorithms tokens are signed with.
func (s *Server) signingAlgorithms(ctx context.Context) ([]string, error) {
	if s.keyProvider == nil {
		// Without a key provider the server signs with the single key it was
		// given, which is RS256 in GenerateIDToken.
		return []string{"RS256"}, nil
	}

	published, err := s.keyProvider.Verification(ctx)
	if err != nil {
		return nil, err
	}

	var algorithms []string
	for _, key := range published {
		if alg := key.Algorithm(); alg != "" && !slices.Contains(algorithms, alg) {
			algorithms = append(algorithms, alg)
		}
	}
	if len(algorithms) == 0 {
		return []string{"RS256"}, nil
	}
	return algorithms, nil
}

// codeChallengeMethods lists the PKCE methods the provider accepts.
func (s *Server) codeChallengeMethods() []string {
	if s.allowPlainCodeChallenge {
		return []string{"S256", "plain"}
	}
	return []string{"S256"}
}

func defaultTo(value, fallback []string) []string {
	if len(value) > 0 {
		return value
	}
	return fallback
}

// tokenEndpointAuthMethods returns the client authentication methods to
// advertise.
//
// Without a configured source this is the set every provider serves.
// private_key_jwt is added only when the provider reports it, since a provider
// built without a client assertion store rejects every assertion.
func (s *Server) tokenEndpointAuthMethods() []string {
	if s.authMethods != nil {
		return s.authMethods.TokenEndpointAuthMethods()
	}
	return []string{
		oauth2.AuthMethodClientSecretBasic,
		oauth2.AuthMethodClientSecretPost,
		oauth2.AuthMethodNone,
	}
}
