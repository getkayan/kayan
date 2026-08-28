package oauth2

import (
	"context"
	"encoding/base64"
	"net/url"
	"strings"
)

// AuthorizeRequest is a validated authorization request.
//
// Every value here has already been checked: the client exists, the redirect
// URI is registered, the response type is supported, and PKCE satisfies the
// provider's policy. A caller holding one of these does not need to know which
// checks exist — that is the point. Hand-parsing the query string means
// reimplementing the redirect URI allowlist, and that is where open
// redirectors come from.
type AuthorizeRequest struct {
	Client              *Client
	ClientID            string
	RedirectURI         string
	ResponseType        []string
	Scopes              []string
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	Prompt              []string

	// AuthenticationRequirements carries max_age and acr_values. They are
	// constraints on the sign-in rather than on the request, so the caller
	// consults them before reusing an existing session; see
	// [AuthenticationRequirements.NeedsReauthentication].
	AuthenticationRequirements
}

// ParseAuthorizeRequest validates authorization request parameters.
//
// Pass the query string from wherever the request arrived — Kayan does not
// read from an *http.Request:
//
//	req, err := provider.ParseAuthorizeRequest(ctx, r.URL.Query())
//	if err != nil {
//	    // Redirect the error to req.RedirectURI only if the URI was validated;
//	    // otherwise render it, since redirecting an unvalidated URI is itself
//	    // the vulnerability.
//	}
func (p *Provider) ParseAuthorizeRequest(ctx context.Context, values url.Values) (*AuthorizeRequest, error) {
	// A request_uri is resolved first and replaces the query entirely. The
	// pushed parameters are used alone (RFC 9126 section 4): merging in
	// whatever else arrived on the authorization URL would let anyone holding
	// a victim's request_uri append their own redirect_uri.
	resolved, err := p.resolvePushedRequest(ctx, values)
	if err != nil {
		return nil, err
	}
	return p.parseAuthorizeParameters(ctx, resolved)
}

// parseAuthorizeParameters validates authorization request parameters that
// have already been resolved.
//
// It is separate from [Provider.ParseAuthorizeRequest] so the pushed
// authorization request endpoint can validate what a client lodges. Going
// through the public entry point would apply the require-PAR gate to the push
// itself, and a pushed request carries no request_uri -- so enabling the
// requirement would refuse every attempt to satisfy it.
func (p *Provider) parseAuthorizeParameters(ctx context.Context, values url.Values) (*AuthorizeRequest, error) {
	clientID := values.Get("client_id")
	if clientID == "" {
		return nil, ErrInvalidRequest.WithDescription("client_id is required")
	}

	client, clientErr := p.clientStore.GetClient(ctx, clientID)
	if clientErr != nil {
		return nil, ErrInvalidClient.WithDescription("unknown client").WithCause(clientErr)
	}
	// A store that reports a miss as (nil, nil) is a shape the interface
	// tolerates. Without this guard the next line dereferences nil, and this
	// parser runs on an unauthenticated query string, so any request naming a
	// client id that does not exist would panic in the caller's handler.
	if client == nil {
		return nil, ErrInvalidClient.WithDescription("unknown client")
	}

	redirectURI := values.Get("redirect_uri")
	if redirectURI == "" {
		// RFC 6749 allows omitting it when exactly one is registered. With
		// several registered there is no safe way to choose.
		if len(client.RedirectURIs) != 1 {
			return nil, ErrInvalidRequest.WithDescription("redirect_uri is required")
		}
		redirectURI = client.RedirectURIs[0]
	}
	if !client.AllowsRedirectURI(redirectURI) {
		// Never redirect this error: sending it to an unregistered URI is the
		// open redirect the allowlist exists to prevent.
		return nil, ErrInvalidRequest.WithDescription("redirect_uri is not registered for this client")
	}

	maxAge, err := parseMaxAge(values.Get("max_age"))
	if err != nil {
		return nil, err
	}

	responseType := splitSpace(values.Get("response_type"))
	if len(responseType) == 0 {
		return nil, ErrInvalidRequest.WithDescription("response_type is required")
	}
	// Only the authorization code flow is implemented. Accepting "token" or
	// "id_token" here would advertise an implicit flow that does not exist.
	if len(responseType) != 1 || responseType[0] != ResponseTypeCode {
		return nil, ErrUnsupportedResponseType.
			WithDescription("only the authorization code response type is supported")
	}

	challenge := values.Get("code_challenge")
	method := values.Get("code_challenge_method")
	if challenge == "" {
		if p.requirePKCE || client.IsPublic() {
			return nil, ErrInvalidRequest.WithDescription("code_challenge is required")
		}
	} else {
		resolved := normalizeChallengeMethod(method)
		switch {
		case resolved == "":
			return nil, ErrInvalidRequest.WithDescription("unsupported code_challenge_method")
		case resolved == challengeMethodPlain && !p.allowPlainCC:
			return nil, ErrInvalidRequest.WithDescription("code_challenge_method must be S256")
		}
		method = resolved
	}

	scopes := splitSpace(values.Get("scope"))
	if err := checkScopes(client, scopes); err != nil {
		return nil, err
	}

	return &AuthorizeRequest{
		Client:              client,
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		ResponseType:        responseType,
		Scopes:              scopes,
		State:               values.Get("state"),
		Nonce:               values.Get("nonce"),
		CodeChallenge:       challenge,
		CodeChallengeMethod: method,
		Prompt:              splitSpace(values.Get("prompt")),
		AuthenticationRequirements: AuthenticationRequirements{
			MaxAge:    maxAge,
			ACRValues: splitSpace(values.Get("acr_values")),
		},
	}, nil
}

// Response types this provider supports.
const ResponseTypeCode = "code"

// TokenRequest is a validated token request with its client authenticated.
type TokenRequest struct {
	Client    *Client
	GrantType string

	// Authorization code grant.
	Code         string
	RedirectURI  string
	CodeVerifier string

	// Refresh token grant.
	RefreshToken string

	// Client credentials grant.
	Scopes []string
}

// ParseTokenRequest validates a token request and authenticates the client.
//
// Credentials are taken from the Authorization header when present, falling
// back to the request body (RFC 6749 section 2.3.1). Pass the header value
// verbatim; an empty string means none was sent.
func (p *Provider) ParseTokenRequest(ctx context.Context, values url.Values, authorization string) (*TokenRequest, error) {
	grantType := values.Get("grant_type")
	if grantType == "" {
		return nil, ErrInvalidRequest.WithDescription("grant_type is required")
	}

	creds, err := clientCredentials(values, authorization)
	if err != nil {
		return nil, err
	}

	client, err := p.authenticateWith(ctx, creds, grantType)
	if err != nil {
		return nil, err
	}

	req := &TokenRequest{Client: client, GrantType: grantType}

	switch grantType {
	case GrantAuthorizationCode:
		req.Code = values.Get("code")
		if req.Code == "" {
			return nil, ErrInvalidRequest.WithDescription("code is required")
		}
		req.RedirectURI = values.Get("redirect_uri")
		req.CodeVerifier = values.Get("code_verifier")

	case GrantRefreshToken:
		req.RefreshToken = values.Get("refresh_token")
		if req.RefreshToken == "" {
			return nil, ErrInvalidRequest.WithDescription("refresh_token is required")
		}

	case GrantClientCredentials:
		// This grant authenticates the client itself, so a public client —
		// which by definition cannot hold a secret — must not use it.
		if client.IsPublic() {
			return nil, ErrUnauthorizedClient.
				WithDescription("the client credentials grant requires a confidential client")
		}
		req.Scopes = splitSpace(values.Get("scope"))
		if err := checkScopes(client, req.Scopes); err != nil {
			return nil, err
		}

	default:
		return nil, ErrUnsupportedGrantType.WithDescriptionf("unsupported grant type %q", grantType)
	}

	return req, nil
}

// clientCredentials extracts client credentials from the Authorization header
// or the request body.
func clientCredentials(values url.Values, authorization string) (clientCreds, error) {
	assertion := values.Get("client_assertion")
	assertionType := values.Get("client_assertion_type")

	if authorization != "" {
		// Presenting a secret and an assertion together is not a client that
		// supports both; it is a request trying two credentials to see which
		// one the endpoint honours. RFC 6749 section 2.3 permits exactly one
		// authentication method per request.
		if assertion != "" || assertionType != "" {
			return clientCreds{}, ErrInvalidClient.WithDescription("more than one client authentication method was used")
		}

		const prefix = "Basic "
		if !strings.HasPrefix(authorization, prefix) {
			return clientCreds{}, ErrInvalidClient.WithDescription("unsupported authorization scheme")
		}

		decoded, decodeErr := base64.StdEncoding.DecodeString(strings.TrimPrefix(authorization, prefix))
		if decodeErr != nil {
			return clientCreds{}, ErrInvalidClient.WithDescription("malformed authorization header")
		}

		id, secret, found := strings.Cut(string(decoded), ":")
		if !found {
			return clientCreds{}, ErrInvalidClient.WithDescription("malformed authorization header")
		}

		// RFC 6749 section 2.3.1 requires the credentials be form-urlencoded
		// before base64. Skipping this rejects any secret containing a
		// reserved character.
		decodedID, idErr := url.QueryUnescape(id)
		decodedSecret, secretErr := url.QueryUnescape(secret)
		if idErr != nil || secretErr != nil {
			return clientCreds{}, ErrInvalidClient.WithDescription("malformed authorization header")
		}
		return clientCreds{id: decodedID, secret: decodedSecret}, nil
	}

	id := values.Get("client_id")

	if assertionType != "" || assertion != "" {
		if values.Get("client_secret") != "" {
			return clientCreds{}, ErrInvalidClient.WithDescription("more than one client authentication method was used")
		}
		if assertion == "" {
			return clientCreds{}, ErrInvalidClient.WithDescription("client_assertion is required")
		}
		// client_id is optional here: the assertion names its own issuer, and
		// that is the identity the request is authenticated as.
		return clientCreds{id: id, assertion: assertion, assertionType: assertionType}, nil
	}

	if id == "" {
		return clientCreds{}, ErrInvalidClient.WithDescription("client authentication is required")
	}
	return clientCreds{id: id, secret: values.Get("client_secret")}, nil
}

// clientCreds is whatever the token endpoint received to authenticate the
// client, in exactly one of its two shapes.
type clientCreds struct {
	id     string
	secret string

	assertion     string
	assertionType string
}

// checkScopes reports whether every requested scope was granted to the client.
func checkScopes(client *Client, requested []string) error {
	// A client with no declared scopes is unrestricted, which keeps existing
	// registrations working; declaring any scope opts into enforcement.
	if len(client.Scopes) == 0 || len(requested) == 0 {
		return nil
	}

	allowed := make(map[string]struct{}, len(client.Scopes))
	for _, scope := range client.Scopes {
		allowed[scope] = struct{}{}
	}
	for _, scope := range requested {
		if _, ok := allowed[scope]; !ok {
			return ErrInvalidScope.WithDescriptionf("scope %q was not granted to this client", scope)
		}
	}
	return nil
}

// splitSpace splits a space-delimited parameter, dropping empty entries.
func splitSpace(value string) []string {
	if value == "" {
		return nil
	}
	return strings.Fields(value)
}
