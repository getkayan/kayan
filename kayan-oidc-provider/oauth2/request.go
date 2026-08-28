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
	clientID := values.Get("client_id")
	if clientID == "" {
		return nil, ErrInvalidRequest.WithDescription("client_id is required")
	}

	client, err := p.clientStore.GetClient(ctx, clientID)
	if err != nil {
		return nil, ErrInvalidClient.WithDescription("unknown client").WithCause(err)
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

	clientID, clientSecret, err := clientCredentials(values, authorization)
	if err != nil {
		return nil, err
	}

	client, err := p.authenticate(ctx, clientID, clientSecret, grantType)
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
func clientCredentials(values url.Values, authorization string) (id, secret string, err error) {
	if authorization != "" {
		const prefix = "Basic "
		if !strings.HasPrefix(authorization, prefix) {
			return "", "", ErrInvalidClient.WithDescription("unsupported authorization scheme")
		}

		decoded, decodeErr := base64.StdEncoding.DecodeString(strings.TrimPrefix(authorization, prefix))
		if decodeErr != nil {
			return "", "", ErrInvalidClient.WithDescription("malformed authorization header")
		}

		id, secret, found := strings.Cut(string(decoded), ":")
		if !found {
			return "", "", ErrInvalidClient.WithDescription("malformed authorization header")
		}

		// RFC 6749 section 2.3.1 requires the credentials be form-urlencoded
		// before base64. Skipping this rejects any secret containing a
		// reserved character.
		decodedID, idErr := url.QueryUnescape(id)
		decodedSecret, secretErr := url.QueryUnescape(secret)
		if idErr != nil || secretErr != nil {
			return "", "", ErrInvalidClient.WithDescription("malformed authorization header")
		}
		return decodedID, decodedSecret, nil
	}

	id = values.Get("client_id")
	if id == "" {
		return "", "", ErrInvalidClient.WithDescription("client authentication is required")
	}
	return id, values.Get("client_secret"), nil
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
