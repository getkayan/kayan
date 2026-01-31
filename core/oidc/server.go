package oidc

import (
	"time"

	"github.com/getkayan/kayan/core/identity"
	"github.com/golang-jwt/jwt/v5"
)

// Discovery represents the OIDC discovery metadata.
type Discovery struct {
	Issuer                           string   `json:"issuer"`
	AuthorizationEndpoint            string   `json:"authorization_endpoint"`
	TokenEndpoint                    string   `json:"token_endpoint"`
	UserinfoEndpoint                 string   `json:"userinfo_endpoint"`
	IntrospectionEndpoint            string   `json:"introspection_endpoint,omitempty"`
	RevocationEndpoint               string   `json:"revocation_endpoint,omitempty"`
	EndSessionEndpoint               string   `json:"end_session_endpoint,omitempty"`
	JwksURI                          string   `json:"jwks_uri"`
	ResponseTypesSupported           []string `json:"response_types_supported"`
	SubjectTypesSupported            []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
	ScopesSupported                  []string `json:"scopes_supported"`
	ClaimsSupported                  []string `json:"claims_supported"`
}

type Server struct {
	issuer     string
	signingKey any
	keyID      string
}

func NewServer(issuer string, signingKey any, keyID string) *Server {
	return &Server{
		issuer:     issuer,
		signingKey: signingKey,
		keyID:      keyID,
	}
}

// GenerateIDToken generates a signed OIDC ID Token.
func (s *Server) GenerateIDToken(clientID string, identityID string, traits identity.JSON) (string, error) {
	claims := jwt.MapClaims{
		"iss":    s.issuer,
		"sub":    identityID,
		"aud":    clientID,
		"exp":    time.Now().Add(1 * time.Hour).Unix(),
		"iat":    time.Now().Unix(),
		"traits": traits, // Optional: include traits in the ID token
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = s.keyID

	return token.SignedString(s.signingKey)
}

func (s *Server) GetDiscovery(baseURL string) Discovery {
	return Discovery{
		Issuer:                           s.issuer,
		AuthorizationEndpoint:            baseURL + "/oauth2/auth",
		TokenEndpoint:                    baseURL + "/oauth2/token",
		UserinfoEndpoint:                 baseURL + "/oidc/userinfo",
		IntrospectionEndpoint:            baseURL + "/oauth2/introspect",
		RevocationEndpoint:               baseURL + "/oauth2/revoke",
		EndSessionEndpoint:               baseURL + "/oidc/logout",
		JwksURI:                          baseURL + "/oauth2/jwks",
		ResponseTypesSupported:           []string{"code", "id_token"},
		SubjectTypesSupported:            []string{"public"},
		IDTokenSigningAlgValuesSupported: []string{"RS256"},
		ScopesSupported:                  []string{"openid", "profile", "email"},
		ClaimsSupported:                  []string{"sub", "iss", "aud", "exp", "iat"},
	}
}
