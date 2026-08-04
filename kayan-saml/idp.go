package saml

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"net/http"
	"time"

	"github.com/getkayan/kayan/core/domain"
	"github.com/getkayan/kayan/core/identity"
)

// ---- Identity Provider ----

// IdPServerConfig holds configuration for Kayan acting as a SAML IdP.
type IdPServerConfig struct {
	// EntityID is this IdP's unique identifier.
	EntityID string

	// SSOUrl is where SPs send authentication requests.
	SSOUrl string

	// SLOUrl is where SPs send logout requests (optional).
	SLOUrl string

	// MetadataURL is where this IdP serves its metadata.
	MetadataURL string

	// Certificate is this IdP's public certificate.
	Certificate *x509.Certificate

	// PrivateKey is for signing assertions.
	PrivateKey *rsa.PrivateKey

	// AssertionTTL is how long assertions are valid.
	AssertionTTL time.Duration

	// Issuer is the issuer value in assertions.
	Issuer string
}

// SPRegistration represents a registered Service Provider.
type SPRegistration struct {
	// ID is a unique identifier for this SP.
	ID string

	// EntityID is the SP's entity ID.
	EntityID string

	// ACSUrl is the SP's Assertion Consumer Service URL.
	ACSUrl string

	// SLOUrl is the SP's Single Logout URL (optional).
	SLOUrl string

	// Certificate is the SP's public certificate (optional, for signed requests).
	Certificate *x509.Certificate

	// NameIDFormat specifies the format for the user identifier.
	NameIDFormat string

	// AttributeMapping maps identity fields to SAML attributes.
	AttributeMapping map[string]string

	// TenantID associates this SP with a specific tenant.
	TenantID string

	// AllowedRedirectURIs for security validation.
	AllowedRedirectURIs []string
}

// ---- IdP Hooks ----

// IdPHooks provides extension points for IdP operations.
type IdPHooks struct {
	// BeforeSSO is called before processing an SSO request.
	BeforeSSO func(ctx context.Context, spID string, authnRequest *AuthnRequest) error

	// AfterSSO is called after successful SSO.
	AfterSSO func(ctx context.Context, spID string, userID string)

	// BeforeAssertion is called before generating an assertion.
	// Modify attributes or return error to cancel.
	BeforeAssertion func(ctx context.Context, sp *SPRegistration, attrs map[string][]string) error

	// AuthenticateUser is called to authenticate the user.
	// If nil, the IdP assumes user is already authenticated via session.
	AuthenticateUser func(ctx context.Context, r *http.Request) (any, error)

	// GetUserAttributes extracts attributes from a user identity.
	GetUserAttributes func(ctx context.Context, ident any, sp *SPRegistration) (map[string][]string, error)

	// GetNameID extracts the NameID from a user identity.
	GetNameID func(ctx context.Context, ident any, sp *SPRegistration) (string, error)

	// OnError is called when an error occurs.
	OnError func(ctx context.Context, err error, spID string)
}

// ---- Identity Provider Implementation ----

// IdentityProvider represents Kayan acting as a SAML IdP.
type IdentityProvider struct {
	config       IdPServerConfig
	sps          map[string]*SPRegistration
	identityRepo domain.IdentityStorage
	sessionStore SessionStore
	hooks        IdPHooks
}

// NewIdentityProvider creates a new SAML IdP.
func NewIdentityProvider(
	config IdPServerConfig,
	identityRepo domain.IdentityStorage,
	sessionStore SessionStore,
) *IdentityProvider {
	if config.AssertionTTL == 0 {
		config.AssertionTTL = 5 * time.Minute
	}
	if config.Issuer == "" {
		config.Issuer = config.EntityID
	}
	return &IdentityProvider{
		config:       config,
		sps:          make(map[string]*SPRegistration),
		identityRepo: identityRepo,
		sessionStore: sessionStore,
	}
}

// SetHooks sets lifecycle hooks.
func (idp *IdentityProvider) SetHooks(hooks IdPHooks) {
	idp.hooks = hooks
}

// RegisterSP adds a Service Provider.
func (idp *IdentityProvider) RegisterSP(sp *SPRegistration) {
	idp.sps[sp.ID] = sp
	// Also index by EntityID for lookup
	idp.sps[sp.EntityID] = sp
}

// GetSP retrieves a registered SP.
func (idp *IdentityProvider) GetSP(id string) (*SPRegistration, error) {
	sp, ok := idp.sps[id]
	if !ok {
		return nil, fmt.Errorf("SP not found: %s", id)
	}
	return sp, nil
}

// HandleSSORequest processes an incoming SSO request from an SP.
// This is the main entry point for SP-initiated SSO.
func (idp *IdentityProvider) HandleSSORequest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse the AuthnRequest
	samlRequest := r.URL.Query().Get("SAMLRequest")
	relayState := r.URL.Query().Get("RelayState")

	if samlRequest == "" {
		// Check POST binding
		if r.Method == "POST" {
			r.ParseForm()
			samlRequest = r.FormValue("SAMLRequest")
			relayState = r.FormValue("RelayState")
		}
	}

	if samlRequest == "" {
		http.Error(w, "Missing SAMLRequest", http.StatusBadRequest)
		return
	}

	// Decode and parse request
	decoded, err := base64.StdEncoding.DecodeString(samlRequest)
	if err != nil {
		http.Error(w, "Invalid SAMLRequest encoding", http.StatusBadRequest)
		return
	}

	var authnRequest AuthnRequest
	if err := xml.Unmarshal(decoded, &authnRequest); err != nil {
		http.Error(w, "Invalid SAMLRequest XML", http.StatusBadRequest)
		return
	}

	// Find the SP
	sp, err := idp.GetSP(authnRequest.Issuer.Value)
	if err != nil {
		http.Error(w, "Unknown Service Provider", http.StatusBadRequest)
		return
	}

	// Before hook
	if idp.hooks.BeforeSSO != nil {
		if err := idp.hooks.BeforeSSO(ctx, sp.ID, &authnRequest); err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
	}

	// Authenticate user
	var ident any
	if idp.hooks.AuthenticateUser != nil {
		ident, err = idp.hooks.AuthenticateUser(ctx, r)
		if err != nil {
			// Redirect to login page with return URL
			// This is application-specific
			http.Error(w, "Authentication required", http.StatusUnauthorized)
			return
		}
	}

	// Generate SAML response
	response, err := idp.generateResponse(ctx, sp, ident, authnRequest.ID)
	if err != nil {
		if idp.hooks.OnError != nil {
			idp.hooks.OnError(ctx, err, sp.ID)
		}
		http.Error(w, "Failed to generate response", http.StatusInternalServerError)
		return
	}

	// Send response via POST binding
	idp.sendPostBinding(w, sp.ACSUrl, response, relayState)
}

// generateResponse creates a SAML response with assertion.
func (idp *IdentityProvider) generateResponse(
	ctx context.Context,
	sp *SPRegistration,
	ident any,
	inResponseTo string,
) ([]byte, error) {
	now := time.Now().UTC()

	// Get NameID
	var nameID string
	if idp.hooks.GetNameID != nil {
		var err error
		nameID, err = idp.hooks.GetNameID(ctx, ident, sp)
		if err != nil {
			return nil, err
		}
	} else {
		// Default: use identity ID
		if fi, ok := ident.(interface{ GetID() any }); ok {
			nameID = fmt.Sprintf("%v", fi.GetID())
		}
	}

	// Get attributes
	attrs := make(map[string][]string)
	if idp.hooks.GetUserAttributes != nil {
		var err error
		attrs, err = idp.hooks.GetUserAttributes(ctx, ident, sp)
		if err != nil {
			return nil, err
		}
	} else {
		// Default attribute extraction
		if ts, ok := ident.(interface{ GetTraits() identity.JSON }); ok {
			attrs["email"] = []string{string(ts.GetTraits())} // Simplified
		}
	}

	// Before assertion hook
	if idp.hooks.BeforeAssertion != nil {
		if err := idp.hooks.BeforeAssertion(ctx, sp, attrs); err != nil {
			return nil, err
		}
	}

	// Build assertion
	assertion := Assertion{
		Subject: Subject{
			NameID: NameID{
				Value:  nameID,
				Format: sp.NameIDFormat,
			},
		},
		Conditions: Conditions{
			NotBefore:    now,
			NotOnOrAfter: now.Add(idp.config.AssertionTTL),
		},
	}

	// Add attributes
	for name, values := range attrs {
		attr := Attribute{Name: name}
		for _, v := range values {
			attr.Values = append(attr.Values, AttributeValue{Value: v})
		}
		assertion.AttributeStatement.Attributes = append(assertion.AttributeStatement.Attributes, attr)
	}

	// Build response
	response := Response{
		ID:           "_" + generateID(),
		InResponseTo: inResponseTo,
		Version:      "2.0",
		IssueInstant: now,
		Destination:  sp.ACSUrl,
		Status: Status{
			StatusCode: StatusCode{Value: "urn:oasis:names:tc:SAML:2.0:status:Success"},
		},
		Assertion: &assertion,
	}

	// Serialize (in production, this should be signed)
	return xml.Marshal(response)
}

// sendPostBinding sends the response via HTTP POST binding.
func (idp *IdentityProvider) sendPostBinding(w http.ResponseWriter, acsURL string, response []byte, relayState string) {
	encoded := base64.StdEncoding.EncodeToString(response)

	html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><title>SAML SSO</title></head>
<body onload="document.forms[0].submit()">
<form method="POST" action="%s">
<input type="hidden" name="SAMLResponse" value="%s"/>
<input type="hidden" name="RelayState" value="%s"/>
<noscript><input type="submit" value="Continue"/></noscript>
</form>
</body>
</html>`, acsURL, encoded, relayState)

	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}

// GetMetadata returns this IdP's metadata XML.
func (idp *IdentityProvider) GetMetadata() ([]byte, error) {
	metadata := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="%s">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="%s"/>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="%s"/>
  </IDPSSODescriptor>
</EntityDescriptor>`, idp.config.EntityID, idp.config.SSOUrl, idp.config.SSOUrl)

	return []byte(metadata), nil
}

// ---- Strategy Implementation ----

// Strategy implements LoginStrategy for SAML authentication.
type Strategy struct {
	sp      *ServiceProvider
	idps    map[string]*IdPConfig
	factory func() any
}

// NewStrategy creates a new SAML login strategy.
func NewStrategy(sp *ServiceProvider, factory func() any) *Strategy {
	return &Strategy{
		sp:      sp,
		factory: factory,
	}
}

func (s *Strategy) ID() string {
	return "saml"
}

// Authenticate is not directly used for SAML (it's redirect-based).
// This is called after the SAML response is processed.
func (s *Strategy) Authenticate(ctx context.Context, identifier, secret string) (any, error) {
	// In SAML flow, authentication happens via redirect
	// This method could be used for the callback handling
	return s.sp.ProcessResponse(ctx, secret, identifier)
}

// BeginAuth initiates SAML authentication with the specified IdP.
func (s *Strategy) BeginAuth(ctx context.Context, idpID string, returnURL string) (string, error) {
	return s.sp.InitiateLogin(ctx, idpID, returnURL)
}
