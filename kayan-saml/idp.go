package saml

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"sync"
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
	mu           sync.RWMutex
	sps          map[string]*SPRegistration
	identityRepo domain.IdentityStorage
	sessionStore SessionStore
	hooks        IdPHooks

	signer Signer
	clock  domain.Clock
}

// IdPOption configures an [IdentityProvider].
type IdPOption func(*IdentityProvider)

// WithIdPSigner sets the signer used for outgoing assertions.
//
// Implement [Signer] yourself to keep the private key in an HSM or KMS.
func WithIdPSigner(s Signer) IdPOption {
	return func(idp *IdentityProvider) { idp.signer = s }
}

// WithIdPClock sets the clock used for assertion validity windows.
func WithIdPClock(c domain.Clock) IdPOption {
	return func(idp *IdentityProvider) { idp.clock = c }
}

// NewIdentityProvider creates a new SAML IdP.
func NewIdentityProvider(
	config IdPServerConfig,
	identityRepo domain.IdentityStorage,
	sessionStore SessionStore,
	opts ...IdPOption,
) *IdentityProvider {
	if config.AssertionTTL == 0 {
		config.AssertionTTL = 5 * time.Minute
	}
	if config.Issuer == "" {
		config.Issuer = config.EntityID
	}

	idp := &IdentityProvider{
		config:       config,
		sps:          make(map[string]*SPRegistration),
		identityRepo: identityRepo,
		sessionStore: sessionStore,
	}
	for _, opt := range opts {
		opt(idp)
	}
	idp.clock = domain.ClockOrDefault(idp.clock)

	// Build a signer from the configured key pair when one was not supplied.
	// Without a signer, generateResponse refuses to emit an assertion rather
	// than emitting one nobody can verify.
	if idp.signer == nil && config.PrivateKey != nil && config.Certificate != nil {
		if signer, err := NewXMLDSigSigner(config.PrivateKey, config.Certificate); err == nil {
			idp.signer = signer
		}
	}
	return idp
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
			if err := r.ParseForm(); err != nil {
				http.Error(w, "Invalid form", http.StatusBadRequest)
				return
			}
			samlRequest = r.FormValue("SAMLRequest")
			relayState = r.FormValue("RelayState")
		}
	}

	if samlRequest == "" {
		http.Error(w, "Missing SAMLRequest", http.StatusBadRequest)
		return
	}
	if len(samlRequest) > 1<<20 {
		http.Error(w, "SAMLRequest too large", http.StatusRequestEntityTooLarge)
		return
	}

	// Decode and parse request
	decoded, err := base64.StdEncoding.DecodeString(samlRequest)
	if err != nil {
		http.Error(w, "Invalid SAMLRequest encoding", http.StatusBadRequest)
		return
	}

	var authnRequest AuthnRequest
	// #nosec G709 -- AuthnRequest is the deliberately narrow wire schema;
	// decoded input is size-limited above and validated before it is trusted.
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
	form, err := idp.PostBindingForm(sp.ACSUrl, response, relayState)
	if err != nil {
		if idp.hooks.OnError != nil {
			idp.hooks.OnError(ctx, err, sp.ID)
		}
		http.Error(w, "Failed to generate response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(form)
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

	// Build assertion. Every field here exists so the service provider can
	// verify something: the ID makes replay detectable, the audience binds the
	// assertion to one service provider, and the subject confirmation binds it
	// to one endpoint and moment.
	expiry := now.Add(idp.config.AssertionTTL)
	assertion := Assertion{
		ID:           "_" + generateID(),
		Version:      "2.0",
		IssueInstant: now,
		Issuer:       Issuer{Value: idp.config.EntityID},
		Subject: Subject{
			NameID: NameID{
				Value:  nameID,
				Format: sp.NameIDFormat,
			},
			SubjectConfirmations: []SubjectConfirmation{{
				Method: ConfirmationMethodBearer,
				SubjectConfirmationData: SubjectConfirmationData{
					Recipient:    sp.ACSUrl,
					NotOnOrAfter: expiry,
					InResponseTo: inResponseTo,
				},
			}},
		},
		Conditions: Conditions{
			NotBefore:    now,
			NotOnOrAfter: expiry,
			AudienceRestrictions: []AudienceRestriction{{
				Audiences: []string{sp.EntityID},
			}},
		},
		AuthnStatement: &AuthnStatement{
			AuthnInstant: now,
			SessionIndex: generateID(),
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
		Issuer:       Issuer{Value: idp.config.EntityID},
		Status: Status{
			StatusCode: StatusCode{Value: StatusSuccess},
		},
		Assertion: &assertion,
	}

	raw, err := xml.Marshal(response)
	if err != nil {
		return nil, fmt.Errorf("saml: marshal response: %w", err)
	}

	// An unsigned assertion authenticates nobody: the service provider has no
	// way to tell it came from here rather than from whoever posted it.
	if idp.signer == nil {
		return nil, ErrNoSigner
	}
	signed, err := idp.signer.Sign(ctx, raw)
	if err != nil {
		return nil, fmt.Errorf("saml: sign response: %w", err)
	}
	return signed, nil
}

// postBindingTemplate renders the auto-submitting form for the HTTP-POST
// binding.
//
// html/template escapes every interpolated value according to where it sits in
// the document. The previous fmt.Sprintf version placed the caller-supplied
// RelayState straight into an attribute, so a value containing a quote broke
// out of it and injected script into the page.
var postBindingTemplate = template.Must(template.New("saml-post").Parse(`<!DOCTYPE html>
<html>
<head><title>SAML SSO</title></head>
<body onload="document.forms[0].submit()">
<form method="POST" action="{{.ACSUrl}}">
<input type="hidden" name="SAMLResponse" value="{{.SAMLResponse}}"/>
<input type="hidden" name="RelayState" value="{{.RelayState}}"/>
<noscript><input type="submit" value="Continue"/></noscript>
</form>
</body>
</html>`))

// PostBindingForm renders the HTML form that delivers a SAML response to the
// service provider over the HTTP-POST binding.
//
// It returns bytes rather than writing to an http.ResponseWriter: transport
// belongs to the caller.
//
//	form, err := idp.PostBindingForm(acsURL, response, relayState)
//	if err != nil { /* ... */ }
//	w.Header().Set("Content-Type", "text/html; charset=utf-8")
//	w.Write(form)
func (idp *IdentityProvider) PostBindingForm(acsURL string, response []byte, relayState string) ([]byte, error) {
	if acsURL == "" {
		return nil, errors.New("saml: empty assertion consumer service URL")
	}

	var buf bytes.Buffer
	err := postBindingTemplate.Execute(&buf, struct {
		ACSUrl       template.URL
		SAMLResponse string
		RelayState   string
	}{
		// The ACS URL comes from this identity provider's own registration,
		// not from the request, so it is a trusted value.
		// #nosec G203 -- acsURL was matched against the registered SP endpoint.
		ACSUrl:       template.URL(acsURL),
		SAMLResponse: base64.StdEncoding.EncodeToString(response),
		RelayState:   relayState,
	})
	if err != nil {
		return nil, fmt.Errorf("saml: render POST binding form: %w", err)
	}
	return buf.Bytes(), nil
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
