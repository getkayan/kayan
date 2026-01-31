package saml

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/getkayan/kayan/core/domain"
	"github.com/getkayan/kayan/core/identity"
)

// ---- Core Types ----

// Config holds SAML Service Provider configuration.
type Config struct {
	// EntityID is the unique identifier for this SP (usually a URL).
	EntityID string

	// ACSUrl is the Assertion Consumer Service URL where IdP sends responses.
	ACSUrl string

	// MetadataURL is where this SP's metadata is served (optional).
	MetadataURL string

	// SLOUrl is the Single Logout Service URL (optional).
	SLOUrl string

	// Certificate is this SP's public certificate for signature verification.
	Certificate *x509.Certificate

	// PrivateKey is this SP's private key for signing requests.
	PrivateKey *rsa.PrivateKey

	// AllowIdPInitiated allows IdP-initiated SSO (security consideration).
	AllowIdPInitiated bool

	// SignRequests determines if AuthnRequests should be signed.
	SignRequests bool

	// SignatureMethod for signing (default: RSA-SHA256).
	SignatureMethod string

	// SessionTTL for pending authentication sessions.
	SessionTTL time.Duration
}

// IdPConfig represents an external Identity Provider configuration.
type IdPConfig struct {
	// ID is a unique identifier for this IdP (e.g., "okta", "azure-ad").
	ID string

	// EntityID is the IdP's entity ID from their metadata.
	EntityID string

	// SSOUrl is the IdP's Single Sign-On URL.
	SSOUrl string

	// SLOUrl is the IdP's Single Logout URL (optional).
	SLOUrl string

	// Certificate is the IdP's public certificate for verifying responses.
	Certificate *x509.Certificate

	// NameIDFormat preferred format (e.g., "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress").
	NameIDFormat string

	// AttributeMapping maps SAML attributes to identity fields.
	AttributeMapping map[string]string

	// TenantID associates this IdP with a specific tenant (optional).
	TenantID string

	// Metadata is the raw IdP metadata XML (if loaded from URL).
	Metadata []byte
}

// ---- Session Management ----

// Session stores pending SAML authentication state.
type Session struct {
	ID         string
	RequestID  string
	IdPID      string
	RelayState string
	CreateTime time.Time
	ExpiresAt  time.Time
	ReturnURL  string
}

// SessionStore interface for SAML session persistence.
type SessionStore interface {
	Save(ctx context.Context, session *Session) error
	Get(ctx context.Context, id string) (*Session, error)
	GetByRequestID(ctx context.Context, requestID string) (*Session, error)
	Delete(ctx context.Context, id string) error
}

// ---- Hooks ----

// Hooks provides extension points for SAML flow customization.
type Hooks struct {
	// BeforeAuthnRequest is called before creating an AuthnRequest.
	// Modify the request or return error to cancel.
	BeforeAuthnRequest func(ctx context.Context, idpID string, req *AuthnRequest) error

	// AfterAuthnRequest is called after AuthnRequest is created.
	AfterAuthnRequest func(ctx context.Context, idpID string, sessionID string)

	// BeforeProcessResponse is called before processing a SAML response.
	BeforeProcessResponse func(ctx context.Context, response *Response) error

	// AfterProcessResponse is called after successful response processing.
	// Receives the extracted user info.
	AfterProcessResponse func(ctx context.Context, user *SAMLUser)

	// OnError is called when an error occurs during SAML flow.
	OnError func(ctx context.Context, err error, idpID string)

	// UserFactory creates a new identity from SAML attributes.
	// If nil, default mapping is used.
	UserFactory func(ctx context.Context, user *SAMLUser) (any, error)

	// UserLoader loads an existing identity by SAML identifier.
	UserLoader func(ctx context.Context, nameID string, idpID string) (any, error)

	// LinkUser links a SAML identity to an existing user.
	LinkUser func(ctx context.Context, ident any, user *SAMLUser) error

	// IDGenerator generates session IDs.
	IDGenerator func() string
}

// ---- SAML Protocol Types ----

// AuthnRequest represents a SAML authentication request.
type AuthnRequest struct {
	XMLName                     xml.Name      `xml:"urn:oasis:names:tc:SAML:2.0:protocol AuthnRequest"`
	ID                          string        `xml:"ID,attr"`
	Version                     string        `xml:"Version,attr"`
	IssueInstant                time.Time     `xml:"IssueInstant,attr"`
	Destination                 string        `xml:"Destination,attr"`
	AssertionConsumerServiceURL string        `xml:"AssertionConsumerServiceURL,attr"`
	ProtocolBinding             string        `xml:"ProtocolBinding,attr"`
	Issuer                      Issuer        `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	NameIDPolicy                *NameIDPolicy `xml:"urn:oasis:names:tc:SAML:2.0:protocol NameIDPolicy,omitempty"`
}

// Issuer represents the SAML issuer element.
type Issuer struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Value   string   `xml:",chardata"`
}

// NameIDPolicy specifies the name identifier format.
type NameIDPolicy struct {
	XMLName     xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol NameIDPolicy"`
	Format      string   `xml:"Format,attr,omitempty"`
	AllowCreate bool     `xml:"AllowCreate,attr,omitempty"`
}

// Response represents a SAML response (simplified).
type Response struct {
	XMLName      xml.Name   `xml:"urn:oasis:names:tc:SAML:2.0:protocol Response"`
	ID           string     `xml:"ID,attr"`
	InResponseTo string     `xml:"InResponseTo,attr"`
	Version      string     `xml:"Version,attr"`
	IssueInstant time.Time  `xml:"IssueInstant,attr"`
	Destination  string     `xml:"Destination,attr"`
	Status       Status     `xml:"urn:oasis:names:tc:SAML:2.0:protocol Status"`
	Assertion    *Assertion `xml:"urn:oasis:names:tc:SAML:2.0:assertion Assertion"`
}

// Status represents the SAML status.
type Status struct {
	StatusCode StatusCode `xml:"urn:oasis:names:tc:SAML:2.0:protocol StatusCode"`
}

// StatusCode represents the status code.
type StatusCode struct {
	Value string `xml:"Value,attr"`
}

// Assertion represents a SAML assertion (simplified).
type Assertion struct {
	Subject            Subject            `xml:"urn:oasis:names:tc:SAML:2.0:assertion Subject"`
	Conditions         Conditions         `xml:"urn:oasis:names:tc:SAML:2.0:assertion Conditions"`
	AttributeStatement AttributeStatement `xml:"urn:oasis:names:tc:SAML:2.0:assertion AttributeStatement"`
}

// Subject contains the NameID.
type Subject struct {
	NameID NameID `xml:"urn:oasis:names:tc:SAML:2.0:assertion NameID"`
}

// NameID represents the user identifier.
type NameID struct {
	Value  string `xml:",chardata"`
	Format string `xml:"Format,attr"`
}

// Conditions for assertion validity.
type Conditions struct {
	NotBefore    time.Time `xml:"NotBefore,attr"`
	NotOnOrAfter time.Time `xml:"NotOnOrAfter,attr"`
}

// AttributeStatement contains user attributes.
type AttributeStatement struct {
	Attributes []Attribute `xml:"urn:oasis:names:tc:SAML:2.0:assertion Attribute"`
}

// Attribute represents a SAML attribute.
type Attribute struct {
	Name         string           `xml:"Name,attr"`
	FriendlyName string           `xml:"FriendlyName,attr"`
	Values       []AttributeValue `xml:"urn:oasis:names:tc:SAML:2.0:assertion AttributeValue"`
}

// AttributeValue holds an attribute value.
type AttributeValue struct {
	Value string `xml:",chardata"`
}

// ---- Extracted User Info ----

// SAMLUser represents user information extracted from a SAML assertion.
type SAMLUser struct {
	NameID       string
	NameIDFormat string
	IdPID        string
	SessionIndex string
	Attributes   map[string][]string

	// Commonly mapped fields (convenience)
	Email       string
	FirstName   string
	LastName    string
	DisplayName string
	Groups      []string
}

// GetAttribute returns the first value of an attribute.
func (u *SAMLUser) GetAttribute(name string) string {
	if vals, ok := u.Attributes[name]; ok && len(vals) > 0 {
		return vals[0]
	}
	return ""
}

// GetAttributes returns all values of an attribute.
func (u *SAMLUser) GetAttributes(name string) []string {
	return u.Attributes[name]
}

// ---- Service Provider ----

// ServiceProvider handles SAML SP operations.
type ServiceProvider struct {
	config       Config
	idps         map[string]*IdPConfig
	sessionStore SessionStore
	identityRepo domain.IdentityStorage
	factory      func() any
	hooks        Hooks
}

// NewServiceProvider creates a new SAML SP.
func NewServiceProvider(
	config Config,
	sessionStore SessionStore,
	identityRepo domain.IdentityStorage,
	factory func() any,
) *ServiceProvider {
	if config.SessionTTL == 0 {
		config.SessionTTL = 5 * time.Minute
	}
	return &ServiceProvider{
		config:       config,
		idps:         make(map[string]*IdPConfig),
		sessionStore: sessionStore,
		identityRepo: identityRepo,
		factory:      factory,
	}
}

// SetHooks sets lifecycle hooks.
func (sp *ServiceProvider) SetHooks(hooks Hooks) {
	sp.hooks = hooks
}

// RegisterIdP adds an Identity Provider configuration.
func (sp *ServiceProvider) RegisterIdP(idp *IdPConfig) {
	sp.idps[idp.ID] = idp
}

// RegisterIdPFromMetadata registers an IdP by fetching its metadata.
func (sp *ServiceProvider) RegisterIdPFromMetadata(ctx context.Context, id, metadataURL string) error {
	resp, err := http.Get(metadataURL)
	if err != nil {
		return fmt.Errorf("failed to fetch IdP metadata: %w", err)
	}
	defer resp.Body.Close()

	metadata, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	idp, err := ParseIdPMetadata(id, metadata)
	if err != nil {
		return err
	}

	sp.RegisterIdP(idp)
	return nil
}

// GetIdP returns the IdP configuration.
func (sp *ServiceProvider) GetIdP(id string) (*IdPConfig, error) {
	idp, ok := sp.idps[id]
	if !ok {
		return nil, fmt.Errorf("IdP not found: %s", id)
	}
	return idp, nil
}

// InitiateLogin starts the SAML authentication flow.
// Returns the redirect URL to the IdP.
func (sp *ServiceProvider) InitiateLogin(ctx context.Context, idpID string, returnURL string) (string, error) {
	idp, err := sp.GetIdP(idpID)
	if err != nil {
		return "", err
	}

	// Generate request ID
	requestID := generateID()
	if sp.hooks.IDGenerator != nil {
		requestID = sp.hooks.IDGenerator()
	}

	// Create AuthnRequest
	req := &AuthnRequest{
		ID:                          "_" + requestID,
		Version:                     "2.0",
		IssueInstant:                time.Now().UTC(),
		Destination:                 idp.SSOUrl,
		AssertionConsumerServiceURL: sp.config.ACSUrl,
		ProtocolBinding:             "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
		Issuer:                      Issuer{Value: sp.config.EntityID},
	}

	if idp.NameIDFormat != "" {
		req.NameIDPolicy = &NameIDPolicy{
			Format:      idp.NameIDFormat,
			AllowCreate: true,
		}
	}

	// Before hook
	if sp.hooks.BeforeAuthnRequest != nil {
		if err := sp.hooks.BeforeAuthnRequest(ctx, idpID, req); err != nil {
			return "", err
		}
	}

	// Serialize and encode
	xmlBytes, err := xml.Marshal(req)
	if err != nil {
		return "", fmt.Errorf("failed to marshal AuthnRequest: %w", err)
	}

	// Store session
	session := &Session{
		ID:         requestID,
		RequestID:  req.ID,
		IdPID:      idpID,
		ReturnURL:  returnURL,
		CreateTime: time.Now(),
		ExpiresAt:  time.Now().Add(sp.config.SessionTTL),
	}

	if err := sp.sessionStore.Save(ctx, session); err != nil {
		return "", fmt.Errorf("failed to save session: %w", err)
	}

	// After hook
	if sp.hooks.AfterAuthnRequest != nil {
		sp.hooks.AfterAuthnRequest(ctx, idpID, session.ID)
	}

	// Build redirect URL (HTTP-Redirect binding)
	samlRequest := base64.StdEncoding.EncodeToString(xmlBytes)
	redirectURL := fmt.Sprintf("%s?SAMLRequest=%s&RelayState=%s",
		idp.SSOUrl,
		url.QueryEscape(samlRequest),
		url.QueryEscape(session.ID),
	)

	return redirectURL, nil
}

// ProcessResponse handles the SAML response from the IdP.
// Returns the authenticated identity.
func (sp *ServiceProvider) ProcessResponse(ctx context.Context, samlResponse, relayState string) (any, error) {
	// Decode response
	responseBytes, err := base64.StdEncoding.DecodeString(samlResponse)
	if err != nil {
		return nil, fmt.Errorf("failed to decode SAML response: %w", err)
	}

	var response Response
	if err := xml.Unmarshal(responseBytes, &response); err != nil {
		return nil, fmt.Errorf("failed to parse SAML response: %w", err)
	}

	// Before hook
	if sp.hooks.BeforeProcessResponse != nil {
		if err := sp.hooks.BeforeProcessResponse(ctx, &response); err != nil {
			return nil, err
		}
	}

	// Validate response (simplified - production should verify signatures)
	if response.Status.StatusCode.Value != "urn:oasis:names:tc:SAML:2.0:status:Success" {
		return nil, fmt.Errorf("SAML response status: %s", response.Status.StatusCode.Value)
	}

	if response.Assertion == nil {
		return nil, fmt.Errorf("no assertion in SAML response")
	}

	// Find session by relay state
	session, err := sp.sessionStore.Get(ctx, relayState)
	if err != nil {
		if !sp.config.AllowIdPInitiated {
			return nil, fmt.Errorf("session not found and IdP-initiated SSO not allowed")
		}
		// IdP-initiated flow
	} else {
		// Verify InResponseTo matches
		if response.InResponseTo != session.RequestID {
			return nil, fmt.Errorf("InResponseTo mismatch")
		}
		defer sp.sessionStore.Delete(ctx, session.ID)
	}

	// Determine IdP
	var idp *IdPConfig
	if session != nil {
		idp, _ = sp.GetIdP(session.IdPID)
	}

	// Extract user info
	user := sp.extractUser(&response, idp)

	// After hook
	if sp.hooks.AfterProcessResponse != nil {
		sp.hooks.AfterProcessResponse(ctx, user)
	}

	// Reconcile identity
	return sp.reconcileIdentity(ctx, user, idp)
}

// extractUser extracts user information from the SAML assertion.
func (sp *ServiceProvider) extractUser(response *Response, idp *IdPConfig) *SAMLUser {
	assertion := response.Assertion
	user := &SAMLUser{
		NameID:       assertion.Subject.NameID.Value,
		NameIDFormat: assertion.Subject.NameID.Format,
		Attributes:   make(map[string][]string),
	}

	if idp != nil {
		user.IdPID = idp.ID
	}

	// Extract attributes
	for _, attr := range assertion.AttributeStatement.Attributes {
		name := attr.Name
		if attr.FriendlyName != "" {
			name = attr.FriendlyName
		}
		for _, val := range attr.Values {
			user.Attributes[name] = append(user.Attributes[name], val.Value)
		}
	}

	// Map common attributes
	if idp != nil && idp.AttributeMapping != nil {
		if emailAttr, ok := idp.AttributeMapping["email"]; ok {
			user.Email = user.GetAttribute(emailAttr)
		}
		if fnAttr, ok := idp.AttributeMapping["first_name"]; ok {
			user.FirstName = user.GetAttribute(fnAttr)
		}
		if lnAttr, ok := idp.AttributeMapping["last_name"]; ok {
			user.LastName = user.GetAttribute(lnAttr)
		}
	} else {
		// Default attribute names
		user.Email = user.GetAttribute("email")
		if user.Email == "" {
			user.Email = user.GetAttribute("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress")
		}
		user.FirstName = user.GetAttribute("firstName")
		user.LastName = user.GetAttribute("lastName")
	}

	return user
}

// reconcileIdentity finds or creates an identity for the SAML user.
func (sp *ServiceProvider) reconcileIdentity(ctx context.Context, user *SAMLUser, idp *IdPConfig) (any, error) {
	identifier := fmt.Sprintf("saml:%s:%s", user.IdPID, user.NameID)

	// Try custom user loader
	if sp.hooks.UserLoader != nil {
		ident, err := sp.hooks.UserLoader(ctx, user.NameID, user.IdPID)
		if err == nil && ident != nil {
			return ident, nil
		}
	}

	// Check for existing credential
	cred, err := sp.identityRepo.GetCredentialByIdentifier(identifier, "saml")
	if err == nil {
		return sp.identityRepo.GetIdentity(sp.factory, cred.IdentityID)
	}

	// Try custom factory
	if sp.hooks.UserFactory != nil {
		return sp.hooks.UserFactory(ctx, user)
	}

	// Create new identity
	ident := sp.factory()
	traits := identity.JSON(fmt.Sprintf(`{"email":"%s","first_name":"%s","last_name":"%s"}`,
		user.Email, user.FirstName, user.LastName))

	if ts, ok := ident.(interface{ SetTraits(identity.JSON) }); ok {
		ts.SetTraits(traits)
	}

	return ident, sp.identityRepo.CreateIdentity(ident)
}

// GetMetadata returns this SP's metadata XML.
func (sp *ServiceProvider) GetMetadata() ([]byte, error) {
	// Simplified metadata generation
	metadata := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="%s">
  <SPSSODescriptor AuthnRequestsSigned="%t" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="%s" index="0"/>
  </SPSSODescriptor>
</EntityDescriptor>`, sp.config.EntityID, sp.config.SignRequests, sp.config.ACSUrl)

	return []byte(metadata), nil
}

// ---- Helper Functions ----

// ParseIdPMetadata parses IdP metadata XML into a config.
func ParseIdPMetadata(id string, metadata []byte) (*IdPConfig, error) {
	// Simplified parsing - production should use proper XML parsing
	// This is a placeholder that would need full implementation
	return &IdPConfig{
		ID:       id,
		Metadata: metadata,
	}, nil
}

func generateID() string {
	// Use crypto/rand in production
	return fmt.Sprintf("%d", time.Now().UnixNano())
}
