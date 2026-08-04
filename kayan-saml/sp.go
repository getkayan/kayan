// Package saml provides SAML 2.0 Service Provider functionality for Kayan IAM.
//
// This package implements the SAML 2.0 protocol for enterprise Single Sign-On (SSO),
// enabling integration with Identity Providers like Okta, Azure AD, and OneLogin.
// It supports SP-initiated and IdP-initiated flows with full attribute mapping.
//
// # Features
//
//   - SP-initiated SSO via HTTP-Redirect binding
//   - IdP-initiated SSO (optional, configurable)
//   - Multiple IdP support with per-IdP configuration
//   - Automatic IdP metadata parsing from URL
//   - Attribute mapping for user provisioning
//   - Session management for pending authentications
//   - Lifecycle hooks for customization
//   - SP metadata generation
//
// # SAML Flow
//
//  1. User initiates login → InitiateLogin() generates AuthnRequest
//  2. User redirects to IdP for authentication
//  3. IdP posts SAMLResponse → ProcessResponse() validates and extracts user
//  4. User is authenticated and identity is reconciled
//
// # Example Usage
//
//	sp := saml.NewServiceProvider(config, sessionStore, identityRepo, userFactory)
//
//	// Register an Identity Provider
//	sp.RegisterIdP(&saml.IdPConfig{
//	    ID:       "okta",
//	    EntityID: "https://okta.example.com",
//	    SSOUrl:   "https://okta.example.com/sso",
//	})
//
//	// Initiate login
//	redirectURL, _ := sp.InitiateLogin(ctx, "okta", "/dashboard")
//
//	// Process response (in ACS handler)
//	user, _ := sp.ProcessResponse(ctx, samlResponse, relayState)
package saml

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
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

	// ClockSkew tolerates clock differences against the identity provider when
	// checking assertion validity. Defaults to [DefaultClockSkew].
	ClockSkew time.Duration
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

	// ExtraCertificates are additional certificates accepted during a signing
	// key rollover, when the identity provider may sign with either.
	ExtraCertificates []*x509.Certificate

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
	Issuer       Issuer     `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
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
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion Assertion"`
	// ID identifies this assertion. It is required by SAML 2.0 and is what
	// makes replay detectable — an assertion with no ID cannot be tracked.
	ID                 string             `xml:"ID,attr"`
	Version            string             `xml:"Version,attr"`
	IssueInstant       time.Time          `xml:"IssueInstant,attr"`
	Issuer             Issuer             `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Subject            Subject            `xml:"urn:oasis:names:tc:SAML:2.0:assertion Subject"`
	Conditions         Conditions         `xml:"urn:oasis:names:tc:SAML:2.0:assertion Conditions"`
	AuthnStatement     *AuthnStatement    `xml:"urn:oasis:names:tc:SAML:2.0:assertion AuthnStatement,omitempty"`
	AttributeStatement AttributeStatement `xml:"urn:oasis:names:tc:SAML:2.0:assertion AttributeStatement"`
}

// AuthnStatement records how and when the subject authenticated.
type AuthnStatement struct {
	AuthnInstant time.Time     `xml:"AuthnInstant,attr"`
	SessionIndex string        `xml:"SessionIndex,attr,omitempty"`
	AuthnContext *AuthnContext `xml:"urn:oasis:names:tc:SAML:2.0:assertion AuthnContext,omitempty"`
}

// AuthnContext describes the authentication method used.
type AuthnContext struct {
	AuthnContextClassRef string `xml:"urn:oasis:names:tc:SAML:2.0:assertion AuthnContextClassRef,omitempty"`
}

// Subject contains the NameID.
type Subject struct {
	NameID NameID `xml:"urn:oasis:names:tc:SAML:2.0:assertion NameID"`
	// SubjectConfirmations bind the assertion to a recipient and a moment in
	// time. Without them a captured assertion can be delivered to any endpoint.
	SubjectConfirmations []SubjectConfirmation `xml:"urn:oasis:names:tc:SAML:2.0:assertion SubjectConfirmation"`
}

// SubjectConfirmation states how the subject is confirmed.
type SubjectConfirmation struct {
	Method                  string                  `xml:"Method,attr"`
	SubjectConfirmationData SubjectConfirmationData `xml:"urn:oasis:names:tc:SAML:2.0:assertion SubjectConfirmationData"`
}

// SubjectConfirmationData scopes a confirmation to one recipient and window.
type SubjectConfirmationData struct {
	Recipient    string    `xml:"Recipient,attr,omitempty"`
	NotOnOrAfter time.Time `xml:"NotOnOrAfter,attr,omitempty"`
	InResponseTo string    `xml:"InResponseTo,attr,omitempty"`
}

// ConfirmationMethodBearer is the bearer confirmation method used by web SSO.
const ConfirmationMethodBearer = "urn:oasis:names:tc:SAML:2.0:cm:bearer"

// NameID represents the user identifier.
type NameID struct {
	Value  string `xml:",chardata"`
	Format string `xml:"Format,attr"`
}

// Conditions for assertion validity.
type Conditions struct {
	NotBefore    time.Time `xml:"NotBefore,attr"`
	NotOnOrAfter time.Time `xml:"NotOnOrAfter,attr"`
	// AudienceRestrictions name the service providers this assertion was
	// minted for. Without checking them, an assertion issued to one service is
	// accepted by another.
	AudienceRestrictions []AudienceRestriction `xml:"urn:oasis:names:tc:SAML:2.0:assertion AudienceRestriction"`
}

// AudienceRestriction limits which service providers may accept an assertion.
type AudienceRestriction struct {
	Audiences []string `xml:"urn:oasis:names:tc:SAML:2.0:assertion Audience"`
}

// allowsAudience reports whether the conditions permit the given audience.
//
// Conditions with no AudienceRestriction permit any audience, per SAML 2.0
// section 2.5.1.4; a service provider that requires one should reject the
// assertion before reaching here.
func (c Conditions) allowsAudience(audience string) bool {
	if len(c.AudienceRestrictions) == 0 {
		return false
	}
	for _, restriction := range c.AudienceRestrictions {
		for _, candidate := range restriction.Audiences {
			if candidate == audience {
				return true
			}
		}
	}
	return false
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
	mu           sync.RWMutex
	idps         map[string]*IdPConfig
	sessionStore SessionStore
	identityRepo domain.IdentityStorage
	factory      func() any
	hooks        Hooks

	verifier    SignatureVerifier
	signer      Signer
	replayCache ReplayCache
	clock       domain.Clock
}

// SPOption configures a [ServiceProvider].
type SPOption func(*ServiceProvider)

// WithSignatureVerifier replaces the signature verifier.
//
// The default requires a valid XML signature. Supply your own to verify
// through an HSM or to apply a stricter policy.
func WithSignatureVerifier(v SignatureVerifier) SPOption {
	return func(sp *ServiceProvider) { sp.verifier = v }
}

// WithSPSigner sets the signer used for outgoing AuthnRequests.
func WithSPSigner(s Signer) SPOption {
	return func(sp *ServiceProvider) { sp.signer = s }
}

// WithReplayCache replaces the assertion replay cache.
//
// The default is in-process, which is correct for a single instance. Several
// replicas each keep their own, so an assertion can be replayed once per
// replica — use a shared cache in that case.
func WithReplayCache(c ReplayCache) SPOption {
	return func(sp *ServiceProvider) { sp.replayCache = c }
}

// WithSPClock sets the clock used for validity windows.
func WithSPClock(c domain.Clock) SPOption {
	return func(sp *ServiceProvider) { sp.clock = c }
}

// NewServiceProvider creates a new SAML SP.
func NewServiceProvider(
	config Config,
	sessionStore SessionStore,
	identityRepo domain.IdentityStorage,
	factory func() any,
	opts ...SPOption,
) *ServiceProvider {
	if config.SessionTTL == 0 {
		config.SessionTTL = 5 * time.Minute
	}

	sp := &ServiceProvider{
		config:       config,
		idps:         make(map[string]*IdPConfig),
		sessionStore: sessionStore,
		identityRepo: identityRepo,
		factory:      factory,
	}
	for _, opt := range opts {
		opt(sp)
	}

	sp.clock = domain.ClockOrDefault(sp.clock)
	if sp.verifier == nil {
		// Signature verification is the only thing authenticating an
		// assertion, so it is on by default and must be opted out of
		// explicitly through WithSignatureVerifier.
		sp.verifier = NewXMLDSigVerifier()
	}
	if sp.replayCache == nil {
		sp.replayCache = NewMemoryReplayCache(sp.clock)
	}
	return sp
}

// SetHooks sets lifecycle hooks.
func (sp *ServiceProvider) SetHooks(hooks Hooks) {
	sp.hooks = hooks
}

// RegisterIdP adds an Identity Provider configuration.
func (sp *ServiceProvider) RegisterIdP(idp *IdPConfig) {
	sp.mu.Lock()
	defer sp.mu.Unlock()
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
func (sp *ServiceProvider) GetIdP(id string) (*IdPConfig, bool) {
	sp.mu.RLock()
	defer sp.mu.RUnlock()
	idp, ok := sp.idps[id]
	return idp, ok
}

// InitiateLogin starts the SAML authentication flow.
// Returns the redirect URL to the IdP.
func (sp *ServiceProvider) InitiateLogin(ctx context.Context, idpID string, returnURL string) (string, error) {
	idp, ok := sp.GetIdP(idpID)
	if !ok {
		return "", fmt.Errorf("saml: identity provider %q is not configured", idpID)
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

	// HTTP-Redirect binding. The message must be DEFLATE-compressed before
	// base64 encoding (SAML 2.0 Bindings section 3.4.4.1); base64 of the raw
	// XML is rejected by real identity providers.
	encoded, err := deflateAndEncode(xmlBytes)
	if err != nil {
		return "", err
	}

	redirect, err := url.Parse(idp.SSOUrl)
	if err != nil {
		return "", fmt.Errorf("saml: parse SSO URL: %w", err)
	}
	query := redirect.Query()
	query.Set("SAMLRequest", encoded)
	query.Set("RelayState", session.ID)
	redirect.RawQuery = query.Encode()

	return redirect.String(), nil
}

// deflateAndEncode compresses a SAML message for the HTTP-Redirect binding.
func deflateAndEncode(message []byte) (string, error) {
	var buf bytes.Buffer
	writer, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		return "", fmt.Errorf("saml: create deflate writer: %w", err)
	}
	if _, err := writer.Write(message); err != nil {
		return "", fmt.Errorf("saml: deflate message: %w", err)
	}
	if err := writer.Close(); err != nil {
		return "", fmt.Errorf("saml: finish deflate: %w", err)
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

// maxDecodedMessageSize bounds a decompressed SAML message.
//
// DEFLATE can expand a small payload enormously, so an unbounded read is a
// denial-of-service vector on an unauthenticated endpoint.
const maxDecodedMessageSize = 5 << 20 // 5 MiB

// ParseRedirectBinding decodes a SAML message from HTTP-Redirect query
// parameters.
//
// It is transport-neutral: pass url.Values from wherever the request arrived.
// Kayan does not read from an *http.Request or write to a ResponseWriter.
func ParseRedirectBinding(values url.Values, parameter string) ([]byte, error) {
	raw := values.Get(parameter)
	if raw == "" {
		return nil, fmt.Errorf("saml: %s parameter is missing", parameter)
	}

	compressed, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("saml: decode %s: %w", parameter, err)
	}

	reader := flate.NewReader(bytes.NewReader(compressed))
	defer reader.Close()

	message, err := io.ReadAll(io.LimitReader(reader, maxDecodedMessageSize+1))
	if err != nil {
		return nil, fmt.Errorf("saml: inflate %s: %w", parameter, err)
	}
	if len(message) > maxDecodedMessageSize {
		return nil, fmt.Errorf("saml: %s exceeds %d bytes when decompressed", parameter, maxDecodedMessageSize)
	}
	return message, nil
}

// ParsePostBinding decodes a SAML message from HTTP-POST form values.
func ParsePostBinding(values url.Values, parameter string) ([]byte, error) {
	raw := values.Get(parameter)
	if raw == "" {
		return nil, fmt.Errorf("saml: %s parameter is missing", parameter)
	}

	message, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("saml: decode %s: %w", parameter, err)
	}
	if len(message) > maxDecodedMessageSize {
		return nil, fmt.Errorf("saml: %s exceeds %d bytes", parameter, maxDecodedMessageSize)
	}
	return message, nil
}

// ProcessResponse handles the SAML response from the IdP and returns the
// authenticated identity.
//
// The signature is verified before anything is trusted, and every claim is
// read from the verified element rather than from the received document. That
// ordering is what defeats XML Signature Wrapping: an attacker who wraps a
// legitimately signed assertion around injected content cannot have the
// injected content read, because the unverified tree is never parsed for
// claims.
func (sp *ServiceProvider) ProcessResponse(ctx context.Context, samlResponse, relayState string) (any, error) {
	responseBytes, err := base64.StdEncoding.DecodeString(samlResponse)
	if err != nil {
		return nil, fmt.Errorf("saml: decode response: %w", err)
	}

	// The envelope is parsed only to read routing fields — the relay state
	// correlation and the status code. Nothing from it reaches the identity.
	var envelope Response
	if err := xml.Unmarshal(responseBytes, &envelope); err != nil {
		return nil, fmt.Errorf("saml: parse response: %w", err)
	}

	if sp.hooks.BeforeProcessResponse != nil {
		if err := sp.hooks.BeforeProcessResponse(ctx, &envelope); err != nil {
			return nil, err
		}
	}

	if envelope.Status.StatusCode.Value != StatusSuccess {
		return nil, fmt.Errorf("saml: response status %s", envelope.Status.StatusCode.Value)
	}

	// Correlate with the request this service provider made, so the identity
	// provider is known before its certificate is used to verify anything.
	session, err := sp.sessionStore.Get(ctx, relayState)
	if err != nil || session == nil {
		if !sp.config.AllowIdPInitiated {
			return nil, fmt.Errorf("%w: no pending request matches this response", ErrUnsolicited)
		}
		session = nil
	} else {
		if !session.ExpiresAt.IsZero() && !sp.clock.Now().Before(session.ExpiresAt) {
			_ = sp.sessionStore.Delete(ctx, session.ID)
			return nil, fmt.Errorf("saml: authentication request expired")
		}
		defer func() { _ = sp.sessionStore.Delete(ctx, session.ID) }()
	}

	idp, err := sp.resolveIdP(session, &envelope)
	if err != nil {
		return nil, err
	}

	verified, err := sp.verify(ctx, responseBytes, idp)
	if err != nil {
		return nil, err
	}

	// Parse the assertion from the verified bytes only.
	assertion, verifiedResponse, err := parseVerified(verified)
	if err != nil {
		return nil, err
	}

	expectedInResponseTo := ""
	if session != nil {
		expectedInResponseTo = session.RequestID
	}

	opts := ValidationOptions{
		Audience:             sp.config.EntityID,
		Destination:          sp.config.ACSUrl,
		ExpectedInResponseTo: expectedInResponseTo,
		AllowUnsolicited:     sp.config.AllowIdPInitiated,
		ClockSkew:            sp.config.ClockSkew,
	}
	if idp != nil {
		opts.ExpectedIssuer = idp.EntityID
	}

	// The envelope's own attributes — Destination, InResponseTo, Issuer — are
	// only trustworthy when the signature covered the Response. When just the
	// assertion was signed, the SubjectConfirmationData inside it carries the
	// equivalent bindings and is what validation relies on instead.
	envelopeForValidation := verifiedResponse
	if envelopeForValidation == nil && verified.CoveredResponse {
		envelopeForValidation = &envelope
	}

	if err := validateAssertion(ctx, assertion, envelopeForValidation, opts, sp.clock, sp.replayCache); err != nil {
		return nil, err
	}

	user := sp.extractUser(assertion, idp)

	if sp.hooks.AfterProcessResponse != nil {
		sp.hooks.AfterProcessResponse(ctx, user)
	}

	return sp.reconcileIdentity(ctx, user, idp)
}

// StatusSuccess is the SAML status code for a successful response.
const StatusSuccess = "urn:oasis:names:tc:SAML:2.0:status:Success"

// resolveIdP determines which identity provider a response came from.
//
// For a solicited response the identity provider is known from the pending
// session. For an unsolicited one it is resolved by issuer, and an unknown
// issuer is refused rather than falling back to a default — otherwise any
// configured certificate could vouch for any issuer.
func (sp *ServiceProvider) resolveIdP(session *Session, envelope *Response) (*IdPConfig, error) {
	if session != nil {
		idp, ok := sp.GetIdP(session.IdPID)
		if !ok {
			return nil, fmt.Errorf("saml: identity provider %q is no longer configured", session.IdPID)
		}
		return idp, nil
	}

	issuer := envelope.Issuer.Value
	if issuer == "" {
		return nil, fmt.Errorf("%w: response has no issuer", ErrWrongIssuer)
	}

	sp.mu.RLock()
	defer sp.mu.RUnlock()
	for _, candidate := range sp.idps {
		if candidate.EntityID == issuer {
			return candidate, nil
		}
	}
	return nil, fmt.Errorf("%w: unknown issuer %q", ErrWrongIssuer, issuer)
}

// verify checks the signature against the identity provider's certificates.
func (sp *ServiceProvider) verify(ctx context.Context, doc []byte, idp *IdPConfig) (*ValidatedDocument, error) {
	if sp.verifier == nil {
		return nil, ErrNoVerifier
	}

	var certs []*x509.Certificate
	if idp != nil {
		if idp.Certificate != nil {
			certs = append(certs, idp.Certificate)
		}
		certs = append(certs, idp.ExtraCertificates...)
	}

	verified, err := sp.verifier.Verify(ctx, doc, certs)
	if err != nil {
		return nil, err
	}
	return verified, nil
}

// parseVerified unmarshals an assertion from verified bytes.
//
// It returns the enclosing response as well when the signature covered the
// response, so validation can trust the envelope's attributes too.
func parseVerified(verified *ValidatedDocument) (*Assertion, *Response, error) {
	if verified.SignedAssertion {
		var assertion Assertion
		if err := xml.Unmarshal(verified.XML, &assertion); err != nil {
			return nil, nil, fmt.Errorf("saml: parse verified assertion: %w", err)
		}
		return &assertion, nil, nil
	}

	var response Response
	if err := xml.Unmarshal(verified.XML, &response); err != nil {
		return nil, nil, fmt.Errorf("saml: parse verified response: %w", err)
	}
	if response.Assertion == nil {
		return nil, nil, fmt.Errorf("saml: verified response carries no assertion")
	}
	return response.Assertion, &response, nil
}

// extractUser extracts user information from the SAML assertion.
// extractUser reads user information from a verified assertion.
//
// It deliberately takes an *Assertion rather than a *Response: the signed
// element is the only thing that may contribute identity claims, and taking
// the envelope here would make it possible to read unverified content.
func (sp *ServiceProvider) extractUser(assertion *Assertion, idp *IdPConfig) *SAMLUser {
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
	var entityDesc EntityDescriptor
	if err := xml.Unmarshal(metadata, &entityDesc); err != nil {
		return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
	}

	idp := &IdPConfig{
		ID:       id,
		Metadata: metadata,
		EntityID: entityDesc.EntityID,
	}

	// Find IDPSSODescriptor
	var idpDesc *IDPSSODescriptor
	for _, role := range entityDesc.RoleDescriptors {
		if desc, ok := role.(*IDPSSODescriptor); ok {
			idpDesc = desc
			break
		}
	}
	// Fallback to searching specific element if unmarshaling interface failed
	if idpDesc == nil {
		// Simplified: assumes the structured binding worked or we implement a custom unmarshaler.
		// For this implementation, we'll define explicit struct fields for common descriptors.
		// See EntityDescriptor struct definition below.
		if entityDesc.IDPSSODescriptor != nil {
			idpDesc = entityDesc.IDPSSODescriptor
		}
	}

	if idpDesc == nil {
		return nil, fmt.Errorf("no IDPSSODescriptor found in metadata")
	}

	// Extract SSO URL (HTTP-Redirect favored)
	for _, sso := range idpDesc.SingleSignOnService {
		if sso.Binding == "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" {
			idp.SSOUrl = sso.Location
			break
		}
	}
	if idp.SSOUrl == "" && len(idpDesc.SingleSignOnService) > 0 {
		idp.SSOUrl = idpDesc.SingleSignOnService[0].Location
	}

	// Extract Certificate
	for _, key := range idpDesc.KeyDescriptors {
		if key.Use == "signing" || key.Use == "" {
			certData, err := base64.StdEncoding.DecodeString(key.KeyInfo.X509Data.X509Certificate)
			if err != nil {
				continue
			}
			cert, err := x509.ParseCertificate(certData)
			if err != nil {
				continue
			}
			idp.Certificate = cert
			break
		}
	}

	return idp, nil
}

// ---- Metadata Types ----

type EntityDescriptor struct {
	XMLName          xml.Name          `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntityDescriptor"`
	EntityID         string            `xml:"entityID,attr"`
	IDPSSODescriptor *IDPSSODescriptor `xml:"urn:oasis:names:tc:SAML:2.0:metadata IDPSSODescriptor"`
	RoleDescriptors  []interface{}     `xml:"-"` // Placeholder for generic access
}

type IDPSSODescriptor struct {
	XMLName             xml.Name              `xml:"urn:oasis:names:tc:SAML:2.0:metadata IDPSSODescriptor"`
	KeyDescriptors      []KeyDescriptor       `xml:"KeyDescriptor"`
	SingleSignOnService []SingleSignOnService `xml:"SingleSignOnService"`
}

type KeyDescriptor struct {
	Use     string  `xml:"use,attr"`
	KeyInfo KeyInfo `xml:"http://www.w3.org/2000/09/xmldsig# KeyInfo"`
}

type KeyInfo struct {
	X509Data X509Data `xml:"http://www.w3.org/2000/09/xmldsig# X509Data"`
}

type X509Data struct {
	X509Certificate string `xml:"http://www.w3.org/2000/09/xmldsig# X509Certificate"`
}

type SingleSignOnService struct {
	Binding  string `xml:"Binding,attr"`
	Location string `xml:"Location,attr"`
}

func generateID() string {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		// Fallback for extreme cases, though rand.Read should usually succeed
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}
