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
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
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

	// NameIDFormat is the format this service provider asks for and
	// advertises in its metadata. Empty advertises the unspecified format.
	NameIDFormat string

	// EncryptionCertificate is the certificate identity providers should
	// encrypt assertions to. When empty, Certificate is advertised for both
	// signing and encryption, which is the common single-key deployment.
	EncryptionCertificate *x509.Certificate

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

	// ForceAuthn records that this request demanded a fresh authentication.
	//
	// It is kept here rather than re-derived from configuration because the
	// same identity provider serves ordinary logins and step-ups, and the
	// response can only be judged against what this particular request asked
	// for.
	ForceAuthn bool

	// RequestedAuthnContexts records the authentication context class
	// references this request would accept. An empty list enforces nothing.
	RequestedAuthnContexts []string
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
	XMLName                     xml.Name  `xml:"urn:oasis:names:tc:SAML:2.0:protocol AuthnRequest"`
	ID                          string    `xml:"ID,attr"`
	Version                     string    `xml:"Version,attr"`
	IssueInstant                time.Time `xml:"IssueInstant,attr"`
	Destination                 string    `xml:"Destination,attr"`
	AssertionConsumerServiceURL string    `xml:"AssertionConsumerServiceURL,attr"`
	ProtocolBinding             string    `xml:"ProtocolBinding,attr"`
	Issuer                      Issuer    `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`

	// ForceAuthn asks the identity provider to reauthenticate the subject
	// rather than answer from an existing session (SAML 2.0 Core, 3.4.1).
	// Omitted when false, which is the protocol default.
	ForceAuthn bool `xml:"ForceAuthn,attr,omitempty"`

	// IsPassive asks the identity provider not to take visible control of the
	// user interface.
	IsPassive bool `xml:"IsPassive,attr,omitempty"`

	NameIDPolicy *NameIDPolicy `xml:"urn:oasis:names:tc:SAML:2.0:protocol NameIDPolicy,omitempty"`

	// RequestedAuthnContext asks for a particular kind of authentication.
	// What comes back is checked against it; see [LoginOptions].
	RequestedAuthnContext *RequestedAuthnContext `xml:"urn:oasis:names:tc:SAML:2.0:protocol RequestedAuthnContext,omitempty"`
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

	// EncryptedAssertion carries the assertion when the identity provider
	// encrypts it. It is captured as raw XML rather than parsed: nothing in it
	// is readable until it has been decrypted, and the decrypted plaintext is
	// then verified before anything is read from it.
	EncryptedAssertion *EncryptedAssertion `xml:"urn:oasis:names:tc:SAML:2.0:assertion EncryptedAssertion"`
}

// EncryptedAssertion is an assertion the identity provider encrypted to this
// service provider's public key.
type EncryptedAssertion struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion EncryptedAssertion"`
	Raw     []byte   `xml:",innerxml"`
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

	// EncryptedID carries the name identifier when the identity provider
	// encrypts it. It is resolved into NameID after the assertion's signature
	// has been verified, never before.
	EncryptedID *EncryptedID `xml:"urn:oasis:names:tc:SAML:2.0:assertion EncryptedID"`
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
// #nosec G101 -- this is a public SAML protocol URN, not a credential.
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

// SAML 2.0 protocol and binding identifiers.
const (
	// BindingHTTPPost is the HTTP-POST binding, used for responses and
	// assertions because they exceed what a URL can carry.
	BindingHTTPPost = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"

	// BindingHTTPRedirect is the HTTP-Redirect binding, used for requests.
	BindingHTTPRedirect = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"

	// ProtocolSAML2 is the protocol a descriptor declares support for.
	ProtocolSAML2 = "urn:oasis:names:tc:SAML:2.0:protocol"

	// NameIDFormatUnspecified is advertised when no format is configured.
	NameIDFormatUnspecified = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
)

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

	verifier           SignatureVerifier
	decrypter          Decrypter
	signer             Signer
	redirectSigner     RedirectSigner
	replayCache        ReplayCache
	clock              domain.Clock
	metadataHTTPClient HTTPDoer
	metadataURLPolicy  MetadataURLPolicy

	// autoProvision allows a successful assertion for an unknown NameID to
	// create an identity. Off by default.
	autoProvision bool
}

// SPOption configures a [ServiceProvider].
type SPOption func(*ServiceProvider)

// HTTPDoer is the minimal HTTP client contract used for metadata retrieval.
type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// MetadataURLPolicy validates an IdP metadata URL before any request is made.
type MetadataURLPolicy func(*url.URL) error

const maxMetadataBytes = 2 << 20

// WithMetadataHTTPClient supplies the client used to retrieve IdP metadata.
// Its redirect policy remains the caller's responsibility.
func WithMetadataHTTPClient(client HTTPDoer) SPOption {
	return func(sp *ServiceProvider) { sp.metadataHTTPClient = client }
}

// WithMetadataURLPolicy replaces the default public-HTTPS metadata policy.
// This is useful for deployments with an explicitly trusted private IdP.
func WithMetadataURLPolicy(policy MetadataURLPolicy) SPOption {
	return func(sp *ServiceProvider) { sp.metadataURLPolicy = policy }
}

// WithSignatureVerifier replaces the signature verifier.
//
// The default requires a valid XML signature. Supply your own to verify
// through an HSM or to apply a stricter policy.
func WithSignatureVerifier(v SignatureVerifier) SPOption {
	return func(sp *ServiceProvider) { sp.verifier = v }
}

// WithDecrypter enables encrypted assertions.
//
// Without one, a response carrying an EncryptedAssertion is refused with
// [ErrNoDecrypter] rather than ignored: an encrypted assertion that silently
// yields no identity would look to the caller like a failed login, and the
// operator would have no indication their identity provider is sending
// something this service provider cannot read.
func WithDecrypter(d Decrypter) SPOption {
	return func(sp *ServiceProvider) { sp.decrypter = d }
}

// WithSPSigner sets the signer for enveloped XML-DSig signatures, used on
// outgoing LogoutResponse documents.
//
// It does NOT sign redirect-binding messages: those carry a detached signature
// in the URL query and need [WithRedirectSigner]. The two are separate because
// they sign different things, and a signer for one cannot produce the other.
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

// WithAutoProvision allows a successful assertion from a NameID with no
// existing identity to create one.
//
// It is off by default. Whether an unknown user signing in should get an
// account is a policy question, and for most deployments the answer is no —
// the identity provider decides who may authenticate, not who may exist here.
// Without it, an unknown NameID is refused with [ErrNoSuchIdentity], which the
// caller can handle by directing the user through their own onboarding.
func WithAutoProvision() SPOption {
	return func(sp *ServiceProvider) { sp.autoProvision = true }
}

// WithSPClock sets the clock used for validity windows.
// WithRedirectSigner supplies the signer for HTTP-Redirect binding messages.
//
// It is separate from [WithSPSigner] because the two sign different things:
// WithSPSigner produces an enveloped XML-DSig signature inside a document,
// while the redirect binding signs a detached octet string built from the URL
// query. A DEFLATE-compressed message has no XML left for a signature to live
// in, so one signer cannot serve both.
//
// When Config.SignRequests is set and no redirect signer is supplied, one is
// derived from Config.PrivateKey. Supply this to keep the key in an HSM.
func WithRedirectSigner(s RedirectSigner) SPOption {
	return func(sp *ServiceProvider) { sp.redirectSigner = s }
}

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
	if sp.metadataURLPolicy == nil {
		sp.metadataURLPolicy = publicMetadataURL
	}
	if sp.metadataHTTPClient == nil {
		sp.metadataHTTPClient = &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(req *http.Request, _ []*http.Request) error {
				return sp.metadataURLPolicy(req.URL)
			},
		}
	}
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
	parsed, err := url.Parse(metadataURL)
	if err != nil {
		return fmt.Errorf("saml: parse IdP metadata URL: %w", err)
	}
	if err := sp.metadataURLPolicy(parsed); err != nil {
		return fmt.Errorf("saml: IdP metadata URL refused: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return fmt.Errorf("saml: create IdP metadata request: %w", err)
	}
	resp, err := sp.metadataHTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("saml: fetch IdP metadata: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("saml: fetch IdP metadata: unexpected HTTP status %d", resp.StatusCode)
	}

	metadata, err := io.ReadAll(io.LimitReader(resp.Body, maxMetadataBytes+1))
	if err != nil {
		return fmt.Errorf("saml: read IdP metadata: %w", err)
	}
	if len(metadata) > maxMetadataBytes {
		return fmt.Errorf("saml: IdP metadata exceeds %d bytes", maxMetadataBytes)
	}

	idp, err := ParseIdPMetadata(id, metadata)
	if err != nil {
		return err
	}

	sp.RegisterIdP(idp)
	return nil
}

func publicMetadataURL(u *url.URL) error {
	if u.Scheme != "https" {
		return fmt.Errorf("HTTPS is required")
	}
	if u.Hostname() == "" || u.User != nil {
		return fmt.Errorf("URL must contain a host and no credentials")
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return fmt.Errorf("local hosts are not allowed")
	}
	if ip := net.ParseIP(host); ip != nil && (ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified()) {
		return fmt.Errorf("private or local IP addresses are not allowed")
	}
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
	return sp.InitiateLoginWith(ctx, idpID, returnURL, LoginOptions{})
}

// InitiateLoginWith starts the SAML authentication flow with per-login
// authentication options, and returns the redirect URL to the IdP.
//
// Use it for a step-up: ForceAuthn to demand a fresh authentication,
// RequestedAuthnContexts to demand a particular kind. Both are enforced when
// the response comes back -- an identity provider is free to ignore either,
// and a service provider that does not check cannot tell an honoured request
// from an ignored one.
func (sp *ServiceProvider) InitiateLoginWith(ctx context.Context, idpID string, returnURL string, options LoginOptions) (string, error) {
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

	// Applied before the BeforeAuthnRequest hook, so a deployment can still
	// override them, and recorded on the session below so the response is
	// judged against what was actually sent.
	options.applyTo(req)

	// Resolve the signer before anything is persisted. A refused login must
	// not leave a pending session behind: that would let an unauthenticated
	// caller fill the session store by repeatedly asking for a login the
	// service provider cannot actually perform.
	redirectSigner, err := sp.resolveRedirectSigner()
	if err != nil {
		return "", err
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
		RelayState: options.RelayState,
		ReturnURL:  returnURL,
		CreateTime: sp.clock.Now(),
		ExpiresAt:  sp.clock.Now().Add(sp.config.SessionTTL),
		// Read from the request rather than the options, so a
		// BeforeAuthnRequest hook that adjusted either one is what gets
		// enforced. Recording the intent instead of what was sent would let a
		// hook that cleared ForceAuthn leave the response check demanding it,
		// or -- worse -- a hook that set it leave the check absent.
		ForceAuthn: req.ForceAuthn,
	}
	if req.RequestedAuthnContext != nil {
		session.RequestedAuthnContexts = append([]string(nil), req.RequestedAuthnContext.AuthnContextClassRef...)
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

	return redirectURL(ctx, idp.SSOUrl, "SAMLRequest", encoded, session.ID, redirectSigner)
}

// resolveRedirectSigner returns the signer for outgoing redirect-binding
// requests, or nil when the deployment does not sign them.
//
// Config.SignRequests used to be read only to populate the metadata document's
// AuthnRequestsSigned attribute, so a service provider advertised signed
// requests and sent unsigned ones. An identity provider configured to require
// signatures rejected every login, and nothing on this side reported why.
//
// It now fails closed. A deployment that asks for signing and cannot sign is a
// misconfiguration the operator has to see, and the first login attempt is
// where they see it.
func (sp *ServiceProvider) resolveRedirectSigner() (RedirectSigner, error) {
	if !sp.config.SignRequests {
		return nil, nil
	}

	if sp.redirectSigner != nil {
		return sp.redirectSigner, nil
	}

	if sp.config.PrivateKey == nil {
		return nil, fmt.Errorf("%w: Config.SignRequests is set, so configure "+
			"Config.PrivateKey or supply WithRedirectSigner", ErrNoRedirectSigner)
	}

	// The metadata document publishes the signing certificate, and it is the
	// only way an identity provider learns which key to verify against. Signing
	// with a key whose certificate is not published produces requests nobody
	// can check, which fails exactly as an unsigned request does.
	if sp.config.Certificate == nil {
		return nil, fmt.Errorf("%w: Config.SignRequests is set but Config.Certificate is not, "+
			"so the metadata document would carry no key for the identity provider "+
			"to verify against", ErrNoRedirectSigner)
	}

	return NewRSARedirectSigner(sp.config.PrivateKey, sp.config.SignatureMethod)
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

	// An encrypted assertion is decrypted before verification, because the
	// signature it carries is inside the ciphertext. The decrypted plaintext
	// is then verified like any other assertion -- decrypting is not
	// authenticating, and treating a successful decryption as proof of origin
	// is the classic way to accept a forged assertion from anyone holding this
	// service provider's public key, which is published in its metadata.
	verifyBytes := responseBytes
	if envelope.EncryptedAssertion != nil {
		if sp.decrypter == nil {
			return nil, ErrNoDecrypter
		}
		plaintext, err := sp.decrypter.Decrypt(ctx, envelope.EncryptedAssertion.Raw)
		if err != nil {
			return nil, err
		}
		verifyBytes = plaintext
	}

	// Verification runs over the decrypted plaintext, and the envelope's own
	// signature is deliberately not consulted for an encrypted response. A
	// signature over the ciphertext says nothing about what the ciphertext
	// contained, so accepting one would let anybody who can encrypt to this
	// service provider -- which is anybody, the key is in the metadata --
	// substitute an assertion of their choosing inside a genuinely signed
	// envelope. The verifier refuses an unsigned document, so a decrypted
	// assertion with no signature of its own is rejected here.
	verified, err := sp.verify(ctx, verifyBytes, idp)
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

	// Resolved from the verified assertion, so the ciphertext being decrypted
	// is one the identity provider signed. Doing it earlier would decrypt
	// something nobody had vouched for, and would rewrite the document before
	// the signature over it was checked.
	if err := resolveEncryptedID(ctx, &assertion.Subject, sp.decrypter); err != nil {
		return nil, err
	}

	// Enforced against the signature-verified assertion. An AuthnStatement
	// read anywhere else says whatever the sender wanted it to say.
	if session != nil {
		if err := enforceAuthnOptions(assertion, session, session.CreateTime, sp.config.ClockSkew); err != nil {
			return nil, err
		}
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
//
// The built-in provisioning path is a convenience for the simple case. Anything
// with its own identity model should supply Hooks.UserFactory, which receives
// the whole SAMLUser including the raw attribute map.
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
	cred, err := sp.identityRepo.GetCredentialByIdentifier(ctx, identifier, "saml")
	if err == nil {
		return sp.identityRepo.GetIdentity(ctx, sp.factory, cred.IdentityID)
	}

	// No existing identity. Creating one on the strength of an assertion is
	// a policy decision — for many deployments a successful sign-on from
	// someone with no account is an error, not an invitation to open one.
	if !sp.autoProvision {
		return nil, fmt.Errorf("%w: %s", ErrNoSuchIdentity, user.NameID)
	}

	// Try custom factory
	if sp.hooks.UserFactory != nil {
		ident, err := sp.hooks.UserFactory(ctx, user)
		if err != nil {
			return nil, err
		}
		return ident, sp.linkCredential(ctx, ident, identifier)
	}

	// Create new identity. Traits are marshalled rather than formatted into a
	// JSON literal: these values come from the identity provider, and a name
	// containing a quote would otherwise break out of the string and rewrite
	// the surrounding object.
	ident := sp.factory()
	traits, err := json.Marshal(map[string]string{
		"email":      user.Email,
		"first_name": user.FirstName,
		"last_name":  user.LastName,
	})
	if err != nil {
		return nil, fmt.Errorf("saml: encoding traits: %w", err)
	}

	if ts, ok := ident.(interface{ SetTraits(identity.JSON) }); ok {
		ts.SetTraits(identity.JSON(traits))
	}

	if err := sp.identityRepo.CreateIdentity(ctx, ident); err != nil {
		return nil, err
	}

	return ident, sp.linkCredential(ctx, ident, identifier)
}

// linkCredential writes the saml: credential that the next sign-on looks up.
//
// Without it reconcileIdentity never finds what it provisioned, so every
// sign-on by the same user created another identity — the account they signed
// in as yesterday is not the one they get today, and the identity table grows
// without bound.
func (sp *ServiceProvider) linkCredential(ctx context.Context, ident any, identifier string) error {
	fi, ok := ident.(interface{ GetID() any })
	if !ok {
		// The caller's type does not expose an ID, so there is nothing to key
		// the credential on. Their UserLoader hook has to handle lookup.
		return nil
	}

	return sp.identityRepo.CreateCredential(ctx, &identity.Credential{
		IdentityID: fmt.Sprintf("%v", fi.GetID()),
		Type:       "saml",
		Identifier: identifier,
		CreatedAt:  sp.clock.Now(),
		UpdatedAt:  sp.clock.Now(),
	})
}

// GetMetadata returns this SP's metadata XML.

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

	// Extract every signing certificate, not just the first.
	//
	// An identity provider rotating its signing key publishes both the
	// outgoing and the incoming certificate for the overlap, then switches
	// which one it signs with at a moment the relying party does not choose.
	// Keeping only the first meant that at cutover every assertion failed
	// signature verification and nobody could log in -- an outage scheduled by
	// somebody else, with nothing on this side having changed.
	//
	// A KeyDescriptor with no "use" attribute is valid for both signing and
	// encryption per the SAML metadata schema, so it is accepted here; one
	// marked "encryption" is not a signing key and is skipped, because
	// accepting it would widen what the SP trusts to verify assertions.
	for _, key := range idpDesc.KeyDescriptors {
		if key.Use != "signing" && key.Use != "" {
			continue
		}
		certData, err := base64.StdEncoding.DecodeString(key.KeyInfo.X509Data.X509Certificate)
		if err != nil {
			continue
		}
		cert, err := x509.ParseCertificate(certData)
		if err != nil {
			continue
		}
		if idp.Certificate == nil {
			idp.Certificate = cert
			continue
		}
		idp.ExtraCertificates = append(idp.ExtraCertificates, cert)
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
