package saml

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"net/url"

	"github.com/beevik/etree"
)

// Errors reported while parsing an incoming AuthnRequest.
var (
	// ErrAuthnRequestNotSigned reports an AuthnRequest that carries no
	// signature, from a service provider that is not allowed to send one
	// unsigned.
	//
	// An unsigned request can be forged by anyone: it names the service
	// provider it claims to come from, and nothing checks that claim. The
	// response still goes only to the registered assertion consumer service,
	// but the request's own contents -- ForceAuthn, IsPassive, the requested
	// authentication context, the request ID the response will answer -- are
	// whatever the forger chose.
	ErrAuthnRequestNotSigned = errors.New("saml: AuthnRequest is not signed")

	// ErrInvalidAuthnRequest reports an AuthnRequest that is malformed or
	// does not match the service provider's registration.
	ErrInvalidAuthnRequest = errors.New("saml: invalid AuthnRequest")

	// ErrNoSubject reports a response requested for no identity, or for one
	// that resolves to an empty NameID. An assertion naming nobody is still
	// a signed statement that someone authenticated, and a service provider
	// that maps an empty NameID to an account would sign that account in.
	ErrNoSubject = errors.New("saml: no authenticated subject for the response")
)

// maxEncodedSAMLRequest bounds the encoded SAMLRequest before any decoding.
const maxEncodedSAMLRequest = 1 << 20

// SSORequest is a validated, service-provider-initiated authentication
// request.
//
// Every value here has been checked: the issuer is a registered service
// provider, the signature verified against that provider's certificate (or
// the provider is explicitly allowed to send unsigned requests), and the
// destination, assertion consumer service, and binding agree with this
// identity provider and the registration.
//
// The caller authenticates the user -- Kayan does not own the login page --
// and then answers with [IdentityProvider.BuildResponse]. Request.ForceAuthn
// and Request.IsPassive are constraints on that sign-in; honouring them is the
// caller's part.
type SSORequest struct {
	// SP is the registered service provider that sent the request.
	SP *SPRegistration

	// Request is the AuthnRequest, parsed from the verified bytes when it was
	// signed.
	Request AuthnRequest

	// RelayState is returned to the service provider unchanged.
	RelayState string

	// Signed reports whether the request carried a signature that verified.
	Signed bool
}

// ParseRedirectAuthnRequest validates an AuthnRequest received over the
// HTTP-Redirect binding.
//
// Pass the raw query string, not url.Values: the redirect binding signs the
// URL-encoded octets as they were sent, and decoding them first can change
// the bytes the signature covers.
//
//	req, err := idp.ParseRedirectAuthnRequest(ctx, r.URL.RawQuery)
func (idp *IdentityProvider) ParseRedirectAuthnRequest(ctx context.Context, rawQuery string) (*SSORequest, error) {
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		return nil, fmt.Errorf("%w: malformed query: %w", ErrInvalidAuthnRequest, err)
	}
	if err := singleValued(values); err != nil {
		return nil, err
	}

	// The message is read from the raw query, the same octets the signature
	// is checked over. Reading it from the decoded values instead would let a
	// parameter name spelled with percent-escapes carry a message the
	// signature check never saw.
	encoded, ok := rawQueryValue(rawQuery, "SAMLRequest")
	if !ok {
		return nil, fmt.Errorf("%w: missing SAMLRequest", ErrInvalidAuthnRequest)
	}
	if len(encoded) > maxEncodedSAMLRequest {
		return nil, fmt.Errorf("%w: SAMLRequest too large", ErrInvalidAuthnRequest)
	}
	message, err := url.QueryUnescape(encoded)
	if err != nil {
		return nil, fmt.Errorf("%w: SAMLRequest encoding: %w", ErrInvalidAuthnRequest, err)
	}
	raw, err := inflateAndDecode(message)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidAuthnRequest, err)
	}

	sp, err := idp.authnRequestIssuer(raw)
	if err != nil {
		return nil, err
	}

	// The redirect binding carries its signature in the query, not the XML.
	signed := false
	if _, present := rawQueryValue(rawQuery, "Signature"); present {
		if sp.Certificate == nil {
			return nil, fmt.Errorf("%w: %q", ErrServiceProviderNotSigned, sp.EntityID)
		}
		if err := VerifyRedirectSignature(rawQuery, []*x509.Certificate{sp.Certificate}); err != nil {
			return nil, err
		}
		signed = true
	} else if !sp.AllowUnsignedAuthnRequests {
		return nil, fmt.Errorf("%w: %q", ErrAuthnRequestNotSigned, sp.EntityID)
	}

	return idp.finishAuthnRequest(ctx, sp, raw, values.Get("RelayState"), signed)
}

// ParsePostAuthnRequest validates an AuthnRequest received over the
// HTTP-POST binding.
//
//	if err := r.ParseForm(); err != nil { /* ... */ }
//	req, err := idp.ParsePostAuthnRequest(ctx, r.PostForm)
func (idp *IdentityProvider) ParsePostAuthnRequest(ctx context.Context, form url.Values) (*SSORequest, error) {
	if err := singleValued(form); err != nil {
		return nil, err
	}
	encoded := form.Get("SAMLRequest")
	if encoded == "" {
		return nil, fmt.Errorf("%w: missing SAMLRequest", ErrInvalidAuthnRequest)
	}
	if len(encoded) > maxEncodedSAMLRequest {
		return nil, fmt.Errorf("%w: SAMLRequest too large", ErrInvalidAuthnRequest)
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("%w: SAMLRequest encoding: %w", ErrInvalidAuthnRequest, err)
	}

	sp, err := idp.authnRequestIssuer(raw)
	if err != nil {
		return nil, err
	}

	signed, err := envelopedSignaturePresent(raw)
	if err != nil {
		return nil, err
	}
	if signed {
		// A signature that is present is always checked, even for a service
		// provider allowed to send unsigned requests: one that fails to verify
		// is evidence of tampering, not an absent feature.
		verified, err := idp.verify(ctx, raw, sp)
		if err != nil {
			return nil, err
		}
		raw = verified.XML
	} else if !sp.AllowUnsignedAuthnRequests {
		return nil, fmt.Errorf("%w: %q", ErrAuthnRequestNotSigned, sp.EntityID)
	}

	return idp.finishAuthnRequest(ctx, sp, raw, form.Get("RelayState"), signed)
}

// authnRequestIssuer finds the registered service provider an AuthnRequest
// names. The parse is unverified and is used for nothing else.
func (idp *IdentityProvider) authnRequestIssuer(raw []byte) (*SPRegistration, error) {
	var unverified AuthnRequest
	// #nosec G709 -- AuthnRequest is the deliberately narrow wire schema;
	// only the Issuer is read here, to choose the verification key.
	if err := xml.Unmarshal(raw, &unverified); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidAuthnRequest, err)
	}
	if unverified.Issuer.Value == "" {
		return nil, fmt.Errorf("%w: no Issuer", ErrInvalidAuthnRequest)
	}
	return idp.serviceProviderByEntityID(unverified.Issuer.Value)
}

// finishAuthnRequest parses the request from bytes that are verified, or that
// the service provider is allowed to send unverified, and checks it against
// the registration.
func (idp *IdentityProvider) finishAuthnRequest(ctx context.Context, sp *SPRegistration, raw []byte, relayState string, signed bool) (*SSORequest, error) {
	var req AuthnRequest
	// #nosec G709 -- see authnRequestIssuer.
	if err := xml.Unmarshal(raw, &req); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidAuthnRequest, err)
	}

	// The issuer read before verification chose the certificate; the one
	// read after must be the same, or a request signed by one service
	// provider would be answered as another.
	if req.Issuer.Value != sp.EntityID {
		return nil, fmt.Errorf("%w: issuer %q does not match the signing service provider %q",
			ErrInvalidAuthnRequest, req.Issuer.Value, sp.EntityID)
	}
	if err := idp.validateAuthnRequest(&req, sp, signed); err != nil {
		return nil, err
	}

	if idp.hooks.BeforeSSO != nil {
		if err := idp.hooks.BeforeSSO(ctx, sp.ID, &req); err != nil {
			return nil, err
		}
	}

	return &SSORequest{SP: sp, Request: req, RelayState: relayState, Signed: signed}, nil
}

// validateAuthnRequest checks the request's fields against this identity
// provider and the service provider's registration.
func (idp *IdentityProvider) validateAuthnRequest(req *AuthnRequest, sp *SPRegistration, signed bool) error {
	if req.ID == "" {
		return fmt.Errorf("%w: no ID", ErrInvalidAuthnRequest)
	}
	if req.Version != "2.0" {
		return fmt.Errorf("%w: unsupported Version %q", ErrInvalidAuthnRequest, req.Version)
	}

	// SAML 2.0 Bindings 3.4.5.2 and 3.5.5.2: a signed request must name its
	// destination, and the recipient must check it. Without the check, a
	// request signed for another identity provider that trusts the same
	// service provider could be replayed here.
	if signed && req.Destination == "" {
		return fmt.Errorf("%w: signed request has no Destination", ErrInvalidAuthnRequest)
	}
	if req.Destination != "" && req.Destination != idp.config.SSOUrl {
		return fmt.Errorf("%w: Destination %q is not this identity provider's SSO endpoint",
			ErrInvalidAuthnRequest, req.Destination)
	}

	// The response is only ever sent to the registered endpoint. A request
	// asking for another one is refused rather than silently redirected, so a
	// misconfigured service provider fails loudly instead of waiting for a
	// response that arrives somewhere it is not listening.
	if req.AssertionConsumerServiceURL != "" && req.AssertionConsumerServiceURL != sp.ACSUrl {
		return fmt.Errorf("%w: AssertionConsumerServiceURL is not registered for %q",
			ErrInvalidAuthnRequest, sp.EntityID)
	}
	if req.ProtocolBinding != "" && req.ProtocolBinding != BindingHTTPPost {
		return fmt.Errorf("%w: unsupported ProtocolBinding %q", ErrInvalidAuthnRequest, req.ProtocolBinding)
	}
	return nil
}

// BuildResponse produces the signed SAML response to a validated request, for
// the identity the caller has authenticated.
//
// Deliver it with [IdentityProvider.PostBindingForm] to req.SP.ACSUrl:
//
//	response, err := idp.BuildResponse(ctx, req, user)
//	form, err := idp.PostBindingForm(req.SP.ACSUrl, response, req.RelayState)
func (idp *IdentityProvider) BuildResponse(ctx context.Context, req *SSORequest, ident any) ([]byte, error) {
	if req == nil || req.SP == nil {
		return nil, errors.New("saml: BuildResponse needs a request from ParseRedirectAuthnRequest or ParsePostAuthnRequest")
	}
	if ident == nil {
		return nil, ErrNoSubject
	}

	response, nameID, err := idp.generateResponse(ctx, req.SP, ident, req.Request.ID)
	if err != nil {
		if idp.hooks.OnError != nil {
			idp.hooks.OnError(ctx, err, req.SP.ID)
		}
		return nil, err
	}
	if idp.hooks.AfterSSO != nil {
		idp.hooks.AfterSSO(ctx, req.SP.ID, nameID)
	}
	return response, nil
}

// singleValued refuses a repeated SAML binding parameter. Which copy a reader
// takes differs between parsers, and the signature check and the message
// parse must not disagree about it.
func singleValued(values url.Values) error {
	for _, name := range reservedRedirectParams {
		if len(values[name]) > 1 {
			return fmt.Errorf("%w: repeated %s parameter", ErrInvalidAuthnRequest, name)
		}
	}
	return nil
}

// envelopedSignaturePresent reports whether a POST-bound message carries an
// XML signature on its root.
func envelopedSignaturePresent(raw []byte) (bool, error) {
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(raw); err != nil {
		return false, fmt.Errorf("%w: %w", ErrInvalidAuthnRequest, err)
	}
	root := doc.Root()
	if root == nil {
		return false, fmt.Errorf("%w: empty document", ErrInvalidAuthnRequest)
	}
	return hasSignature(root), nil
}
