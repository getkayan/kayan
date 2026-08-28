package saml

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"net/url"
	"time"
)

// StatusResponder reports that the responder could not carry out the request
// (SAML 2.0 Core section 3.2.2.2).
//
// It is what a logout response says when the sessions were not ended. A
// service provider that receives Success for a logout that did not happen
// records the user as signed out everywhere while a live session remains.
const StatusResponder = "urn:oasis:names:tc:SAML:2.0:status:Responder"

// StatusPartialLogout reports that some sessions could not be ended
// (SAML 2.0 Core section 3.7.3.2).
const StatusPartialLogout = "urn:oasis:names:tc:SAML:2.0:status:PartialLogout"

// Errors reported by the identity provider's single logout endpoint.
var (
	// ErrUnknownServiceProvider reports a logout message from an entity this
	// identity provider does not know.
	ErrUnknownServiceProvider = errors.New("saml: logout message from an unregistered service provider")

	// ErrServiceProviderNotSigned reports a registered service provider with
	// no certificate.
	//
	// A logout request that cannot be verified must not be acted on. Anyone
	// who knows a username could otherwise post one and end that user's
	// sessions across the whole federation -- a denial of service an attacker
	// can aim at a specific person, repeatedly, with no credential at all.
	ErrServiceProviderNotSigned = errors.New("saml: service provider has no certificate, so its logout requests cannot be verified")
)

// IdPLogoutInstruction is a verified logout request from a service provider.
type IdPLogoutInstruction struct {
	// RequestID is the request this response must reference.
	RequestID string

	// SPID is the registered service provider that sent it.
	SPID string

	// NameID identifies the subject whose sessions should end.
	NameID string

	// NameIDFormat is the format the service provider used.
	NameIDFormat string

	// SessionIndex names one session, or is empty when the request covers
	// every session the subject holds.
	SessionIndex string
}

// WithIdPVerifier sets the verifier for incoming service provider messages.
//
// Defaults to [NewXMLDSigVerifier], which refuses an unsigned document.
func WithIdPVerifier(v SignatureVerifier) IdPOption {
	return func(idp *IdentityProvider) { idp.verifier = v }
}

// ProcessLogoutRequest verifies a service provider's LogoutRequest and reports
// whose sessions to end.
//
// The identity provider's metadata advertises a single logout endpoint
// whenever SLOUrl is configured. Until now nothing served it, so a federation
// that read the metadata and sent logout requests received nothing back and
// reported the federation inconsistent -- the advertised-but-absent capability
// this package has shipped before.
//
// The signature is mandatory and the certificate comes from the registered
// service provider that the Issuer names. Neither is negotiable: an
// unverifiable logout request is a cross-user denial of service that needs no
// credential, and resolving the certificate any other way would let one
// registered service provider end sessions on behalf of another.
//
// The caller ends the sessions and answers with [IdentityProvider.BuildLogoutResponse].
func (idp *IdentityProvider) ProcessLogoutRequest(ctx context.Context, samlRequest string) (*IdPLogoutInstruction, error) {
	raw, err := base64.StdEncoding.DecodeString(samlRequest)
	if err != nil {
		return nil, fmt.Errorf("saml: decode LogoutRequest: %w", err)
	}

	// Parsed once without verification, only to learn which service provider
	// to look up. Nothing read here survives into a decision.
	var unverified LogoutRequest
	if err := xml.Unmarshal(raw, &unverified); err != nil {
		return nil, fmt.Errorf("saml: parse LogoutRequest: %w", err)
	}

	sp, err := idp.serviceProviderByEntityID(unverified.Issuer.Value)
	if err != nil {
		return nil, err
	}

	verified, err := idp.verify(ctx, raw, sp)
	if err != nil {
		return nil, err
	}

	// Re-parsed from the verified bytes, so nothing below came from the
	// untrusted parse above.
	var req LogoutRequest
	if err := xml.Unmarshal(verified.XML, &req); err != nil {
		return nil, fmt.Errorf("saml: parse verified LogoutRequest: %w", err)
	}
	// The verified issuer has to be the one the certificate belongs to. A
	// document signed by one service provider but claiming another's issuer
	// after verification would otherwise end that other provider's sessions.
	if req.Issuer.Value != sp.EntityID {
		return nil, fmt.Errorf("%w: signed by %q but issued as %q",
			ErrUnknownServiceProvider, sp.EntityID, req.Issuer.Value)
	}
	if err := resolveLogoutSubject(ctx, &req, idp.decrypter); err != nil {
		return nil, err
	}

	return &IdPLogoutInstruction{
		RequestID:    req.ID,
		SPID:         sp.ID,
		NameID:       req.NameID.Value,
		NameIDFormat: req.NameID.Format,
		SessionIndex: req.SessionIndex,
	}, nil
}

// BuildLogoutResponse produces the signed answer owed to a service provider
// once its logout request has been carried out.
//
// success reports whether the sessions were actually ended. A service provider
// that receives Success for a logout that did not happen records the user as
// signed out everywhere while a live session remains.
func (idp *IdentityProvider) BuildLogoutResponse(ctx context.Context, spID, inResponseTo string, success bool) ([]byte, error) {
	sp, err := idp.GetSP(spID)
	if err != nil {
		return nil, err
	}
	if idp.signer == nil {
		// An unsigned logout response is one a correct service provider
		// refuses, so producing it would report a completed logout the peer
		// then discards.
		return nil, ErrNoSigner
	}

	status := StatusSuccess
	if !success {
		status = StatusResponder
	}

	response := &LogoutResponse{
		ID:           "_" + generateID(),
		InResponseTo: inResponseTo,
		Version:      "2.0",
		IssueInstant: idp.now(),
		Destination:  sp.SLOUrl,
		Issuer:       Issuer{Value: idp.config.Issuer},
		Status:       Status{StatusCode: StatusCode{Value: status}},
	}

	raw, err := xml.Marshal(response)
	if err != nil {
		return nil, fmt.Errorf("saml: marshal LogoutResponse: %w", err)
	}
	return idp.signer.Sign(ctx, raw)
}

// BuildLogoutRequest produces a signed LogoutRequest for one service provider,
// and the redirect URL to send it on.
//
// It is how an identity-provider-initiated logout propagates: the caller ends
// its own session, then sends one of these to each service provider that holds
// a session for the subject. [IdentityProvider.LogoutTargets] lists them.
func (idp *IdentityProvider) BuildLogoutRequest(ctx context.Context, spID string, subject LogoutSubject) (string, error) {
	sp, err := idp.GetSP(spID)
	if err != nil {
		return "", err
	}
	if sp.SLOUrl == "" {
		// Returning an empty string would let a caller believe the session was
		// ended when nothing was sent.
		return "", fmt.Errorf("saml: service provider %q has no single logout endpoint", spID)
	}
	if subject.NameID == "" {
		// Some implementations read a request with no NameID as covering every
		// session they hold, so an accidentally empty subject logs out the
		// entire service provider rather than one user.
		return "", fmt.Errorf("saml: a logout request must name a subject")
	}

	request := &LogoutRequest{
		ID:           "_" + generateID(),
		Version:      "2.0",
		IssueInstant: idp.now(),
		Destination:  sp.SLOUrl,
		Issuer:       Issuer{Value: idp.config.Issuer},
		NameID:       NameID{Value: subject.NameID, Format: subject.NameIDFormat},
		SessionIndex: subject.SessionIndex,
	}

	raw, err := xml.Marshal(request)
	if err != nil {
		return "", fmt.Errorf("saml: marshal LogoutRequest: %w", err)
	}

	// DEFLATE before base64, as the HTTP-Redirect binding requires (SAML 2.0
	// Bindings section 3.4.4.1).
	encoded, err := deflateAndEncode(raw)
	if err != nil {
		return "", err
	}

	redirect, err := url.Parse(sp.SLOUrl)
	if err != nil {
		return "", fmt.Errorf("saml: parse SLO URL: %w", err)
	}
	query := redirect.Query()
	query.Set("SAMLRequest", encoded)
	redirect.RawQuery = query.Encode()
	return redirect.String(), nil
}

// LogoutTargets lists the registered service providers that can be sent a
// logout request, excluding the one named.
//
// Exclude the service provider that initiated the logout: it has already ended
// its own session, and sending it a request produces a message it must answer
// about a session that no longer exists.
//
// It lists every registration with a logout endpoint rather than only those
// holding a live session, because this library does not track which service
// providers a subject signed into -- that belongs to the caller's session
// store, and guessing would either miss sessions or wake providers needlessly.
func (idp *IdentityProvider) LogoutTargets(exceptSPID string) []*SPRegistration {
	idp.mu.RLock()
	defer idp.mu.RUnlock()

	// Each registration is indexed under both its ID and its EntityID, so the
	// map yields it twice. Without deduplication every service provider would
	// be sent two logout requests, and each would answer the second with an
	// error about a session it had just ended.
	seen := make(map[*SPRegistration]bool, len(idp.sps))
	targets := make([]*SPRegistration, 0, len(idp.sps))
	for _, sp := range idp.sps {
		if seen[sp] || sp.SLOUrl == "" {
			continue
		}
		// Excluded by either key, since the caller may hold whichever one it
		// was given.
		if sp.ID == exceptSPID || sp.EntityID == exceptSPID {
			continue
		}
		seen[sp] = true
		targets = append(targets, sp)
	}
	return targets
}

// serviceProviderByEntityID resolves a registration from an issuer value.
//
// An unknown issuer is refused rather than falling back to a default
// registration, which would let any configured certificate vouch for any
// issuer.
func (idp *IdentityProvider) serviceProviderByEntityID(entityID string) (*SPRegistration, error) {
	if entityID == "" {
		return nil, fmt.Errorf("%w: the message names no issuer", ErrUnknownServiceProvider)
	}

	idp.mu.RLock()
	defer idp.mu.RUnlock()
	for _, sp := range idp.sps {
		if sp.EntityID == entityID {
			return sp, nil
		}
	}
	return nil, fmt.Errorf("%w: %q", ErrUnknownServiceProvider, entityID)
}

// verify checks a service provider's signature against its registered
// certificate.
func (idp *IdentityProvider) verify(ctx context.Context, doc []byte, sp *SPRegistration) (*ValidatedDocument, error) {
	if sp.Certificate == nil {
		return nil, fmt.Errorf("%w: %q", ErrServiceProviderNotSigned, sp.EntityID)
	}
	verifier := idp.verifier
	if verifier == nil {
		verifier = NewXMLDSigVerifier()
	}
	return verifier.Verify(ctx, doc, []*x509.Certificate{sp.Certificate})
}

// now returns the identity provider's current time.
func (idp *IdentityProvider) now() time.Time {
	if idp.clock != nil {
		return idp.clock.Now().UTC()
	}
	return time.Now().UTC()
}
