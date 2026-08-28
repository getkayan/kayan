package saml

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"net/url"
	"time"
)

// LogoutRequest asks a party to end a subject's session (SAML 2.0 Core
// section 3.7.1).
type LogoutRequest struct {
	XMLName      xml.Name  `xml:"urn:oasis:names:tc:SAML:2.0:protocol LogoutRequest"`
	ID           string    `xml:"ID,attr"`
	Version      string    `xml:"Version,attr"`
	IssueInstant time.Time `xml:"IssueInstant,attr"`
	Destination  string    `xml:"Destination,attr,omitempty"`
	Issuer       Issuer    `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	NameID       NameID    `xml:"urn:oasis:names:tc:SAML:2.0:assertion NameID"`

	// EncryptedID carries the subject when the identity provider encrypts it.
	// A federation that encrypts assertion name identifiers encrypts logout
	// ones too, and a service provider that could read the first but not the
	// second would authenticate users it can never sign out.
	EncryptedID *EncryptedID `xml:"urn:oasis:names:tc:SAML:2.0:assertion EncryptedID"`

	// SessionIndex names the single session to end. Omitted, the request
	// covers every session the subject holds with the recipient.
	SessionIndex string `xml:"urn:oasis:names:tc:SAML:2.0:protocol SessionIndex,omitempty"`
}

// LogoutResponse answers a [LogoutRequest] (SAML 2.0 Core section 3.7.3).
type LogoutResponse struct {
	XMLName      xml.Name  `xml:"urn:oasis:names:tc:SAML:2.0:protocol LogoutResponse"`
	ID           string    `xml:"ID,attr"`
	InResponseTo string    `xml:"InResponseTo,attr"`
	Version      string    `xml:"Version,attr"`
	IssueInstant time.Time `xml:"IssueInstant,attr"`
	Destination  string    `xml:"Destination,attr,omitempty"`
	Issuer       Issuer    `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Status       Status    `xml:"urn:oasis:names:tc:SAML:2.0:protocol Status"`
}

// LogoutSubject names whose session to end.
type LogoutSubject struct {
	// NameID identifies the subject, as it appeared in the assertion that
	// established the session.
	NameID string

	// NameIDFormat is the format of NameID, when the identity provider
	// requires it to round-trip.
	NameIDFormat string

	// SessionIndex names one session. Leave it empty to end every session the
	// subject holds at the identity provider.
	SessionIndex string
}

// LogoutInstruction is a verified request to end a local session.
type LogoutInstruction struct {
	// RequestID is the LogoutRequest's ID, which the response must echo in
	// InResponseTo.
	RequestID string

	// IdPID is the registered identity provider that sent the request.
	IdPID string

	// NameID identifies whose session to end.
	NameID string

	// SessionIndex names one session, or is empty when every session for the
	// subject is covered.
	SessionIndex string
}

// InitiateLogout builds a redirect asking an identity provider to end a
// subject's session everywhere it is signed in.
//
// The caller ends its own local session; this is the message that propagates
// that to the identity provider and, through it, to the other service
// providers in the federation.
func (sp *ServiceProvider) InitiateLogout(ctx context.Context, idpID string, subject LogoutSubject) (string, error) {
	idp, ok := sp.GetIdP(idpID)
	if !ok {
		return "", fmt.Errorf("saml: identity provider %q is not configured", idpID)
	}
	if idp.SLOUrl == "" {
		// Returning a redirect to nowhere, or an empty string, would let a
		// caller believe the session was ended federation-wide when nothing
		// was sent.
		return "", fmt.Errorf("saml: identity provider %q has no single logout endpoint", idpID)
	}
	if subject.NameID == "" {
		// Some identity providers read a request with no NameID as covering
		// every session they hold, so an accidentally empty subject is not a
		// harmless malformed message.
		return "", fmt.Errorf("saml: a logout request must name a subject")
	}

	requestID := generateID()
	if sp.hooks.IDGenerator != nil {
		requestID = sp.hooks.IDGenerator()
	}

	req := &LogoutRequest{
		ID:           "_" + requestID,
		Version:      "2.0",
		IssueInstant: sp.clock.Now().UTC(),
		Destination:  idp.SLOUrl,
		Issuer:       Issuer{Value: sp.config.EntityID},
		NameID: NameID{
			Value:  subject.NameID,
			Format: subject.NameIDFormat,
		},
		SessionIndex: subject.SessionIndex,
	}

	xmlBytes, err := xml.Marshal(req)
	if err != nil {
		return "", fmt.Errorf("saml: marshal LogoutRequest: %w", err)
	}

	// HTTP-Redirect requires DEFLATE before base64 (SAML 2.0 Bindings section
	// 3.4.4.1), the same as an AuthnRequest.
	encoded, err := deflateAndEncode(xmlBytes)
	if err != nil {
		return "", err
	}

	redirect, err := url.Parse(idp.SLOUrl)
	if err != nil {
		return "", fmt.Errorf("saml: parse SLO URL: %w", err)
	}
	query := redirect.Query()
	query.Set("SAMLRequest", encoded)
	redirect.RawQuery = query.Encode()

	return redirect.String(), nil
}

// ProcessLogoutRequest verifies an identity provider's LogoutRequest and
// reports whose session to end.
//
// The signature is required and is not optional the way an assertion's can be
// made. A LogoutRequest terminates sessions, so an unauthenticated one is a
// denial of service anybody can aim at a named user and repeat for as long as
// they keep sending it. Nothing is read from the message until the signature
// over it verifies against a registered identity provider's certificate.
//
// Ending the local session is the caller's: this returns what to end.
func (sp *ServiceProvider) ProcessLogoutRequest(ctx context.Context, samlRequest, relayState string) (*LogoutInstruction, error) {
	if sp.verifier == nil {
		return nil, ErrNoVerifier
	}

	requestBytes, err := decodeSAMLMessage(samlRequest)
	if err != nil {
		return nil, err
	}

	// Parsed once only to learn which identity provider claims to have sent
	// it, so its certificate can be selected. Nothing from this parse is
	// trusted; the verified bytes are re-parsed below.
	var claimed LogoutRequest
	if err := xml.Unmarshal(requestBytes, &claimed); err != nil {
		return nil, fmt.Errorf("saml: parse LogoutRequest: %w", err)
	}

	idpID, idp := sp.idpByEntityID(claimed.Issuer.Value)
	if idp == nil {
		// Refused before any signature check, because there is no certificate
		// to check against -- a stranger's request is not made trustworthy by
		// carrying a well-formed signature.
		return nil, fmt.Errorf("saml: no identity provider registered for issuer %q", claimed.Issuer.Value)
	}

	verified, err := sp.verify(ctx, requestBytes, idp)
	if err != nil {
		return nil, err
	}

	var req LogoutRequest
	if err := xml.Unmarshal(verified.XML, &req); err != nil {
		return nil, fmt.Errorf("saml: parse verified LogoutRequest: %w", err)
	}
	if err := resolveLogoutSubject(ctx, &req, sp.decrypter); err != nil {
		return nil, err
	}

	return &LogoutInstruction{
		RequestID:    req.ID,
		IdPID:        idpID,
		NameID:       req.NameID.Value,
		SessionIndex: req.SessionIndex,
	}, nil
}

// resolveLogoutSubject fills in a LogoutRequest's NameID, decrypting an
// EncryptedID if that is how the subject arrived.
//
// It runs on the verified request, for the same reason the assertion path
// does: the signature covers the ciphertext, so decrypting afterwards yields a
// name the identity provider actually asserted.
//
// Getting the subject wrong here ends the wrong user's session. That is a
// denial of service rather than a takeover, but it is one an attacker can aim.
func resolveLogoutSubject(ctx context.Context, req *LogoutRequest, decrypter Decrypter) error {
	if req.EncryptedID != nil {
		if req.NameID.Value != "" {
			return ErrAmbiguousNameID
		}
		if decrypter == nil {
			return fmt.Errorf("%w: the LogoutRequest carries an EncryptedID", ErrNoDecrypter)
		}
		plaintext, err := decrypter.Decrypt(ctx, req.EncryptedID.Raw)
		if err != nil {
			return err
		}
		var nameID NameID
		if err := xml.Unmarshal(plaintext, &nameID); err != nil {
			return fmt.Errorf("%w: %v", ErrEncryptedIDUnreadable, err)
		}
		req.NameID = nameID
	}

	if req.NameID.Value == "" {
		return fmt.Errorf("saml: LogoutRequest names no subject")
	}
	return nil
}

// ProcessRedirectLogoutRequest verifies a LogoutRequest that arrived over the
// HTTP-Redirect binding and reports whose session to end.
//
// It takes the raw query string rather than parsed values because the
// signature covers the octets exactly as they arrived: decoding and
// re-encoding a value usually round-trips unchanged, and where it does not the
// signature fails for a reason nobody can see. A caller has this as
// r.URL.RawQuery.
//
// [ProcessLogoutRequest] handles the POST binding, where the signature is
// enveloped in the document. The two bindings carry their signatures in
// different places, so they cannot share one verification path -- and until
// this existed, a service provider advertising a Redirect binding for single
// logout rejected every redirect-bound request it received.
//
// The signature is mandatory here for the same reason it is on the POST
// binding: a LogoutRequest ends sessions, so an unauthenticated one is a
// denial of service anybody can aim at a named user.
func (sp *ServiceProvider) ProcessRedirectLogoutRequest(ctx context.Context, rawQuery string) (*LogoutInstruction, error) {
	encoded, ok := rawQueryValue(rawQuery, "SAMLRequest")
	if !ok || encoded == "" {
		return nil, fmt.Errorf("saml: query carries no SAMLRequest")
	}
	unescaped, err := url.QueryUnescape(encoded)
	if err != nil {
		return nil, fmt.Errorf("saml: decode SAMLRequest: %w", err)
	}

	requestBytes, err := decodeSAMLMessage(unescaped)
	if err != nil {
		return nil, err
	}

	// Parsed once only to select a certificate. Nothing from this parse is
	// trusted; the message is re-parsed below, after the signature over it
	// verifies.
	var claimed LogoutRequest
	if err := xml.Unmarshal(requestBytes, &claimed); err != nil {
		return nil, fmt.Errorf("saml: parse LogoutRequest: %w", err)
	}

	idpID, idp := sp.idpByEntityID(claimed.Issuer.Value)
	if idp == nil {
		return nil, fmt.Errorf("saml: no identity provider registered for issuer %q", claimed.Issuer.Value)
	}

	var certs []*x509.Certificate
	if idp.Certificate != nil {
		certs = append(certs, idp.Certificate)
	}
	certs = append(certs, idp.ExtraCertificates...)

	if err := VerifyRedirectSignature(rawQuery, certs); err != nil {
		return nil, err
	}

	// Re-parsed from the verified bytes, so nothing read below came from the
	// untrusted parse above.
	var req LogoutRequest
	if err := xml.Unmarshal(requestBytes, &req); err != nil {
		return nil, fmt.Errorf("saml: parse verified LogoutRequest: %w", err)
	}
	if err := resolveLogoutSubject(ctx, &req, sp.decrypter); err != nil {
		return nil, err
	}

	return &LogoutInstruction{
		RequestID:    req.ID,
		IdPID:        idpID,
		NameID:       req.NameID.Value,
		SessionIndex: req.SessionIndex,
	}, nil
}

// BuildLogoutResponse produces the reply owed to an identity provider once the
// local session has been ended.
//
// status is [StatusSuccess] when the session was ended. Reporting success for
// a logout that did not happen would leave the identity provider believing the
// federation is consistent when one service provider is still signed in.
func (sp *ServiceProvider) BuildLogoutResponse(ctx context.Context, idpID, inResponseTo, status string) (string, error) {
	idp, ok := sp.GetIdP(idpID)
	if !ok {
		return "", fmt.Errorf("saml: identity provider %q is not configured", idpID)
	}
	if inResponseTo == "" {
		// Without it the identity provider cannot correlate the reply, and a
		// response matching no request is indistinguishable from a forged one.
		return "", fmt.Errorf("saml: a logout response must name the request it answers")
	}

	responseID := generateID()
	if sp.hooks.IDGenerator != nil {
		responseID = sp.hooks.IDGenerator()
	}

	resp := &LogoutResponse{
		ID:           "_" + responseID,
		InResponseTo: inResponseTo,
		Version:      "2.0",
		IssueInstant: sp.clock.Now().UTC(),
		Destination:  idp.SLOUrl,
		Issuer:       Issuer{Value: sp.config.EntityID},
		Status:       Status{StatusCode: StatusCode{Value: status}},
	}

	xmlBytes, err := xml.Marshal(resp)
	if err != nil {
		return "", fmt.Errorf("saml: marshal LogoutResponse: %w", err)
	}

	if sp.signer != nil {
		signed, err := sp.signer.Sign(ctx, xmlBytes)
		if err != nil {
			return "", fmt.Errorf("saml: sign LogoutResponse: %w", err)
		}
		xmlBytes = signed
	}

	return base64.StdEncoding.EncodeToString(xmlBytes), nil
}

// decodeSAMLMessage base64-decodes a SAML message and inflates it when it
// arrived over the HTTP-Redirect binding.
//
// The two bindings differ: Redirect DEFLATE-compresses before base64, POST
// does not. Rather than requiring the caller to say which they received, both
// are accepted -- an inflate that fails leaves the raw bytes, which is what a
// POST binding carries.
func decodeSAMLMessage(encoded string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("saml: decode message: %w", err)
	}
	if inflated, err := inflate(raw); err == nil && len(inflated) > 0 {
		return inflated, nil
	}
	return raw, nil
}

// inflateAndDecode is decodeSAMLMessage for a message known to be deflated.
func inflateAndDecode(encoded string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("saml: decode message: %w", err)
	}
	return inflate(raw)
}

// inflate reverses the DEFLATE compression the HTTP-Redirect binding applies.
func inflate(compressed []byte) ([]byte, error) {
	reader := flate.NewReader(bytes.NewReader(compressed))
	defer func() { _ = reader.Close() }()

	// Bounded so a small compressed payload cannot expand into a large
	// allocation: an unauthenticated endpoint decompresses whatever it is
	// given, which is what makes a decompression bomb reachable here.
	limited := io.LimitReader(reader, maxInflatedMessageSize+1)
	out, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("saml: inflate message: %w", err)
	}
	if len(out) > maxInflatedMessageSize {
		return nil, fmt.Errorf("saml: inflated message exceeds %d bytes", maxInflatedMessageSize)
	}
	return out, nil
}

// maxInflatedMessageSize caps what a redirect-bound message may expand to.
// Real AuthnRequests and LogoutRequests are a few kilobytes.
const maxInflatedMessageSize = 5 << 20

// idpByEntityID finds a registered identity provider by its entity ID.
func (sp *ServiceProvider) idpByEntityID(entityID string) (string, *IdPConfig) {
	if entityID == "" {
		return "", nil
	}
	sp.mu.RLock()
	defer sp.mu.RUnlock()
	for id, idp := range sp.idps {
		if idp.EntityID == entityID {
			return id, idp
		}
	}
	return "", nil
}
