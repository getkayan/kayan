package saml

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"
)

// Single Logout ends a session across every service provider an identity
// signed into. The security property that matters is that a LogoutRequest is
// authenticated: it terminates sessions, so an unauthenticated one is a denial
// of service anybody can aim at any user by name.

func logoutHarness(t *testing.T) *attackHarness {
	t.Helper()
	h := newAttackHarness(t)
	idp, _ := h.sp.GetIdP("idp1")
	idp.SLOUrl = "http://idp.example.com/slo"
	return h
}

// TestInitiateLogoutBuildsARedirect covers SP-initiated logout: the service
// provider asks the identity provider to end the session everywhere.
func TestInitiateLogoutBuildsARedirect(t *testing.T) {
	h := logoutHarness(t)

	redirect, err := h.sp.InitiateLogout(h.context, "idp1", LogoutSubject{
		NameID:       "alice@example.test",
		SessionIndex: "session-index-1",
	})
	if err != nil {
		t.Fatalf("InitiateLogout: %v", err)
	}

	parsed, err := url.Parse(redirect)
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}
	if parsed.Host != "idp.example.com" || parsed.Path != "/slo" {
		t.Errorf("redirect = %q, want the IdP's SLO endpoint", redirect)
	}

	encoded := parsed.Query().Get("SAMLRequest")
	if encoded == "" {
		t.Fatal("the redirect carries no SAMLRequest")
	}

	// The message must be DEFLATE-compressed before base64, per SAML 2.0
	// Bindings 3.4.4.1. Base64 of raw XML is rejected by real IdPs, so
	// decoding it as such is what proves the binding is right.
	raw, err := inflateAndDecode(encoded)
	if err != nil {
		t.Fatalf("decode SAMLRequest: %v", err)
	}
	var req LogoutRequest
	if err := xml.Unmarshal(raw, &req); err != nil {
		t.Fatalf("parse LogoutRequest: %v", err)
	}
	if req.NameID.Value != "alice@example.test" {
		t.Errorf("NameID = %q, want alice@example.test", req.NameID.Value)
	}
	if req.SessionIndex != "session-index-1" {
		t.Errorf("SessionIndex = %q, want session-index-1", req.SessionIndex)
	}
	if req.Destination != "http://idp.example.com/slo" {
		t.Errorf("Destination = %q, want the IdP SLO URL", req.Destination)
	}
	if req.Issuer.Value != testSPEntityID {
		t.Errorf("Issuer = %q, want this service provider", req.Issuer.Value)
	}
}

// TestInitiateLogoutRequiresAnSLOEndpoint keeps a silent no-op from looking
// like a logout. An IdP with no SLO URL cannot be asked to end anything, and
// the caller has to know that rather than believe the session was terminated.
func TestInitiateLogoutRequiresAnSLOEndpoint(t *testing.T) {
	h := newAttackHarness(t) // no SLOUrl configured

	if _, err := h.sp.InitiateLogout(h.context, "idp1", LogoutSubject{NameID: "alice@example.test"}); err == nil {
		t.Error("InitiateLogout succeeded against an IdP with no SLO endpoint")
	}
}

// TestInitiateLogoutRequiresASubject keeps a request that names nobody from
// being sent. Some identity providers read an empty NameID as "every session",
// so this is not a harmless malformed message.
func TestInitiateLogoutRequiresASubject(t *testing.T) {
	h := logoutHarness(t)

	if _, err := h.sp.InitiateLogout(h.context, "idp1", LogoutSubject{}); err == nil {
		t.Error("InitiateLogout accepted a request naming no subject")
	}
}

// TestProcessLogoutRequestRequiresASignature is the central security test.
//
// A LogoutRequest terminates sessions. If an unsigned one were honoured,
// anyone who can reach the SLO endpoint could sign out any user they can name
// -- a denial of service needing no credential, aimed at a specific person,
// repeatable for as long as they keep sending it.
func TestProcessLogoutRequestRequiresASignature(t *testing.T) {
	h := logoutHarness(t)

	unsigned := &LogoutRequest{
		ID:           "_logout-1",
		Version:      "2.0",
		IssueInstant: time.Now().UTC(),
		Destination:  testACSUrl,
		Issuer:       Issuer{Value: testIdPEntity},
		NameID:       NameID{Value: "alice@example.test"},
	}
	raw, err := xml.Marshal(unsigned)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	_, err = h.sp.ProcessLogoutRequest(h.context, base64.StdEncoding.EncodeToString(raw), "")
	if err == nil {
		t.Fatal("an unsigned LogoutRequest was accepted")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "sign") {
		t.Errorf("error = %v, want one naming the missing signature", err)
	}
}

// TestProcessLogoutRequestRejectsAnotherKeysSignature covers the same attack
// with a signature that exists but is not the identity provider's.
func TestProcessLogoutRequestRejectsAnotherKeysSignature(t *testing.T) {
	h := logoutHarness(t)
	attacker, _ := testSigner(t)

	req := &LogoutRequest{
		ID:           "_logout-1",
		Version:      "2.0",
		IssueInstant: time.Now().UTC(),
		Destination:  testACSUrl,
		Issuer:       Issuer{Value: testIdPEntity},
		NameID:       NameID{Value: "alice@example.test"},
	}
	raw, err := xml.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	signed, err := attacker.Sign(h.context, raw)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if _, err := h.sp.ProcessLogoutRequest(h.context, base64.StdEncoding.EncodeToString(signed), ""); err == nil {
		t.Error("a LogoutRequest signed by an untrusted key was accepted")
	}
}

// TestProcessLogoutRequestAcceptsASignedRequest is the positive half. Without
// it the tests above would pass against an implementation that refused
// everything.
func TestProcessLogoutRequestAcceptsASignedRequest(t *testing.T) {
	h := logoutHarness(t)

	req := &LogoutRequest{
		ID:           "_logout-1",
		Version:      "2.0",
		IssueInstant: time.Now().UTC(),
		Destination:  testACSUrl,
		Issuer:       Issuer{Value: testIdPEntity},
		NameID:       NameID{Value: "alice@example.test"},
		SessionIndex: "session-index-1",
	}
	raw, err := xml.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	signed, err := h.signer.Sign(h.context, raw)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	got, err := h.sp.ProcessLogoutRequest(h.context, base64.StdEncoding.EncodeToString(signed), "")
	if err != nil {
		t.Fatalf("ProcessLogoutRequest: %v", err)
	}
	if got.NameID != "alice@example.test" {
		t.Errorf("NameID = %q, want alice@example.test", got.NameID)
	}
	if got.SessionIndex != "session-index-1" {
		t.Errorf("SessionIndex = %q, want session-index-1", got.SessionIndex)
	}
	if got.RequestID != "_logout-1" {
		t.Errorf("RequestID = %q, want _logout-1", got.RequestID)
	}
}

// TestProcessLogoutRequestRejectsAnUnknownIssuer keeps a signed request from
// an identity provider this service provider does not federate with from
// being honoured just because it carries a valid-looking signature.
func TestProcessLogoutRequestRejectsAnUnknownIssuer(t *testing.T) {
	h := logoutHarness(t)

	req := &LogoutRequest{
		ID:           "_logout-1",
		Version:      "2.0",
		IssueInstant: time.Now().UTC(),
		Destination:  testACSUrl,
		Issuer:       Issuer{Value: "http://stranger.example.com"},
		NameID:       NameID{Value: "alice@example.test"},
	}
	raw, err := xml.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	signed, err := h.signer.Sign(h.context, raw)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	_, err = h.sp.ProcessLogoutRequest(h.context, base64.StdEncoding.EncodeToString(signed), "")
	if err == nil {
		t.Fatal("a LogoutRequest from an unregistered issuer was accepted")
	}
	// The rejection must name the unknown issuer. Falling through to signature
	// verification with no certificate happens to fail too, but for the wrong
	// reason -- and would start succeeding the moment any registered IdP's key
	// matched, which is exactly the case this guards.
	if !strings.Contains(err.Error(), "no identity provider registered") {
		t.Errorf("error = %v, want one naming the unregistered issuer", err)
	}
}

// TestBuildLogoutResponse covers the reply a service provider owes the
// identity provider once it has ended the local session.
func TestBuildLogoutResponse(t *testing.T) {
	h := logoutHarness(t)

	encoded, err := h.sp.BuildLogoutResponse(h.context, "idp1", "_logout-1", StatusSuccess)
	if err != nil {
		t.Fatalf("BuildLogoutResponse: %v", err)
	}

	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	var resp LogoutResponse
	if err := xml.Unmarshal(raw, &resp); err != nil {
		t.Fatalf("parse LogoutResponse: %v", err)
	}
	if resp.InResponseTo != "_logout-1" {
		t.Errorf("InResponseTo = %q, want _logout-1", resp.InResponseTo)
	}
	if resp.Status.StatusCode.Value != StatusSuccess {
		t.Errorf("status = %q, want success", resp.Status.StatusCode.Value)
	}
	if resp.Issuer.Value != testSPEntityID {
		t.Errorf("Issuer = %q, want this service provider", resp.Issuer.Value)
	}
}

// TestLogoutRequestWithNoVerifierIsRefused keeps a service provider that
// disabled signature verification from silently accepting logout requests
// from anyone.
func TestLogoutRequestWithNoVerifierIsRefused(t *testing.T) {
	h := logoutHarness(t)
	h.sp.verifier = nil

	if _, err := h.sp.ProcessLogoutRequest(h.context, base64.StdEncoding.EncodeToString([]byte("<x/>")), ""); !errors.Is(err, ErrNoVerifier) {
		t.Errorf("error = %v, want ErrNoVerifier", err)
	}
}

// idpSigningKey replaces the harness identity provider's certificate with a
// fresh pair and returns the private key, so a test can sign as that identity
// provider. testSigner discards the key it generates.
func idpSigningKey(t *testing.T, h *attackHarness) *rsa.PrivateKey {
	t.Helper()
	key, cert := testKeyPair(t)
	idp, ok := h.sp.GetIdP("idp1")
	if !ok {
		t.Fatal("harness has no idp1")
	}
	idp.Certificate = cert
	idp.ExtraCertificates = nil
	return key
}

// buildSignedRedirectLogout produces a redirect-bound LogoutRequest signed by
// the harness's identity provider, as an identity provider would send one.
func buildSignedRedirectLogout(t *testing.T, h *attackHarness, key *rsa.PrivateKey, nameID string) string {
	t.Helper()

	req := &LogoutRequest{
		ID: "_logout-redirect-1", Version: "2.0",
		IssueInstant: time.Now().UTC(),
		Destination:  "https://sp.example.test/slo",
		Issuer:       Issuer{Value: testIdPEntity},
		NameID:       NameID{Value: nameID},
		SessionIndex: "session-index-1",
	}
	raw, err := xml.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	encoded, err := deflateAndEncode(raw)
	if err != nil {
		t.Fatalf("deflate: %v", err)
	}

	signer, err := NewRSARedirectSigner(key, "")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	full, err := redirectURL(h.context, "https://sp.example.test/slo", "SAMLRequest", encoded, "", signer)
	if err != nil {
		t.Fatalf("build redirect: %v", err)
	}
	parsed, err := url.Parse(full)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return parsed.RawQuery
}

// TestProcessRedirectLogoutRequestAcceptsASignedRequest covers an advertised
// capability that could not work.
//
// The metadata document offers a Redirect binding for single logout, but the
// only logout entry point verified an enveloped XML-DSig signature. A
// redirect-bound message is DEFLATE-compressed and carries its signature in
// the query, so every such request was rejected with ErrUnsigned.
func TestProcessRedirectLogoutRequestAcceptsASignedRequest(t *testing.T) {
	h := logoutHarness(t)
	key := idpSigningKey(t, h)

	query := buildSignedRedirectLogout(t, h, key, "alice@example.test")

	got, err := h.sp.ProcessRedirectLogoutRequest(h.context, query)
	if err != nil {
		t.Fatalf("ProcessRedirectLogoutRequest: %v", err)
	}
	if got.NameID != "alice@example.test" {
		t.Errorf("NameID = %q, want alice@example.test", got.NameID)
	}
	if got.SessionIndex != "session-index-1" {
		t.Errorf("SessionIndex = %q, want session-index-1", got.SessionIndex)
	}
}

// TestProcessRedirectLogoutRequestRequiresASignature is the same property the
// POST binding already has: a LogoutRequest ends sessions, so an
// unauthenticated one is a denial of service aimed at a named user.
func TestProcessRedirectLogoutRequestRequiresASignature(t *testing.T) {
	h := logoutHarness(t)

	req := &LogoutRequest{
		ID: "_logout-1", Version: "2.0", IssueInstant: time.Now().UTC(),
		Issuer: Issuer{Value: testIdPEntity},
		NameID: NameID{Value: "alice@example.test"},
	}
	raw, _ := xml.Marshal(req)
	encoded, err := deflateAndEncode(raw)
	if err != nil {
		t.Fatalf("deflate: %v", err)
	}
	query := "SAMLRequest=" + url.QueryEscape(encoded)

	if _, err := h.sp.ProcessRedirectLogoutRequest(h.context, query); !errors.Is(err, ErrNoRedirectSignature) {
		t.Errorf("error = %v, want ErrNoRedirectSignature", err)
	}
}

// TestProcessRedirectLogoutRequestRejectsATamperedSubject is the test that
// matters most: the signature must actually cover the message. Verifying only
// that a Signature parameter is present and well-formed would let an attacker
// keep a genuine signature and swap the subject, logging out anybody.
func TestProcessRedirectLogoutRequestRejectsATamperedSubject(t *testing.T) {
	h := logoutHarness(t)
	key := idpSigningKey(t, h)

	query := buildSignedRedirectLogout(t, h, key, "alice@example.test")

	// Re-encode a different subject under the same, still-valid signature.
	tampered := &LogoutRequest{
		ID: "_logout-redirect-1", Version: "2.0",
		IssueInstant: time.Now().UTC(),
		Destination:  "https://sp.example.test/slo",
		Issuer:       Issuer{Value: testIdPEntity},
		NameID:       NameID{Value: "victim@example.test"},
	}
	rawXML, _ := xml.Marshal(tampered)
	swapped, err := deflateAndEncode(rawXML)
	if err != nil {
		t.Fatalf("deflate: %v", err)
	}

	sigStart := strings.Index(query, "&SigAlg=")
	if sigStart < 0 {
		t.Fatal("no SigAlg in the built query")
	}
	forged := "SAMLRequest=" + url.QueryEscape(swapped) + query[sigStart:]

	if _, err := h.sp.ProcessRedirectLogoutRequest(h.context, forged); err == nil {
		t.Error("a LogoutRequest whose subject was swapped under a valid signature was accepted")
	}
}

// TestProcessRedirectLogoutRequestRejectsAnUnknownIssuer keeps a signed
// message from an identity provider this service provider does not federate
// with from being honoured.
func TestProcessRedirectLogoutRequestRejectsAnUnknownIssuer(t *testing.T) {
	h := logoutHarness(t)
	key := idpSigningKey(t, h)

	req := &LogoutRequest{
		ID: "_logout-1", Version: "2.0", IssueInstant: time.Now().UTC(),
		Issuer: Issuer{Value: "https://stranger.example.test"},
		NameID: NameID{Value: "alice@example.test"},
	}
	raw, _ := xml.Marshal(req)
	encoded, _ := deflateAndEncode(raw)
	signer, _ := NewRSARedirectSigner(key, "")
	full, err := redirectURL(h.context, "https://sp.example.test/slo", "SAMLRequest", encoded, "", signer)
	if err != nil {
		t.Fatalf("build redirect: %v", err)
	}
	parsed, _ := url.Parse(full)

	_, err = h.sp.ProcessRedirectLogoutRequest(h.context, parsed.RawQuery)
	if err == nil {
		t.Fatal("a LogoutRequest from an unregistered issuer was accepted")
	}
	if !strings.Contains(err.Error(), "no identity provider registered") {
		t.Errorf("error = %v, want one naming the unregistered issuer", err)
	}
}
