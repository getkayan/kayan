package saml

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"strings"
	"testing"
	"time"
)

const (
	sloSPEntity = "http://sp.example.com"
	sloSPSLOUrl = "http://sp.example.com/slo"
)

// sloIdP returns an identity provider with one service provider registered for
// single logout, plus a signer that stands in for that service provider.
func sloIdP(t *testing.T) (*IdentityProvider, Signer, *x509.Certificate) {
	t.Helper()

	idpSigner, _ := testSigner(t)
	spSigner, spCert := testSigner(t)

	idp := NewIdentityProvider(IdPServerConfig{
		EntityID: "http://idp.example.com",
		SSOUrl:   "http://idp.example.com/sso",
		SLOUrl:   "http://idp.example.com/slo",
	}, nil, nil, WithIdPSigner(idpSigner))

	idp.RegisterSP(&SPRegistration{
		ID:          "sp1",
		EntityID:    sloSPEntity,
		ACSUrl:      "http://sp.example.com/acs",
		SLOUrl:      sloSPSLOUrl,
		Certificate: spCert,
	})

	return idp, spSigner, spCert
}

// spLogoutRequest builds a LogoutRequest as a service provider would.
func spLogoutRequest(nameID string) LogoutRequest {
	return LogoutRequest{
		ID:           "_sp-logout-1",
		Version:      "2.0",
		IssueInstant: time.Now().UTC(),
		Destination:  "http://idp.example.com/slo",
		Issuer:       Issuer{Value: sloSPEntity},
		NameID:       NameID{Value: nameID},
		SessionIndex: "session-42",
	}
}

// signLogout marshals and signs a logout request.
func signLogout(t *testing.T, signer Signer, request LogoutRequest) string {
	t.Helper()
	raw, err := xml.Marshal(request)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	signed, err := signer.Sign(context.Background(), raw)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return base64.StdEncoding.EncodeToString(signed)
}

// TestIdPProcessesASignedLogoutRequest is the capability the metadata already
// advertised.
//
// IdP metadata declares a SingleLogoutService whenever SLOUrl is configured,
// and nothing served it. A federation that read that metadata and sent logout
// requests got no answer and reported the federation inconsistent.
func TestIdPProcessesASignedLogoutRequest(t *testing.T) {
	idp, spSigner, _ := sloIdP(t)

	instruction, err := idp.ProcessLogoutRequest(context.Background(),
		signLogout(t, spSigner, spLogoutRequest("victim@example.com")))
	if err != nil {
		t.Fatalf("ProcessLogoutRequest: %v", err)
	}

	if instruction.SPID != "sp1" {
		t.Errorf("SPID = %q, want sp1", instruction.SPID)
	}
	if instruction.NameID != "victim@example.com" {
		t.Errorf("NameID = %q", instruction.NameID)
	}
	if instruction.SessionIndex != "session-42" {
		t.Errorf("SessionIndex = %q", instruction.SessionIndex)
	}
	if instruction.RequestID != "_sp-logout-1" {
		t.Errorf("RequestID = %q, want the value the response must reference", instruction.RequestID)
	}
}

// TestUnsignedLogoutRequestIsRefused is the central security test.
//
// A logout request that is acted on without verification is a denial of
// service anyone can aim at a named person: knowing a username is enough to
// end their sessions across the whole federation, repeatedly, with no
// credential at all.
func TestUnsignedLogoutRequestIsRefused(t *testing.T) {
	idp, _, _ := sloIdP(t)

	raw, err := xml.Marshal(spLogoutRequest("victim@example.com"))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	instruction, err := idp.ProcessLogoutRequest(context.Background(),
		base64.StdEncoding.EncodeToString(raw))
	if err == nil {
		t.Fatal("an unsigned logout request was acted on")
	}
	if instruction != nil {
		t.Error("an instruction was returned alongside the error")
	}
}

// TestLogoutRequestSignedByAnotherPartyIsRefused. The certificate has to be
// the registered one for the issuer named. Any other resolution lets one
// certificate vouch for any issuer.
func TestLogoutRequestSignedByAnotherPartyIsRefused(t *testing.T) {
	idp, _, _ := sloIdP(t)
	stranger, _ := testSigner(t)

	instruction, err := idp.ProcessLogoutRequest(context.Background(),
		signLogout(t, stranger, spLogoutRequest("victim@example.com")))
	if err == nil {
		t.Fatal("a logout request signed by an unregistered key was acted on")
	}
	if instruction != nil {
		t.Error("an instruction was returned alongside the error")
	}
}

// TestLogoutRequestFromAnUnknownIssuerIsRefused. An unknown issuer must not
// fall back to a default registration, which would let any configured
// certificate vouch for any entity.
func TestLogoutRequestFromAnUnknownIssuerIsRefused(t *testing.T) {
	idp, spSigner, _ := sloIdP(t)

	request := spLogoutRequest("victim@example.com")
	request.Issuer = Issuer{Value: "http://stranger.example.com"}

	_, err := idp.ProcessLogoutRequest(context.Background(), signLogout(t, spSigner, request))
	if !errors.Is(err, ErrUnknownServiceProvider) {
		t.Errorf("error = %v, want ErrUnknownServiceProvider", err)
	}
}

// TestServiceProviderWithoutACertificateIsRefused.
//
// Certificate is optional on a registration, which is fine for a service
// provider that never signs anything. A logout request from one cannot be
// verified, and acting on it anyway is the unauthenticated cross-user logout
// this endpoint must not offer.
func TestServiceProviderWithoutACertificateIsRefused(t *testing.T) {
	idp, spSigner, _ := sloIdP(t)
	idp.RegisterSP(&SPRegistration{
		ID:       "sp2",
		EntityID: "http://unsigned.example.com",
		ACSUrl:   "http://unsigned.example.com/acs",
		SLOUrl:   "http://unsigned.example.com/slo",
	})

	request := spLogoutRequest("victim@example.com")
	request.Issuer = Issuer{Value: "http://unsigned.example.com"}

	_, err := idp.ProcessLogoutRequest(context.Background(), signLogout(t, spSigner, request))
	if !errors.Is(err, ErrServiceProviderNotSigned) {
		t.Errorf("error = %v, want ErrServiceProviderNotSigned", err)
	}
}

// TestLogoutResponseIsSigned. A service provider that follows the
// specification refuses an unsigned logout response, so producing one would
// report a completed logout the peer then discards.
func TestLogoutResponseIsSigned(t *testing.T) {
	idp, _, _ := sloIdP(t)

	raw, err := idp.BuildLogoutResponse(context.Background(), "sp1", "_sp-logout-1", true)
	if err != nil {
		t.Fatalf("BuildLogoutResponse: %v", err)
	}
	if !strings.Contains(string(raw), "SignatureValue") {
		t.Errorf("the logout response carries no signature: %s", raw)
	}

	var response LogoutResponse
	if err := xml.Unmarshal(raw, &response); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if response.InResponseTo != "_sp-logout-1" {
		t.Errorf("InResponseTo = %q, want the request it answers", response.InResponseTo)
	}
	if response.Status.StatusCode.Value != StatusSuccess {
		t.Errorf("status = %q, want Success", response.Status.StatusCode.Value)
	}
	if response.Destination != sloSPSLOUrl {
		t.Errorf("Destination = %q, want the service provider's logout endpoint", response.Destination)
	}
}

// TestFailedLogoutIsNotReportedAsSuccess.
//
// A service provider that receives Success for a logout that did not happen
// records the user as signed out everywhere while a live session remains --
// the worst possible outcome for the one operation whose entire purpose is
// ending sessions.
func TestFailedLogoutIsNotReportedAsSuccess(t *testing.T) {
	idp, _, _ := sloIdP(t)

	raw, err := idp.BuildLogoutResponse(context.Background(), "sp1", "_sp-logout-1", false)
	if err != nil {
		t.Fatalf("BuildLogoutResponse: %v", err)
	}

	var response LogoutResponse
	if err := xml.Unmarshal(raw, &response); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if response.Status.StatusCode.Value == StatusSuccess {
		t.Error("a failed logout was reported as Success")
	}
	if response.Status.StatusCode.Value != StatusResponder {
		t.Errorf("status = %q, want Responder", response.Status.StatusCode.Value)
	}
}

// TestIdPInitiatedLogoutRequest covers propagation: the identity provider ends
// its own session and tells each service provider to do the same.
func TestIdPInitiatedLogoutRequest(t *testing.T) {
	idp, _, _ := sloIdP(t)

	redirect, err := idp.BuildLogoutRequest(context.Background(), "sp1",
		LogoutSubject{NameID: "victim@example.com", SessionIndex: "session-42"})
	if err != nil {
		t.Fatalf("BuildLogoutRequest: %v", err)
	}
	if !strings.HasPrefix(redirect, sloSPSLOUrl) {
		t.Errorf("redirect = %q, want it addressed to the service provider", redirect)
	}

	request := decodeLogoutRequest(t, redirect)
	if request.NameID.Value != "victim@example.com" {
		t.Errorf("NameID = %q", request.NameID.Value)
	}
	if request.SessionIndex != "session-42" {
		t.Errorf("SessionIndex = %q", request.SessionIndex)
	}
	if request.Destination != sloSPSLOUrl {
		t.Errorf("Destination = %q", request.Destination)
	}
}

// TestLogoutRequestWithNoSubjectIsRefused.
//
// Some implementations read a request with no NameID as covering every session
// they hold. An accidentally empty subject would sign out the entire service
// provider rather than one user.
func TestLogoutRequestWithNoSubjectIsRefused(t *testing.T) {
	idp, _, _ := sloIdP(t)

	if _, err := idp.BuildLogoutRequest(context.Background(), "sp1", LogoutSubject{}); err == nil {
		t.Fatal("a logout request naming no subject was built")
	}
}

// TestLogoutRequestToASPWithNoEndpointIsRefused. Returning an empty string
// would let a caller believe the session was ended when nothing was sent.
func TestLogoutRequestToASPWithNoEndpointIsRefused(t *testing.T) {
	idp, _, _ := sloIdP(t)
	idp.RegisterSP(&SPRegistration{
		ID:       "sp-no-slo",
		EntityID: "http://nologout.example.com",
		ACSUrl:   "http://nologout.example.com/acs",
	})

	redirect, err := idp.BuildLogoutRequest(context.Background(), "sp-no-slo",
		LogoutSubject{NameID: "victim@example.com"})
	if err == nil {
		t.Fatal("a logout request was built for a service provider with no endpoint")
	}
	if redirect != "" {
		t.Error("a redirect was returned alongside the error")
	}
}

// TestLogoutTargetsExcludesTheInitiator. The service provider that started the
// logout has already ended its own session; sending it a request produces a
// message it must answer about a session that no longer exists.
func TestLogoutTargetsExcludesTheInitiator(t *testing.T) {
	idp, _, _ := sloIdP(t)
	idp.RegisterSP(&SPRegistration{
		ID:       "sp2",
		EntityID: "http://other.example.com",
		ACSUrl:   "http://other.example.com/acs",
		SLOUrl:   "http://other.example.com/slo",
	})
	// A registration with no logout endpoint cannot be told anything.
	idp.RegisterSP(&SPRegistration{
		ID:       "sp3",
		EntityID: "http://silent.example.com",
		ACSUrl:   "http://silent.example.com/acs",
	})

	targets := idp.LogoutTargets("sp1")
	if len(targets) != 1 {
		t.Fatalf("targets = %d, want just sp2", len(targets))
	}
	if targets[0].ID != "sp2" {
		t.Errorf("target = %q, want sp2", targets[0].ID)
	}
}

// decodeLogoutRequest pulls a LogoutRequest back out of a redirect URL.
func decodeLogoutRequest(t *testing.T, redirect string) LogoutRequest {
	t.Helper()
	raw := decodeAuthnRequestXML(t, strings.Replace(redirect, "SAMLRequest=", "SAMLRequest=", 1))
	var request LogoutRequest
	if err := xml.Unmarshal([]byte(raw), &request); err != nil {
		t.Fatalf("unmarshal LogoutRequest: %v", err)
	}
	return request
}
