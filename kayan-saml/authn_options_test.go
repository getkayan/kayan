package saml

import (
	"context"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"
)

// stepUpSession records a pending request that demanded something of the
// identity provider.
func stepUpSession(t testing.TB, h *attackHarness, forceAuthn bool, contexts ...string) {
	t.Helper()
	if err := h.store.Save(h.context, &Session{
		ID:                     testSessionID,
		RequestID:              testRequestID,
		IdPID:                  "idp1",
		CreateTime:             time.Now(),
		ExpiresAt:              time.Now().Add(time.Minute),
		ForceAuthn:             forceAuthn,
		RequestedAuthnContexts: contexts,
	}); err != nil {
		t.Fatalf("save session: %v", err)
	}
}

// withAuthnStatement attaches an AuthnStatement to a response.
func withAuthnStatement(resp Response, instant time.Time, classRef string) Response {
	statement := &AuthnStatement{AuthnInstant: instant}
	if classRef != "" {
		statement.AuthnContext = &AuthnContext{AuthnContextClassRef: classRef}
	}
	resp.Assertion.AuthnStatement = statement
	return resp
}

// TestRequestedAuthnContextIsEnforced is the central test.
//
// An identity provider may ignore RequestedAuthnContext entirely and answer a
// multi-factor request with a password-only assertion. A service provider that
// does not check accepts it, the step-up it performed before a sensitive
// operation never happened, and every log on both sides records a successful
// authentication. The signature is valid, the audience is right, the timestamps
// are fresh -- nothing else in the pipeline notices.
func TestRequestedAuthnContextIsEnforced(t *testing.T) {
	h := newAttackHarness(t)
	stepUpSession(t, h, false, AuthnContextMFA)

	// The identity provider answers with a password login.
	resp := withAuthnStatement(validResponse(), time.Now().UTC(), AuthnContextPasswordProtectedTransport)

	ident, err := h.sp.ProcessResponse(h.context, h.sign(t, resp), testSessionID)
	if err == nil {
		t.Fatal("a password-only assertion satisfied a request for multi-factor")
	}
	if ident != nil {
		t.Error("an identity was returned alongside the error")
	}
	if !errors.Is(err, ErrAuthnContextNotSatisfied) {
		t.Errorf("error = %v, want ErrAuthnContextNotSatisfied", err)
	}
}

// TestMatchingAuthnContextIsAccepted keeps the check from being a blanket
// refusal, which would make the test above pass against an implementation that
// rejects every login.
func TestMatchingAuthnContextIsAccepted(t *testing.T) {
	h := newAttackHarness(t)
	stepUpSession(t, h, false, AuthnContextMFA, "http://schemas.microsoft.com/claims/multipleauthn")

	resp := withAuthnStatement(validResponse(), time.Now().UTC(), AuthnContextMFA)

	if _, err := h.sp.ProcessResponse(h.context, h.sign(t, resp), testSessionID); err != nil {
		t.Fatalf("an assertion matching the requested context was refused: %v", err)
	}
}

// TestMissingAuthnStatementFailsAStepUp.
//
// An assertion with no AuthnStatement carries no evidence about how the
// subject authenticated. Treating that as satisfying the request reads "we
// could not tell, so we allowed it" -- and it is the cheapest way for an
// identity provider to appear compliant.
func TestMissingAuthnStatementFailsAStepUp(t *testing.T) {
	h := newAttackHarness(t)
	stepUpSession(t, h, false, AuthnContextMFA)

	// validResponse carries no AuthnStatement at all.
	if _, err := h.sp.ProcessResponse(h.context, h.sign(t, validResponse()), testSessionID); !errors.Is(err, ErrAuthnContextNotSatisfied) {
		t.Errorf("error = %v, want an assertion with no AuthnStatement to fail a step-up", err)
	}
}

// TestEmptyAuthnContextClassRefFailsAStepUp. An AuthnStatement present but
// carrying no class reference is the same absence with more XML around it.
func TestEmptyAuthnContextClassRefFailsAStepUp(t *testing.T) {
	h := newAttackHarness(t)
	stepUpSession(t, h, false, AuthnContextMFA)

	resp := withAuthnStatement(validResponse(), time.Now().UTC(), "")

	if _, err := h.sp.ProcessResponse(h.context, h.sign(t, resp), testSessionID); !errors.Is(err, ErrAuthnContextNotSatisfied) {
		t.Errorf("error = %v, want an empty AuthnContextClassRef to fail a step-up", err)
	}
}

// TestForceAuthnRejectsAStaleAuthentication.
//
// ForceAuthn asks the identity provider to reauthenticate rather than reuse an
// existing session. An identity provider that ignores it answers from the
// session it already had, and the only evidence is that AuthnInstant predates
// the request. Without this check, a step-up before a sensitive operation is
// satisfied by a login the user performed that morning -- possibly at a
// machine that is no longer in their possession, which is the case step-up
// exists for.
func TestForceAuthnRejectsAStaleAuthentication(t *testing.T) {
	h := newAttackHarness(t)
	stepUpSession(t, h, true)

	// The subject authenticated hours before this request was issued.
	resp := withAuthnStatement(validResponse(), time.Now().UTC().Add(-6*time.Hour),
		AuthnContextPasswordProtectedTransport)

	ident, err := h.sp.ProcessResponse(h.context, h.sign(t, resp), testSessionID)
	if err == nil {
		t.Fatal("an authentication predating the request satisfied ForceAuthn")
	}
	if ident != nil {
		t.Error("an identity was returned alongside the error")
	}
	if !errors.Is(err, ErrStaleAuthentication) {
		t.Errorf("error = %v, want ErrStaleAuthentication", err)
	}
}

// TestForceAuthnAcceptsAFreshAuthentication is the other half. A genuine
// reauthentication must pass, or the check is just a refusal.
func TestForceAuthnAcceptsAFreshAuthentication(t *testing.T) {
	h := newAttackHarness(t)
	stepUpSession(t, h, true)

	resp := withAuthnStatement(validResponse(), time.Now().UTC(),
		AuthnContextPasswordProtectedTransport)

	if _, err := h.sp.ProcessResponse(h.context, h.sign(t, resp), testSessionID); err != nil {
		t.Fatalf("a fresh authentication was refused: %v", err)
	}
}

// TestForceAuthnMissingInstantIsRefused. No AuthnInstant means no evidence of
// when the subject authenticated, which is the entire question ForceAuthn asks.
func TestForceAuthnMissingInstantIsRefused(t *testing.T) {
	h := newAttackHarness(t)
	stepUpSession(t, h, true)

	resp := withAuthnStatement(validResponse(), time.Time{}, AuthnContextPasswordProtectedTransport)

	if _, err := h.sp.ProcessResponse(h.context, h.sign(t, resp), testSessionID); !errors.Is(err, ErrStaleAuthentication) {
		t.Errorf("error = %v, want a missing AuthnInstant to fail ForceAuthn", err)
	}
}

// TestOrdinaryLoginIgnoresAuthnContext keeps the enforcement scoped to
// requests that asked for something. A login that requested nothing must not
// start failing because the identity provider sends an unfamiliar class
// reference, or every existing deployment breaks.
func TestOrdinaryLoginIgnoresAuthnContext(t *testing.T) {
	h := newAttackHarness(t)

	resp := withAuthnStatement(validResponse(), time.Now().UTC().Add(-6*time.Hour),
		"urn:example:something:proprietary")

	if _, err := h.sp.ProcessResponse(h.context, h.sign(t, resp), testSessionID); err != nil {
		t.Fatalf("an ordinary login was refused over an authentication context it never "+
			"asked about: %v", err)
	}
}

// TestAuthnRequestCarriesTheOptions checks the wire format. An option that is
// enforced on the way back but never sent would fail every login against an
// identity provider that would have complied.
func TestAuthnRequestCarriesTheOptions(t *testing.T) {
	h := newAttackHarness(t)

	redirect, err := h.sp.InitiateLoginWith(h.context, "idp1", "/after", LoginOptions{
		ForceAuthn:             true,
		IsPassive:              true,
		RequestedAuthnContexts: []string{AuthnContextMFA},
		Comparison:             ComparisonMinimum,
	})
	if err != nil {
		t.Fatalf("InitiateLoginWith: %v", err)
	}

	req := decodeAuthnRequest(t, redirect)
	if !req.ForceAuthn {
		t.Error("ForceAuthn was not sent")
	}
	if !req.IsPassive {
		t.Error("IsPassive was not sent")
	}
	if req.RequestedAuthnContext == nil {
		t.Fatal("RequestedAuthnContext was not sent")
	}
	if req.RequestedAuthnContext.Comparison != ComparisonMinimum {
		t.Errorf("Comparison = %q, want %q", req.RequestedAuthnContext.Comparison, ComparisonMinimum)
	}
	if len(req.RequestedAuthnContext.AuthnContextClassRef) != 1 ||
		req.RequestedAuthnContext.AuthnContextClassRef[0] != AuthnContextMFA {
		t.Errorf("AuthnContextClassRef = %v", req.RequestedAuthnContext.AuthnContextClassRef)
	}
}

// TestPlainLoginSendsNoOptions. ForceAuthn="false" and IsPassive="false" are
// the protocol defaults; sending them is noise, and some identity providers
// treat an explicit IsPassive as a request regardless of its value.
func TestPlainLoginSendsNoOptions(t *testing.T) {
	h := newAttackHarness(t)

	redirect, err := h.sp.InitiateLogin(h.context, "idp1", "/after")
	if err != nil {
		t.Fatalf("InitiateLogin: %v", err)
	}

	raw := decodeAuthnRequestXML(t, redirect)
	for _, attribute := range []string{"ForceAuthn", "IsPassive", "RequestedAuthnContext"} {
		if strings.Contains(raw, attribute) {
			t.Errorf("a plain login sent %s: %s", attribute, raw)
		}
	}
}

// TestSessionRecordsWhatWasSent covers the ordering the enforcement depends on.
//
// The session records what the request actually carried, after the
// BeforeAuthnRequest hook has run. Recording the caller's intent instead would
// let a hook that cleared ForceAuthn leave the response check demanding it --
// every login failing for a reason nothing explains -- or a hook that set it
// leave the check absent, which is the same silent gap the options exist to
// close.
func TestSessionRecordsWhatWasSent(t *testing.T) {
	h := newAttackHarness(t)
	h.sp.hooks.BeforeAuthnRequest = func(_ context.Context, _ string, req *AuthnRequest) error {
		req.ForceAuthn = false
		req.RequestedAuthnContext = &RequestedAuthnContext{
			AuthnContextClassRef: []string{AuthnContextX509},
		}
		return nil
	}

	if _, err := h.sp.InitiateLoginWith(h.context, "idp1", "/after", LoginOptions{
		ForceAuthn:             true,
		RequestedAuthnContexts: []string{AuthnContextMFA},
	}); err != nil {
		t.Fatalf("InitiateLoginWith: %v", err)
	}

	saved := h.store.last(t)
	if saved.ForceAuthn {
		t.Error("the session demands ForceAuthn although the hook cleared it from the request")
	}
	if len(saved.RequestedAuthnContexts) != 1 || saved.RequestedAuthnContexts[0] != AuthnContextX509 {
		t.Errorf("RequestedAuthnContexts = %v, want the hook's value", saved.RequestedAuthnContexts)
	}
}

// decodeAuthnRequest pulls the AuthnRequest back out of a redirect URL.
func decodeAuthnRequest(t *testing.T, redirect string) *AuthnRequest {
	t.Helper()
	var req AuthnRequest
	if err := xml.Unmarshal([]byte(decodeAuthnRequestXML(t, redirect)), &req); err != nil {
		t.Fatalf("unmarshal AuthnRequest: %v", err)
	}
	return &req
}

// decodeAuthnRequestXML returns the raw AuthnRequest XML from a redirect URL.
func decodeAuthnRequestXML(t *testing.T, redirect string) string {
	t.Helper()
	parsed, err := url.Parse(redirect)
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}
	encoded := parsed.Query().Get("SAMLRequest")
	if encoded == "" {
		t.Fatal("the redirect carries no SAMLRequest")
	}
	deflated, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("base64: %v", err)
	}
	raw, err := inflate(deflated)
	if err != nil {
		t.Fatalf("inflate: %v", err)
	}
	return string(raw)
}
