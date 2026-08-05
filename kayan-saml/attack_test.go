package saml

import (
	"context"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// Attack corpus for the SAML assertion consumer.
//
// Each case is a technique that works against a service provider missing one
// check. They exist as tests so that removing a check fails the build rather
// than silently reopening the hole.

const (
	testSPEntityID = "http://sp.example.com"
	testACSUrl     = "http://sp.example.com/acs"
	testIdPEntity  = "http://idp.example.com"
	testSessionID  = "session-1"
	testRequestID  = "request-1"
)

// attackHarness wires a service provider with a pending request, ready to
// receive a response.
type attackHarness struct {
	sp      *ServiceProvider
	signer  Signer
	store   *mockSessionStore
	context context.Context
}

func newAttackHarness(t testing.TB) *attackHarness {
	t.Helper()

	signer, cert := testSigner(t)
	store := newMockSessionStore()

	sp := NewServiceProvider(
		Config{EntityID: testSPEntityID, ACSUrl: testACSUrl},
		store,
		newMockIdentityRepo(),
		func() any { return &mockUser{} },
		WithAutoProvision(),
	)
	sp.RegisterIdP(&IdPConfig{
		ID:          "idp1",
		EntityID:    testIdPEntity,
		SSOUrl:      "http://idp.example.com/sso",
		Certificate: cert,
	})

	h := &attackHarness{sp: sp, signer: signer, store: store, context: context.Background()}
	h.newSession(t)
	return h
}

// newSession records a pending authentication request.
func (h *attackHarness) newSession(t testing.TB) {
	t.Helper()
	if err := h.store.Save(h.context, &Session{
		ID:        testSessionID,
		RequestID: testRequestID,
		IdPID:     "idp1",
		ExpiresAt: time.Now().Add(time.Minute),
	}); err != nil {
		t.Fatalf("save session: %v", err)
	}
}

// validResponse returns a response that passes every check.
func validResponse() Response {
	now := time.Now().UTC()
	return Response{
		ID:           "_response-1",
		InResponseTo: testRequestID,
		Version:      "2.0",
		IssueInstant: now,
		Destination:  testACSUrl,
		Issuer:       Issuer{Value: testIdPEntity},
		Status:       Status{StatusCode: StatusCode{Value: StatusSuccess}},
		Assertion: &Assertion{
			ID:           "_assertion-1",
			Version:      "2.0",
			IssueInstant: now,
			Issuer:       Issuer{Value: testIdPEntity},
			Subject: Subject{
				NameID: NameID{Value: "victim@example.com"},
				SubjectConfirmations: []SubjectConfirmation{{
					Method: ConfirmationMethodBearer,
					SubjectConfirmationData: SubjectConfirmationData{
						Recipient:    testACSUrl,
						NotOnOrAfter: now.Add(5 * time.Minute),
						InResponseTo: testRequestID,
					},
				}},
			},
			Conditions: Conditions{
				NotBefore:    now.Add(-time.Minute),
				NotOnOrAfter: now.Add(5 * time.Minute),
				AudienceRestrictions: []AudienceRestriction{{
					Audiences: []string{testSPEntityID},
				}},
			},
			AttributeStatement: AttributeStatement{
				Attributes: []Attribute{
					{Name: "email", Values: []AttributeValue{{Value: "victim@example.com"}}},
				},
			},
		},
	}
}

func (h *attackHarness) sign(t testing.TB, resp Response) string {
	t.Helper()

	raw, err := xml.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	signed, err := h.signer.Sign(h.context, raw)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return base64.StdEncoding.EncodeToString(signed)
}

func encode(t testing.TB, resp Response) string {
	t.Helper()
	raw, err := xml.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

// TestValidAssertionIsAccepted is the control. Without it, a service provider
// that rejects everything would pass the whole corpus.
func TestValidAssertionIsAccepted(t *testing.T) {
	h := newAttackHarness(t)

	if _, err := h.sp.ProcessResponse(h.context, h.sign(t, validResponse()), testSessionID); err != nil {
		t.Fatalf("a valid signed assertion was rejected: %v", err)
	}
}

// TestUnsignedAssertionRejected covers the original defect: the service
// provider accepted whatever was posted to its endpoint.
func TestUnsignedAssertionRejected(t *testing.T) {
	h := newAttackHarness(t)

	_, err := h.sp.ProcessResponse(h.context, encode(t, validResponse()), testSessionID)
	if !errors.Is(err, ErrUnsigned) {
		t.Fatalf("error = %v, want ErrUnsigned; anyone could otherwise assert any identity", err)
	}
}

// TestForeignSignatureRejected proves a signature from a key the service
// provider does not trust is refused.
func TestForeignSignatureRejected(t *testing.T) {
	h := newAttackHarness(t)

	// The attacker signs with their own perfectly valid key.
	attackerSigner, _ := testSigner(t)
	raw, err := xml.Marshal(validResponse())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	signed, err := attackerSigner.Sign(h.context, raw)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	_, err = h.sp.ProcessResponse(h.context, base64.StdEncoding.EncodeToString(signed), testSessionID)
	if !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("error = %v, want ErrInvalidSignature", err)
	}
}

// TestSignatureWrappingRejected is the XSW corpus.
//
// Each variant carries a legitimately signed assertion somewhere in the
// document while placing attacker-controlled content where a naive parser
// would read it. The defense is structural: claims are unmarshaled only from
// the bytes the signature covers, so the injected element is never parsed.
func TestSignatureWrappingRejected(t *testing.T) {
	h := newAttackHarness(t)

	// A genuine, signed response for the real user.
	genuine := h.sign(t, validResponse())
	genuineXML, err := base64.StdEncoding.DecodeString(genuine)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	signed := string(genuineXML)

	// The attacker's assertion, unsigned, claiming to be an administrator.
	forged := validResponse()
	forged.Assertion.ID = "_assertion-evil"
	forged.Assertion.Subject.NameID.Value = "admin@example.com"
	forgedRaw, err := xml.Marshal(forged.Assertion)
	if err != nil {
		t.Fatalf("marshal forged assertion: %v", err)
	}
	evil := string(forgedRaw)

	variants := map[string]string{
		// The forged assertion precedes the signed one, so a parser taking the
		// first Assertion child reads the attacker's.
		"forged assertion first": strings.Replace(signed,
			"<Assertion", evil+"<Assertion", 1),

		// The forged assertion follows the signed one, for a parser taking the
		// last match.
		"forged assertion last": strings.Replace(signed,
			"</Response>", evil+"</Response>", 1),

		// The signed assertion is buried inside an Extensions element, leaving
		// the forged one in the position the schema expects.
		"signed assertion moved into Extensions": wrapInExtensions(signed, evil),
	}

	for name, payload := range variants {
		t.Run(name, func(t *testing.T) {
			h.newSession(t)

			user, err := h.sp.ProcessResponse(h.context,
				base64.StdEncoding.EncodeToString([]byte(payload)), testSessionID)

			// Rejecting outright is the expected outcome. Accepting is only
			// tolerable if the identity is the signed one, never the injected
			// one — that assertion is what makes this test meaningful even if
			// the underlying library changes behavior.
			if err == nil {
				name := identityName(t, user)
				if strings.Contains(name, "admin") {
					t.Fatalf("signature wrapping succeeded: authenticated as %q", name)
				}
			}
		})
	}
}

// wrapInExtensions relocates the signed assertion into an Extensions element
// and puts the forged one where the schema expects an assertion.
func wrapInExtensions(signed, evil string) string {
	start := strings.Index(signed, "<Assertion")
	end := strings.Index(signed, "</Assertion>")
	if start < 0 || end < 0 {
		return signed
	}
	original := signed[start : end+len("</Assertion>")]
	return signed[:start] + "<Extensions>" + original + "</Extensions>" + evil + signed[end+len("</Assertion>"):]
}

func identityName(t *testing.T, user any) string {
	t.Helper()
	if u, ok := user.(*mockUser); ok {
		return fmt.Sprintf("%s %s", u.ID, u.Traits)
	}
	return fmt.Sprintf("%v", user)
}

// TestReplayRejected proves a captured assertion cannot be presented twice.
func TestReplayRejected(t *testing.T) {
	h := newAttackHarness(t)
	response := h.sign(t, validResponse())

	if _, err := h.sp.ProcessResponse(h.context, response, testSessionID); err != nil {
		t.Fatalf("first presentation failed: %v", err)
	}

	// The same assertion, presented again with a fresh pending request.
	h.newSession(t)
	_, err := h.sp.ProcessResponse(h.context, response, testSessionID)
	if !errors.Is(err, ErrReplay) {
		t.Fatalf("error = %v, want ErrReplay; a captured assertion could otherwise be reused", err)
	}
}

// TestConditionCorpus covers the validity checks. Each entry is an assertion
// that is correctly signed but must still be refused.
func TestConditionCorpus(t *testing.T) {
	now := time.Now().UTC()

	tests := []struct {
		name    string
		mutate  func(*Response)
		wantErr error
	}{
		{
			name: "expired",
			mutate: func(r *Response) {
				r.Assertion.Conditions.NotOnOrAfter = now.Add(-time.Hour)
			},
			wantErr: ErrAssertionExpired,
		},
		{
			name: "not yet valid",
			mutate: func(r *Response) {
				r.Assertion.Conditions.NotBefore = now.Add(time.Hour)
			},
			wantErr: ErrAssertionNotYetValid,
		},
		{
			name: "audience names another service provider",
			mutate: func(r *Response) {
				r.Assertion.Conditions.AudienceRestrictions = []AudienceRestriction{{
					Audiences: []string{"http://other.example.com"},
				}}
			},
			wantErr: ErrWrongAudience,
		},
		{
			name: "no audience restriction at all",
			mutate: func(r *Response) {
				r.Assertion.Conditions.AudienceRestrictions = nil
			},
			wantErr: ErrWrongAudience,
		},
		{
			name: "destination is another endpoint",
			mutate: func(r *Response) {
				r.Destination = "http://other.example.com/acs"
			},
			wantErr: ErrWrongDestination,
		},
		{
			name: "subject confirmation names another recipient",
			mutate: func(r *Response) {
				r.Assertion.Subject.SubjectConfirmations[0].SubjectConfirmationData.Recipient =
					"http://other.example.com/acs"
			},
			wantErr: ErrWrongDestination,
		},
		{
			name: "issuer is a different identity provider",
			mutate: func(r *Response) {
				r.Assertion.Issuer = Issuer{Value: "http://evil.example.com"}
			},
			wantErr: ErrWrongIssuer,
		},
		{
			name: "subject confirmation expired",
			mutate: func(r *Response) {
				r.Assertion.Subject.SubjectConfirmations[0].SubjectConfirmationData.NotOnOrAfter =
					now.Add(-time.Hour)
			},
			wantErr: ErrAssertionExpired,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newAttackHarness(t)

			response := validResponse()
			tc.mutate(&response)

			_, err := h.sp.ProcessResponse(h.context, h.sign(t, response), testSessionID)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("error = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

// TestInResponseToMismatchRejected proves a response cannot be injected into a
// sign-on the user began for a different request.
func TestInResponseToMismatchRejected(t *testing.T) {
	h := newAttackHarness(t)

	response := validResponse()
	response.InResponseTo = "some-other-request"
	response.Assertion.Subject.SubjectConfirmations[0].SubjectConfirmationData.InResponseTo = "some-other-request"

	if _, err := h.sp.ProcessResponse(h.context, h.sign(t, response), testSessionID); err == nil {
		t.Fatal("a response answering a different request was accepted")
	}
}

// TestUnsolicitedRejectedByDefault proves identity-provider-initiated sign-on
// is refused unless enabled, since nothing correlates it with a request.
func TestUnsolicitedRejectedByDefault(t *testing.T) {
	h := newAttackHarness(t)

	response := validResponse()
	response.InResponseTo = ""
	response.Assertion.Subject.SubjectConfirmations[0].SubjectConfirmationData.InResponseTo = ""

	// No relay state, so no pending request matches.
	_, err := h.sp.ProcessResponse(h.context, h.sign(t, response), "no-such-session")
	if !errors.Is(err, ErrUnsolicited) {
		t.Fatalf("error = %v, want ErrUnsolicited", err)
	}
}

// TestMissingAssertionIDRejected proves an assertion that cannot be tracked
// for replay is refused rather than accepted untracked.
func TestMissingAssertionIDRejected(t *testing.T) {
	h := newAttackHarness(t)

	response := validResponse()
	response.Assertion.ID = ""

	_, err := h.sp.ProcessResponse(h.context, h.sign(t, response), testSessionID)
	if !errors.Is(err, ErrMissingAssertionID) {
		t.Fatalf("error = %v, want ErrMissingAssertionID", err)
	}
}

// TestPostBindingFormEscapesRelayState covers the XSS in the identity
// provider's auto-submitting form.
func TestPostBindingFormEscapesRelayState(t *testing.T) {
	idp := NewIdentityProvider(
		IdPServerConfig{EntityID: testIdPEntity, SSOUrl: "http://idp.example.com/sso"},
		nil, nil,
	)

	hostile := []string{
		`"><script>alert(1)</script>`,
		`" onload="alert(1)`,
		`"><img src=x onerror=alert(1)>`,
		`'></form><form action='https://evil.test'>`,
	}

	for _, relayState := range hostile {
		t.Run(relayState, func(t *testing.T) {
			form, err := idp.PostBindingForm(testACSUrl, []byte("<Response/>"), relayState)
			if err != nil {
				t.Fatalf("PostBindingForm: %v", err)
			}

			rendered := string(form)

			// What matters is whether the value can break out of its
			// attribute, which requires an unescaped quote or angle bracket.
			// Text like onload= is inert once the quotes around it are
			// escaped, and scanning for it would also match the template's own
			// <body onload="document.forms[0].submit()">.
			attr, ok := relayStateAttribute(rendered)
			if !ok {
				t.Fatalf("no RelayState input was rendered:\n%s", rendered)
			}
			for _, breakout := range []string{`"`, "'", "<", ">"} {
				if strings.Contains(attr, breakout) {
					t.Fatalf("RelayState %q left an unescaped %q in its attribute: value=%q",
						relayState, breakout, attr)
				}
			}

			// The document must still contain exactly one form, so the value
			// cannot have opened another.
			if got := strings.Count(rendered, "<form"); got != 1 {
				t.Fatalf("RelayState %q produced %d form elements:\n%s", relayState, got, rendered)
			}
		})
	}
}

// TestRedirectBindingRoundTrip proves the HTTP-Redirect binding DEFLATEs the
// message, which real identity providers require.
func TestRedirectBindingRoundTrip(t *testing.T) {
	message := []byte(`<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_1"/>`)

	encoded, err := deflateAndEncode(message)
	if err != nil {
		t.Fatalf("deflateAndEncode: %v", err)
	}

	// A raw base64 of the message would decode to the same length; DEFLATE
	// output differs, which is what proves compression happened.
	if encoded == base64.StdEncoding.EncodeToString(message) {
		t.Fatal("the message was not compressed")
	}

	values := map[string][]string{"SAMLRequest": {encoded}}
	decoded, err := ParseRedirectBinding(values, "SAMLRequest")
	if err != nil {
		t.Fatalf("ParseRedirectBinding: %v", err)
	}
	if string(decoded) != string(message) {
		t.Errorf("round-trip produced %q, want %q", decoded, message)
	}
}

// TestRedirectBindingRejectsDecompressionBomb proves an unauthenticated
// endpoint cannot be made to allocate without bound.
func TestRedirectBindingRejectsDecompressionBomb(t *testing.T) {
	// Highly compressible input that expands far beyond the limit.
	bomb := make([]byte, maxDecodedMessageSize*4)
	encoded, err := deflateAndEncode(bomb)
	if err != nil {
		t.Fatalf("deflateAndEncode: %v", err)
	}

	values := map[string][]string{"SAMLRequest": {encoded}}
	if _, err := ParseRedirectBinding(values, "SAMLRequest"); err == nil {
		t.Fatal("a decompression bomb was accepted")
	}
}

// TestUnsignedAllowedOnlyWhenRequested proves the escape hatch exists but is
// never the default.
func TestUnsignedAllowedOnlyWhenRequested(t *testing.T) {
	if NewXMLDSigVerifier().allowUnsigned {
		t.Fatal("unsigned assertions are accepted by default")
	}
	if !NewXMLDSigVerifier(WithAllowUnsigned()).allowUnsigned {
		t.Fatal("WithAllowUnsigned had no effect")
	}
}

// relayStateAttribute extracts the rendered RelayState attribute value.
func relayStateAttribute(rendered string) (string, bool) {
	const marker = `name="RelayState" value="`
	start := strings.Index(rendered, marker)
	if start < 0 {
		return "", false
	}
	rest := rendered[start+len(marker):]
	end := strings.Index(rest, `"`)
	if end < 0 {
		return "", false
	}
	return rest[:end], true
}
