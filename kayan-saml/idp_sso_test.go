package saml

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"
)

const (
	ssoIdPURL    = "https://idp.example.com/sso"
	ssoSPEntity  = "https://sp.example.com"
	ssoSPACS     = "https://sp.example.com/acs"
	ssoRelay     = "relay-123"
	ssoRequestID = "_request-1"
)

type ssoFixture struct {
	idp    *IdentityProvider
	sp     *SPRegistration
	spKey  *rsa.PrivateKey
	spCert *x509.Certificate
}

func newSSOFixture(t *testing.T) *ssoFixture {
	t.Helper()
	idpSigner, _ := testSigner(t)
	idp := NewIdentityProvider(IdPServerConfig{
		EntityID: "https://idp.example.com",
		SSOUrl:   ssoIdPURL,
	}, nil, nil, WithIdPSigner(idpSigner))

	key, cert := testKeyPair(t)
	sp := &SPRegistration{
		ID:          "sp1",
		EntityID:    ssoSPEntity,
		ACSUrl:      ssoSPACS,
		Certificate: cert,
	}
	idp.RegisterSP(sp)
	return &ssoFixture{idp: idp, sp: sp, spKey: key, spCert: cert}
}

func validAuthnRequest() AuthnRequest {
	return AuthnRequest{
		ID:                          ssoRequestID,
		Version:                     "2.0",
		IssueInstant:                time.Now().UTC(),
		Destination:                 ssoIdPURL,
		AssertionConsumerServiceURL: ssoSPACS,
		ProtocolBinding:             BindingHTTPPost,
		Issuer:                      Issuer{Value: ssoSPEntity},
	}
}

// redirectQuery builds an HTTP-Redirect binding query, signed when key is
// non-nil.
func redirectQuery(t *testing.T, req AuthnRequest, key *rsa.PrivateKey) string {
	t.Helper()
	raw, err := xml.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := deflateAndEncode(raw)
	if err != nil {
		t.Fatal(err)
	}
	var signer RedirectSigner
	if key != nil {
		s, err := NewRSARedirectSigner(key, SigAlgRSASHA256)
		if err != nil {
			t.Fatal(err)
		}
		signer = s
	}
	full, err := redirectURL(context.Background(), ssoIdPURL, "SAMLRequest", encoded, ssoRelay, signer)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(full)
	if err != nil {
		t.Fatal(err)
	}
	return parsed.RawQuery
}

// postForm builds an HTTP-POST binding form, signed with an enveloped
// signature when key is non-nil.
func postForm(t *testing.T, req AuthnRequest, key *rsa.PrivateKey, cert *x509.Certificate) url.Values {
	t.Helper()
	raw, err := xml.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	if key != nil {
		signer, err := NewXMLDSigSigner(key, cert)
		if err != nil {
			t.Fatal(err)
		}
		raw, err = signer.Sign(context.Background(), raw)
		if err != nil {
			t.Fatal(err)
		}
	}
	return url.Values{
		"SAMLRequest": {base64.StdEncoding.EncodeToString(raw)},
		"RelayState":  {ssoRelay},
	}
}

func TestSignedRedirectAuthnRequestIsAccepted(t *testing.T) {
	f := newSSOFixture(t)

	req, err := f.idp.ParseRedirectAuthnRequest(context.Background(), redirectQuery(t, validAuthnRequest(), f.spKey))
	if err != nil {
		t.Fatalf("ParseRedirectAuthnRequest: %v", err)
	}
	if !req.Signed || req.SP != f.sp || req.RelayState != ssoRelay || req.Request.ID != ssoRequestID {
		t.Fatalf("unexpected request: signed=%v sp=%v relay=%q id=%q", req.Signed, req.SP, req.RelayState, req.Request.ID)
	}

	response, err := f.idp.BuildResponse(context.Background(), req, &mockUser{ID: "user1"})
	if err != nil {
		t.Fatalf("BuildResponse: %v", err)
	}
	var parsed Response
	if err := xml.Unmarshal(response, &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.InResponseTo != ssoRequestID || parsed.Destination != ssoSPACS {
		t.Errorf("response InResponseTo=%q Destination=%q", parsed.InResponseTo, parsed.Destination)
	}
	if parsed.Assertion == nil || parsed.Assertion.Subject.NameID.Value != "user1" {
		t.Errorf("assertion does not name the authenticated user")
	}
}

func TestSignedPostAuthnRequestIsAccepted(t *testing.T) {
	f := newSSOFixture(t)

	req, err := f.idp.ParsePostAuthnRequest(context.Background(), postForm(t, validAuthnRequest(), f.spKey, f.spCert))
	if err != nil {
		t.Fatalf("ParsePostAuthnRequest: %v", err)
	}
	if !req.Signed || req.Request.ID != ssoRequestID || req.RelayState != ssoRelay {
		t.Fatalf("unexpected request: signed=%v id=%q relay=%q", req.Signed, req.Request.ID, req.RelayState)
	}
}

// TestUnsignedAuthnRequestIsRefusedByDefault. An unsigned request is one
// anyone can forge in the service provider's name, so it is refused unless the
// registration opts out.
func TestUnsignedAuthnRequestIsRefusedByDefault(t *testing.T) {
	f := newSSOFixture(t)
	ctx := context.Background()

	if _, err := f.idp.ParseRedirectAuthnRequest(ctx, redirectQuery(t, validAuthnRequest(), nil)); !errors.Is(err, ErrAuthnRequestNotSigned) {
		t.Errorf("redirect: err = %v, want ErrAuthnRequestNotSigned", err)
	}
	if _, err := f.idp.ParsePostAuthnRequest(ctx, postForm(t, validAuthnRequest(), nil, nil)); !errors.Is(err, ErrAuthnRequestNotSigned) {
		t.Errorf("post: err = %v, want ErrAuthnRequestNotSigned", err)
	}
}

func TestUnsignedAuthnRequestIsAcceptedWhenAllowed(t *testing.T) {
	f := newSSOFixture(t)
	f.sp.AllowUnsignedAuthnRequests = true
	ctx := context.Background()

	req, err := f.idp.ParseRedirectAuthnRequest(ctx, redirectQuery(t, validAuthnRequest(), nil))
	if err != nil || req.Signed {
		t.Errorf("redirect: err = %v, signed = %v", err, req != nil && req.Signed)
	}
	req, err = f.idp.ParsePostAuthnRequest(ctx, postForm(t, validAuthnRequest(), nil, nil))
	if err != nil || req.Signed {
		t.Errorf("post: err = %v, signed = %v", err, req != nil && req.Signed)
	}
}

// TestRedirectSignedByAnotherKeyIsRefused. The certificate comes from the
// registration the Issuer names; a key the service provider does not hold
// must not pass.
func TestRedirectSignedByAnotherKeyIsRefused(t *testing.T) {
	f := newSSOFixture(t)
	otherKey, _ := testKeyPair(t)

	_, err := f.idp.ParseRedirectAuthnRequest(context.Background(), redirectQuery(t, validAuthnRequest(), otherKey))
	if err == nil || !strings.Contains(err.Error(), "does not verify") {
		t.Fatalf("err = %v, want a signature verification failure", err)
	}
}

// TestTamperedRedirectMessageIsRefused swaps the signed SAMLRequest for one
// asking for something else, keeping the original signature.
func TestTamperedRedirectMessageIsRefused(t *testing.T) {
	f := newSSOFixture(t)

	signed := redirectQuery(t, validAuthnRequest(), f.spKey)
	altered := validAuthnRequest()
	altered.ID = "_attacker-chosen"
	forged := redirectQuery(t, altered, nil)

	original, _ := rawQueryValue(signed, "SAMLRequest")
	replacement, _ := rawQueryValue(forged, "SAMLRequest")
	tampered := strings.Replace(signed, "SAMLRequest="+original, "SAMLRequest="+replacement, 1)

	_, err := f.idp.ParseRedirectAuthnRequest(context.Background(), tampered)
	if err == nil || !strings.Contains(err.Error(), "does not verify") {
		t.Fatalf("err = %v, want a signature verification failure", err)
	}
}

// TestRedirectParameterPollutionIsRefused. A second SAMLRequest -- plainly or
// with a percent-escaped name -- must not let the message that is parsed
// differ from the message whose signature was checked.
func TestRedirectParameterPollutionIsRefused(t *testing.T) {
	f := newSSOFixture(t)
	signed := redirectQuery(t, validAuthnRequest(), f.spKey)
	forged, _ := rawQueryValue(redirectQuery(t, validAuthnRequest(), nil), "SAMLRequest")

	for name, query := range map[string]string{
		"repeated":       signed + "&SAMLRequest=" + forged,
		"escaped repeat": "SAML%52equest=" + forged + "&" + signed,
		"escaped only":   strings.Replace(signed, "SAMLRequest=", "SAML%52equest=", 1),
	} {
		_, err := f.idp.ParseRedirectAuthnRequest(context.Background(), query)
		if !errors.Is(err, ErrInvalidAuthnRequest) {
			t.Errorf("%s: err = %v, want ErrInvalidAuthnRequest", name, err)
		}
	}
}

func TestPostSignedByAnotherKeyIsRefused(t *testing.T) {
	f := newSSOFixture(t)
	otherKey, otherCert := testKeyPair(t)

	_, err := f.idp.ParsePostAuthnRequest(context.Background(), postForm(t, validAuthnRequest(), otherKey, otherCert))
	if !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("err = %v, want ErrInvalidSignature", err)
	}
}

// TestPresentSignatureIsVerifiedEvenWhenUnsignedIsAllowed. Allowing unsigned
// requests must not turn a signature that fails into one that is ignored.
func TestPresentSignatureIsVerifiedEvenWhenUnsignedIsAllowed(t *testing.T) {
	f := newSSOFixture(t)
	f.sp.AllowUnsignedAuthnRequests = true
	otherKey, otherCert := testKeyPair(t)
	ctx := context.Background()

	if _, err := f.idp.ParsePostAuthnRequest(ctx, postForm(t, validAuthnRequest(), otherKey, otherCert)); !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("post: err = %v, want ErrInvalidSignature", err)
	}
	if _, err := f.idp.ParseRedirectAuthnRequest(ctx, redirectQuery(t, validAuthnRequest(), otherKey)); err == nil {
		t.Error("redirect: a request with a failing signature was accepted")
	}
}

func TestAuthnRequestFieldsAreChecked(t *testing.T) {
	tests := map[string]func(*AuthnRequest){
		"wrong Destination":          func(r *AuthnRequest) { r.Destination = "https://other-idp.example.com/sso" },
		"signed without Destination": func(r *AuthnRequest) { r.Destination = "" },
		"unregistered ACS URL":       func(r *AuthnRequest) { r.AssertionConsumerServiceURL = "https://attacker.example.com/acs" },
		"unsupported binding":        func(r *AuthnRequest) { r.ProtocolBinding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact" },
		"wrong version":              func(r *AuthnRequest) { r.Version = "1.1" },
		"no ID":                      func(r *AuthnRequest) { r.ID = "" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			f := newSSOFixture(t)
			req := validAuthnRequest()
			mutate(&req)
			_, err := f.idp.ParseRedirectAuthnRequest(context.Background(), redirectQuery(t, req, f.spKey))
			if !errors.Is(err, ErrInvalidAuthnRequest) {
				t.Fatalf("err = %v, want ErrInvalidAuthnRequest", err)
			}
		})
	}
}

func TestAuthnRequestFromAnUnknownIssuerIsRefused(t *testing.T) {
	f := newSSOFixture(t)
	req := validAuthnRequest()
	req.Issuer.Value = "https://unknown.example.com"

	_, err := f.idp.ParseRedirectAuthnRequest(context.Background(), redirectQuery(t, req, f.spKey))
	if !errors.Is(err, ErrUnknownServiceProvider) {
		t.Fatalf("err = %v, want ErrUnknownServiceProvider", err)
	}
}

// TestResponseNamesSomebody. An assertion with an empty NameID is still a
// signed statement that someone authenticated.
func TestResponseNamesSomebody(t *testing.T) {
	f := newSSOFixture(t)
	req, err := f.idp.ParseRedirectAuthnRequest(context.Background(), redirectQuery(t, validAuthnRequest(), f.spKey))
	if err != nil {
		t.Fatal(err)
	}

	for name, ident := range map[string]any{
		"nil identity":   nil,
		"empty identity": &mockUser{ID: ""},
	} {
		if _, err := f.idp.BuildResponse(context.Background(), req, ident); !errors.Is(err, ErrNoSubject) {
			t.Errorf("%s: err = %v, want ErrNoSubject", name, err)
		}
	}
}

// TestNilIdentityIsRefusedWhateverTheNameIDHookSays. A GetNameID hook that
// resolves a fixed or default value must not turn "nobody authenticated" into
// an assertion for that value.
func TestNilIdentityIsRefusedWhateverTheNameIDHookSays(t *testing.T) {
	f := newSSOFixture(t)
	f.idp.SetHooks(IdPHooks{
		GetNameID: func(context.Context, any, *SPRegistration) (string, error) { return "admin", nil },
	})
	req, err := f.idp.ParseRedirectAuthnRequest(context.Background(), redirectQuery(t, validAuthnRequest(), f.spKey))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.idp.BuildResponse(context.Background(), req, nil); !errors.Is(err, ErrNoSubject) {
		t.Fatalf("err = %v, want ErrNoSubject", err)
	}
}

func TestMetadataAdvertisesSignedAuthnRequests(t *testing.T) {
	f := newSSOFixture(t)
	metadata, err := f.idp.GetMetadata()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(metadata), `WantAuthnRequestsSigned="true"`) {
		t.Errorf("metadata does not advertise WantAuthnRequestsSigned")
	}
}

// TestPassiveRequestCanBeRefusedWithNoPassive. A passive request with no
// session has to be answered, with a signed failure and no assertion.
func TestPassiveRequestCanBeRefusedWithNoPassive(t *testing.T) {
	f := newSSOFixture(t)
	passive := validAuthnRequest()
	passive.IsPassive = true
	req, err := f.idp.ParseRedirectAuthnRequest(context.Background(), redirectQuery(t, passive, f.spKey))
	if err != nil {
		t.Fatal(err)
	}

	raw, err := f.idp.BuildErrorResponse(context.Background(), req, StatusNoPassive)
	if err != nil {
		t.Fatalf("BuildErrorResponse: %v", err)
	}
	if !strings.Contains(string(raw), "Signature") {
		t.Error("failure response is not signed")
	}
	var resp Response
	if err := xml.Unmarshal(raw, &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Assertion != nil {
		t.Error("failure response carries an assertion")
	}
	code := resp.Status.StatusCode
	if code.Value != StatusResponder || code.StatusCode == nil || code.StatusCode.Value != StatusNoPassive {
		t.Errorf("status = %+v, want Responder/NoPassive", code)
	}
	if resp.InResponseTo != ssoRequestID || resp.Destination != ssoSPACS {
		t.Errorf("InResponseTo=%q Destination=%q", resp.InResponseTo, resp.Destination)
	}
}

// TestErrorResponseRefusesSuccess. The failure builder must not be usable to
// emit a status a service provider reads as success.
func TestErrorResponseRefusesSuccess(t *testing.T) {
	f := newSSOFixture(t)
	req, err := f.idp.ParseRedirectAuthnRequest(context.Background(), redirectQuery(t, validAuthnRequest(), f.spKey))
	if err != nil {
		t.Fatal(err)
	}
	for _, reason := range []string{StatusSuccess, "", "urn:example:custom"} {
		if _, err := f.idp.BuildErrorResponse(context.Background(), req, reason); err == nil {
			t.Errorf("reason %q was accepted", reason)
		}
	}
}
