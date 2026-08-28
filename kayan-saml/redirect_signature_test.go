package saml

import (
	"context"
	"crypto"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"net/url"
	"strings"
	"testing"
)

// Config.SignRequests was read in exactly one place: to populate the metadata
// document's AuthnRequestsSigned attribute. InitiateLogin never consulted a
// signer and added no SigAlg or Signature parameters, so a service provider
// advertised signed requests and put unsigned ones on the wire. An identity
// provider configured to require signatures -- common ADFS and Ping hardening
// -- rejected every login, and nothing on this side said why.

func signingSP(t *testing.T, opts ...SPOption) (*ServiceProvider, *rsa.PrivateKey) {
	t.Helper()

	key, cert := testKeyPair(t)
	config := Config{
		EntityID:     testSPEntityID,
		ACSUrl:       testACSUrl,
		Certificate:  cert,
		PrivateKey:   key,
		SignRequests: true,
	}
	sp := NewServiceProvider(config, newMockSessionStore(), newMockIdentityRepo(),
		func() any { return &mockUser{} }, opts...)
	sp.RegisterIdP(&IdPConfig{
		ID:       "idp1",
		EntityID: testIdPEntity,
		SSOUrl:   "https://idp.example.test/sso",
		// A NameIDFormat is set deliberately. Several assertions below depend
		// on the request having more than one child element, and every other
		// fixture in this package leaves it empty.
		NameIDFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
	})
	return sp, key
}

// verifyRedirectSignature checks a signed redirect the way an identity
// provider does: rebuild the signed octets from the raw query, then verify.
//
// It reads the RAW query rather than url.Values, because the signature covers
// the exact octet string in the exact order the sender emitted. Re-encoding
// through url.Values would sort the parameters and silently produce a
// different string, which is the mistake this whole path exists to avoid.
func verifyRedirectSignature(t *testing.T, redirect string, pub *rsa.PublicKey) {
	t.Helper()

	parsed, err := url.Parse(redirect)
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}
	raw := parsed.RawQuery

	sigIndex := strings.Index(raw, "&Signature=")
	if sigIndex < 0 {
		t.Fatal("the redirect carries no Signature parameter")
	}
	// Everything before &Signature= is what was signed.
	signedOctets := raw[:sigIndex]

	values := parsed.Query()
	encodedSig := values.Get("Signature")
	if encodedSig == "" {
		t.Fatal("the Signature parameter is empty")
	}
	signature, err := base64.StdEncoding.DecodeString(encodedSig)
	if err != nil {
		t.Fatalf("Signature is not valid base64: %v", err)
	}

	var hash crypto.Hash
	switch values.Get("SigAlg") {
	case SigAlgRSASHA256:
		hash = crypto.SHA256
	case SigAlgRSASHA512:
		hash = crypto.SHA512
	default:
		t.Fatalf("unexpected SigAlg %q", values.Get("SigAlg"))
	}

	hasher := hash.New()
	hasher.Write([]byte(signedOctets))
	if err := rsa.VerifyPKCS1v15(pub, hash, hasher.Sum(nil), signature); err != nil {
		t.Errorf("the redirect signature does not verify: %v\nsigned octets: %s", err, signedOctets)
	}
}

// TestInitiateLoginSignsTheRedirect is the central test. It verifies the
// signature the way a recipient does rather than merely asserting that the
// parameters are present, because a present-but-wrong signature is exactly
// what a real identity provider rejects.
func TestInitiateLoginSignsTheRedirect(t *testing.T) {
	sp, key := signingSP(t)

	redirect, err := sp.InitiateLogin(context.Background(), "idp1", "/dashboard")
	if err != nil {
		t.Fatalf("InitiateLogin: %v", err)
	}

	values, err := url.ParseQuery(mustQuery(t, redirect))
	if err != nil {
		t.Fatalf("parse query: %v", err)
	}
	if values.Get("SAMLRequest") == "" {
		t.Fatal("no SAMLRequest parameter")
	}
	if values.Get("SigAlg") != SigAlgRSASHA256 {
		t.Errorf("SigAlg = %q, want RSA-SHA256", values.Get("SigAlg"))
	}

	verifyRedirectSignature(t, redirect, &key.PublicKey)
}

// TestSignedOctetsExcludeTheSignature pins the one ordering mistake that
// produces a signature nothing can verify: including Signature in its own
// input, or letting the parameters be sorted.
func TestSignedOctetsExcludeTheSignature(t *testing.T) {
	sp, _ := signingSP(t)

	redirect, err := sp.InitiateLogin(context.Background(), "idp1", "/dashboard")
	if err != nil {
		t.Fatalf("InitiateLogin: %v", err)
	}
	raw := mustQuery(t, redirect)

	// SAML 2.0 Bindings 3.4.4.1 fixes this order. Alphabetical sorting, which
	// url.Values.Encode would apply, puts RelayState first and SigAlg before
	// Signature -- a different octet string entirely.
	wantOrder := []string{"SAMLRequest=", "&RelayState=", "&SigAlg=", "&Signature="}
	position := 0
	for _, part := range wantOrder {
		idx := strings.Index(raw[position:], part)
		if idx < 0 {
			t.Fatalf("query is missing %q or has it out of order: %s", part, raw)
		}
		position += idx + len(part)
	}
}

// TestSignRequestsWithoutAKeyFailsClosed covers the misconfiguration that used
// to be silent. Advertising signed requests while sending unsigned ones is the
// failure this whole change exists to remove, so asking for signing without
// the means to sign must be an error rather than a quiet downgrade.
func TestSignRequestsWithoutAKeyFailsClosed(t *testing.T) {
	_, cert := testKeyPair(t)
	sp := NewServiceProvider(
		Config{EntityID: testSPEntityID, ACSUrl: testACSUrl, Certificate: cert, SignRequests: true},
		newMockSessionStore(), newMockIdentityRepo(), func() any { return &mockUser{} },
	)
	sp.RegisterIdP(&IdPConfig{ID: "idp1", EntityID: testIdPEntity, SSOUrl: "https://idp.example.test/sso"})

	if _, err := sp.InitiateLogin(context.Background(), "idp1", ""); !errors.Is(err, ErrNoRedirectSigner) {
		t.Errorf("error = %v, want ErrNoRedirectSigner", err)
	}
}

// TestSignRequestsWithoutACertificateFailsClosed covers the inverted form of
// the same over-claim. Metadata publishes the signing KeyDescriptor only when
// a certificate is configured, so signing with a key whose certificate is not
// published yields requests no identity provider can verify -- which fails
// exactly as an unsigned request does, for a reason that is harder to find.
func TestSignRequestsWithoutACertificateFailsClosed(t *testing.T) {
	key, _ := testKeyPair(t)
	sp := NewServiceProvider(
		Config{EntityID: testSPEntityID, ACSUrl: testACSUrl, PrivateKey: key, SignRequests: true},
		newMockSessionStore(), newMockIdentityRepo(), func() any { return &mockUser{} },
	)
	sp.RegisterIdP(&IdPConfig{ID: "idp1", EntityID: testIdPEntity, SSOUrl: "https://idp.example.test/sso"})

	if _, err := sp.InitiateLogin(context.Background(), "idp1", ""); !errors.Is(err, ErrNoRedirectSigner) {
		t.Errorf("error = %v, want ErrNoRedirectSigner", err)
	}
}

// TestNoSigningLeavesTheRedirectUnsigned keeps the default path working. A
// deployment that never asked for signed requests must not start failing.
func TestNoSigningLeavesTheRedirectUnsigned(t *testing.T) {
	sp := NewServiceProvider(
		Config{EntityID: testSPEntityID, ACSUrl: testACSUrl},
		newMockSessionStore(), newMockIdentityRepo(), func() any { return &mockUser{} },
	)
	sp.RegisterIdP(&IdPConfig{ID: "idp1", EntityID: testIdPEntity, SSOUrl: "https://idp.example.test/sso"})

	redirect, err := sp.InitiateLogin(context.Background(), "idp1", "")
	if err != nil {
		t.Fatalf("InitiateLogin: %v", err)
	}
	values, _ := url.ParseQuery(mustQuery(t, redirect))
	if values.Has("SigAlg") || values.Has("Signature") {
		t.Error("an unsigned deployment emitted signature parameters")
	}
	if values.Get("SAMLRequest") == "" {
		t.Error("the unsigned redirect carries no SAMLRequest")
	}
}

// TestSignatureMethodIsHonoured covers a second field that was documented and
// never read. A deployment that configures SHA-512 and silently gets SHA-256
// believes a cryptographic policy is in force that is not.
func TestSignatureMethodIsHonoured(t *testing.T) {
	key, cert := testKeyPair(t)
	sp := NewServiceProvider(
		Config{
			EntityID: testSPEntityID, ACSUrl: testACSUrl,
			Certificate: cert, PrivateKey: key, SignRequests: true,
			SignatureMethod: SigAlgRSASHA512,
		},
		newMockSessionStore(), newMockIdentityRepo(), func() any { return &mockUser{} },
	)
	sp.RegisterIdP(&IdPConfig{ID: "idp1", EntityID: testIdPEntity, SSOUrl: "https://idp.example.test/sso"})

	redirect, err := sp.InitiateLogin(context.Background(), "idp1", "")
	if err != nil {
		t.Fatalf("InitiateLogin: %v", err)
	}
	values, _ := url.ParseQuery(mustQuery(t, redirect))
	if values.Get("SigAlg") != SigAlgRSASHA512 {
		t.Errorf("SigAlg = %q, want RSA-SHA512", values.Get("SigAlg"))
	}
	verifyRedirectSignature(t, redirect, &key.PublicKey)
}

// TestRSASHA1IsRefused keeps a weak algorithm from being accepted quietly. An
// operator who configured it must learn their policy is not being applied
// rather than have a different algorithm substituted behind their back.
func TestRSASHA1IsRefused(t *testing.T) {
	key, _ := testKeyPair(t)
	if _, err := NewRSARedirectSigner(key, SigAlgRSASHA1); err == nil {
		t.Error("RSA-SHA1 was accepted")
	}
	if _, err := NewRSARedirectSigner(key, "http://example.test/made-up"); err == nil {
		t.Error("an unknown signature method was accepted")
	}
	if _, err := NewRSARedirectSigner(nil, ""); err == nil {
		t.Error("a nil key was accepted")
	}
}

// TestReservedQueryParametersAreRefused covers HTTP parameter pollution. An
// endpoint that already carries SAMLRequest would produce a URL with the
// parameter twice, and which copy the recipient reads is a property of their
// parser rather than anything this library controls.
//
// The check applies to unsigned deployments too: duplication is not a signing
// concern.
func TestReservedQueryParametersAreRefused(t *testing.T) {
	for _, signRequests := range []bool{true, false} {
		key, cert := testKeyPair(t)
		config := Config{EntityID: testSPEntityID, ACSUrl: testACSUrl, SignRequests: signRequests}
		if signRequests {
			config.PrivateKey, config.Certificate = key, cert
		}
		sp := NewServiceProvider(config, newMockSessionStore(), newMockIdentityRepo(),
			func() any { return &mockUser{} })
		sp.RegisterIdP(&IdPConfig{
			ID: "idp1", EntityID: testIdPEntity,
			SSOUrl: "https://idp.example.test/sso?SAMLRequest=planted",
		})

		if _, err := sp.InitiateLogin(context.Background(), "idp1", ""); err == nil {
			t.Errorf("signRequests=%v: an endpoint already carrying SAMLRequest was accepted", signRequests)
		}
	}
}

// TestFailedSigningLeavesNoPendingSession covers an unauthenticated side
// effect. A refused login must not write to the session store, or an attacker
// can fill it by repeatedly asking for a login that cannot be performed.
func TestFailedSigningLeavesNoPendingSession(t *testing.T) {
	store := newMockSessionStore()
	_, cert := testKeyPair(t)
	sp := NewServiceProvider(
		Config{EntityID: testSPEntityID, ACSUrl: testACSUrl, Certificate: cert, SignRequests: true},
		store, newMockIdentityRepo(), func() any { return &mockUser{} },
	)
	sp.RegisterIdP(&IdPConfig{ID: "idp1", EntityID: testIdPEntity, SSOUrl: "https://idp.example.test/sso"})

	if _, err := sp.InitiateLogin(context.Background(), "idp1", ""); err == nil {
		t.Fatal("InitiateLogin succeeded with no signing key")
	}
	if n := len(store.sessions); n != 0 {
		t.Errorf("a refused login left %d session(s) in the store", n)
	}
}

func mustQuery(t *testing.T, rawURL string) string {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}
	return parsed.RawQuery
}
