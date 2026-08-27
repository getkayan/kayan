package saml

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"strings"
	"testing"
)

// Metadata is the file an administrator uploads to an identity provider to
// register a service provider. It is what tells the IdP which certificate to
// verify signatures against, which one to encrypt to, and where to send
// responses and logout messages. A stub that omits the key material produces
// an integration that cannot be completed at all -- most identity providers
// reject the upload outright, and the ones that accept it fail later with
// nothing pointing at the metadata as the cause.
//
// These tests parse what is produced, rather than matching strings, because
// what matters is that a conforming consumer can read it.

// parsedSPMetadata is the shape an identity provider reads from SP metadata.
type parsedSPMetadata struct {
	XMLName         xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntityDescriptor"`
	EntityID        string   `xml:"entityID,attr"`
	SPSSODescriptor struct {
		AuthnRequestsSigned        string `xml:"AuthnRequestsSigned,attr"`
		WantAssertionsSigned       string `xml:"WantAssertionsSigned,attr"`
		ProtocolSupportEnumeration string `xml:"protocolSupportEnumeration,attr"`
		KeyDescriptors             []struct {
			Use         string `xml:"use,attr"`
			Certificate string `xml:"KeyInfo>X509Data>X509Certificate"`
		} `xml:"KeyDescriptor"`
		NameIDFormats            []string `xml:"NameIDFormat"`
		AssertionConsumerService []struct {
			Binding  string `xml:"Binding,attr"`
			Location string `xml:"Location,attr"`
			Index    string `xml:"index,attr"`
		} `xml:"AssertionConsumerService"`
		SingleLogoutService []struct {
			Binding  string `xml:"Binding,attr"`
			Location string `xml:"Location,attr"`
		} `xml:"SingleLogoutService"`
	} `xml:"urn:oasis:names:tc:SAML:2.0:metadata SPSSODescriptor"`
}

func spWithMetadata(t *testing.T) (*ServiceProvider, *x509.Certificate) {
	t.Helper()
	key, cert := testKeyPair(t)
	sp := NewServiceProvider(
		Config{
			EntityID:     "https://sp.example.test/metadata",
			ACSUrl:       "https://sp.example.test/acs",
			SLOUrl:       "https://sp.example.test/slo",
			Certificate:  cert,
			PrivateKey:   key,
			SignRequests: true,
			NameIDFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
		},
		newMockSessionStore(), newMockIdentityRepo(), func() any { return &mockUser{} },
	)
	return sp, cert
}

// TestSPMetadataCarriesTheSigningCertificate is the test that matters most.
//
// Without a KeyDescriptor the identity provider has no certificate to verify
// this service provider's signed AuthnRequests against, and no key to encrypt
// assertions to. That is the whole reason metadata is exchanged.
func TestSPMetadataCarriesTheSigningCertificate(t *testing.T) {
	sp, cert := spWithMetadata(t)

	raw, err := sp.GetMetadata()
	if err != nil {
		t.Fatalf("GetMetadata: %v", err)
	}

	var parsed parsedSPMetadata
	if err := xml.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("the metadata is not parseable as an EntityDescriptor: %v\n%s", err, raw)
	}

	if len(parsed.SPSSODescriptor.KeyDescriptors) == 0 {
		t.Fatal("the metadata carries no KeyDescriptor; an identity provider " +
			"cannot verify this service provider's signatures or encrypt to it")
	}

	wantCert := base64.StdEncoding.EncodeToString(cert.Raw)
	var sawSigning, sawEncryption bool
	for _, kd := range parsed.SPSSODescriptor.KeyDescriptors {
		got := strings.Join(strings.Fields(kd.Certificate), "")
		if got != wantCert {
			t.Errorf("KeyDescriptor use=%q carries a certificate that is not this SP's", kd.Use)
		}
		switch kd.Use {
		case "signing":
			sawSigning = true
		case "encryption":
			sawEncryption = true
		}
	}
	if !sawSigning {
		t.Error("no KeyDescriptor is marked for signing")
	}
	if !sawEncryption {
		t.Error("no KeyDescriptor is marked for encryption; an identity provider " +
			"that encrypts assertions has no key to encrypt to")
	}
}

// TestSPMetadataAdvertisesTheEndpoints covers what an identity provider needs
// in order to send anything back.
func TestSPMetadataAdvertisesTheEndpoints(t *testing.T) {
	sp, _ := spWithMetadata(t)

	raw, err := sp.GetMetadata()
	if err != nil {
		t.Fatalf("GetMetadata: %v", err)
	}
	var parsed parsedSPMetadata
	if err := xml.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("parse metadata: %v", err)
	}

	if parsed.EntityID != "https://sp.example.test/metadata" {
		t.Errorf("entityID = %q", parsed.EntityID)
	}

	acs := parsed.SPSSODescriptor.AssertionConsumerService
	if len(acs) == 0 {
		t.Fatal("no AssertionConsumerService is advertised")
	}
	if acs[0].Location != "https://sp.example.test/acs" {
		t.Errorf("ACS location = %q", acs[0].Location)
	}
	if acs[0].Binding != BindingHTTPPost {
		t.Errorf("ACS binding = %q, want HTTP-POST", acs[0].Binding)
	}
	if acs[0].Index == "" {
		t.Error("the AssertionConsumerService has no index, which some identity providers require")
	}

	slo := parsed.SPSSODescriptor.SingleLogoutService
	if len(slo) == 0 {
		t.Fatal("no SingleLogoutService is advertised although an SLO URL is configured")
	}
	if slo[0].Location != "https://sp.example.test/slo" {
		t.Errorf("SLO location = %q", slo[0].Location)
	}
}

// TestSPMetadataDeclaresItsExpectations covers the flags an identity provider
// reads to decide what to send.
//
// WantAssertionsSigned matters: an identity provider that reads it as false
// may send unsigned assertions, which this service provider then rejects --
// an integration that fails at the last step, with the cause sitting in a
// metadata file nobody thinks to re-read.
func TestSPMetadataDeclaresItsExpectations(t *testing.T) {
	sp, _ := spWithMetadata(t)

	raw, err := sp.GetMetadata()
	if err != nil {
		t.Fatalf("GetMetadata: %v", err)
	}
	var parsed parsedSPMetadata
	if err := xml.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("parse metadata: %v", err)
	}

	descriptor := parsed.SPSSODescriptor
	if descriptor.WantAssertionsSigned != "true" {
		t.Errorf("WantAssertionsSigned = %q, want true: this service provider "+
			"refuses unsigned assertions, so its metadata must say so", descriptor.WantAssertionsSigned)
	}
	if descriptor.AuthnRequestsSigned != "true" {
		t.Errorf("AuthnRequestsSigned = %q, want true", descriptor.AuthnRequestsSigned)
	}
	if !strings.Contains(descriptor.ProtocolSupportEnumeration, "urn:oasis:names:tc:SAML:2.0:protocol") {
		t.Errorf("protocolSupportEnumeration = %q", descriptor.ProtocolSupportEnumeration)
	}
	if len(descriptor.NameIDFormats) == 0 {
		t.Error("no NameIDFormat is advertised")
	}
}

// TestSPMetadataOmitsWhatIsNotConfigured keeps the document honest. Announcing
// an SLO endpoint that does not exist means an identity provider sends logout
// requests into a 404 and reports the federation inconsistent.
func TestSPMetadataOmitsWhatIsNotConfigured(t *testing.T) {
	sp := NewServiceProvider(
		Config{EntityID: "https://sp.example.test/metadata", ACSUrl: "https://sp.example.test/acs"},
		newMockSessionStore(), newMockIdentityRepo(), func() any { return &mockUser{} },
	)

	raw, err := sp.GetMetadata()
	if err != nil {
		t.Fatalf("GetMetadata: %v", err)
	}
	var parsed parsedSPMetadata
	if err := xml.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("parse metadata: %v", err)
	}

	if len(parsed.SPSSODescriptor.SingleLogoutService) != 0 {
		t.Error("an SLO endpoint is advertised although none is configured")
	}
	if len(parsed.SPSSODescriptor.KeyDescriptors) != 0 {
		t.Error("a KeyDescriptor is advertised although no certificate is configured")
	}
	if parsed.SPSSODescriptor.AuthnRequestsSigned != "false" {
		t.Errorf("AuthnRequestsSigned = %q, want false when requests are not signed",
			parsed.SPSSODescriptor.AuthnRequestsSigned)
	}
}

// TestSPMetadataRoundTrips is the strongest check available without a real
// identity provider: what this package produces, this package can read.
func TestSPMetadataRoundTrips(t *testing.T) {
	sp, cert := spWithMetadata(t)

	raw, err := sp.GetMetadata()
	if err != nil {
		t.Fatalf("GetMetadata: %v", err)
	}

	// ParseIdPMetadata reads an IDPSSODescriptor, so SP metadata is not its
	// input -- but the EntityDescriptor envelope and the KeyDescriptor shape
	// are shared, and that is what a consumer parses first.
	var envelope struct {
		XMLName  xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntityDescriptor"`
		EntityID string   `xml:"entityID,attr"`
	}
	if err := xml.Unmarshal(raw, &envelope); err != nil {
		t.Fatalf("the envelope is not parseable: %v", err)
	}
	if envelope.EntityID == "" {
		t.Error("the entityID did not survive a round trip")
	}

	// The certificate must decode back to the one configured.
	var parsed parsedSPMetadata
	if err := xml.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("parse metadata: %v", err)
	}
	if len(parsed.SPSSODescriptor.KeyDescriptors) == 0 {
		t.Fatal("the metadata carries no KeyDescriptor to round-trip")
	}
	encoded := strings.Join(strings.Fields(parsed.SPSSODescriptor.KeyDescriptors[0].Certificate), "")
	der, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("the advertised certificate is not valid base64: %v", err)
	}
	got, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("the advertised certificate does not parse: %v", err)
	}
	if !got.Equal(cert) {
		t.Error("the advertised certificate is not the one configured")
	}
}

// parsedIdPMetadata is the shape a service provider reads from IdP metadata.
type parsedIdPMetadata struct {
	XMLName          xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntityDescriptor"`
	EntityID         string   `xml:"entityID,attr"`
	IDPSSODescriptor struct {
		WantAuthnRequestsSigned string `xml:"WantAuthnRequestsSigned,attr"`
		KeyDescriptors          []struct {
			Use         string `xml:"use,attr"`
			Certificate string `xml:"KeyInfo>X509Data>X509Certificate"`
		} `xml:"KeyDescriptor"`
		SingleSignOnService []struct {
			Binding  string `xml:"Binding,attr"`
			Location string `xml:"Location,attr"`
		} `xml:"SingleSignOnService"`
		SingleLogoutService []struct {
			Binding  string `xml:"Binding,attr"`
			Location string `xml:"Location,attr"`
		} `xml:"SingleLogoutService"`
	} `xml:"urn:oasis:names:tc:SAML:2.0:metadata IDPSSODescriptor"`
}

// TestIdPMetadataCarriesTheSigningCertificate covers the same gap on the
// identity-provider side. Without it a service provider has nothing to verify
// this IdP's assertions against.
func TestIdPMetadataCarriesTheSigningCertificate(t *testing.T) {
	key, cert := testKeyPair(t)
	idp := NewIdentityProvider(IdPServerConfig{
		EntityID:    "https://idp.example.test/metadata",
		SSOUrl:      "https://idp.example.test/sso",
		SLOUrl:      "https://idp.example.test/slo",
		Certificate: cert,
		PrivateKey:  key,
	}, nil, nil)

	raw, err := idp.GetMetadata()
	if err != nil {
		t.Fatalf("GetMetadata: %v", err)
	}

	var parsed parsedIdPMetadata
	if err := xml.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("the metadata is not parseable: %v\n%s", err, raw)
	}

	if len(parsed.IDPSSODescriptor.KeyDescriptors) == 0 {
		t.Fatal("the metadata carries no KeyDescriptor; a service provider " +
			"cannot verify assertions from this identity provider")
	}
	wantCert := base64.StdEncoding.EncodeToString(cert.Raw)
	got := strings.Join(strings.Fields(parsed.IDPSSODescriptor.KeyDescriptors[0].Certificate), "")
	if got != wantCert {
		t.Error("the advertised certificate is not this identity provider's")
	}

	if len(parsed.IDPSSODescriptor.SingleLogoutService) == 0 {
		t.Error("no SingleLogoutService is advertised although an SLO URL is configured")
	}
}

// TestIdPMetadataIsReadableByTheSPParser closes the loop: metadata this
// package emits as an identity provider is metadata it accepts as a service
// provider. A mismatch between the two would only surface against a real IdP.
func TestIdPMetadataIsReadableByTheSPParser(t *testing.T) {
	key, cert := testKeyPair(t)
	idp := NewIdentityProvider(IdPServerConfig{
		EntityID:    "https://idp.example.test/metadata",
		SSOUrl:      "https://idp.example.test/sso",
		SLOUrl:      "https://idp.example.test/slo",
		Certificate: cert,
		PrivateKey:  key,
	}, nil, nil)

	raw, err := idp.GetMetadata()
	if err != nil {
		t.Fatalf("GetMetadata: %v", err)
	}

	config, err := ParseIdPMetadata("idp-1", raw)
	if err != nil {
		t.Fatalf("ParseIdPMetadata could not read metadata this package produced: %v", err)
	}
	if config.EntityID != "https://idp.example.test/metadata" {
		t.Errorf("EntityID = %q", config.EntityID)
	}
	if config.SSOUrl != "https://idp.example.test/sso" {
		t.Errorf("SSOUrl = %q", config.SSOUrl)
	}
	if config.Certificate == nil {
		t.Fatal("the parsed config carries no certificate")
	}
	if !config.Certificate.Equal(cert) {
		t.Error("the round-tripped certificate is not the original")
	}
}
