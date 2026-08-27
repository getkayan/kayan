package saml

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

// metadataWithCerts renders IdP metadata advertising the given signing
// certificates, which is what an identity provider publishes while it rotates
// a signing key: both the outgoing and incoming certificate, so relying
// parties accept assertions signed with either.
func metadataWithCerts(certs ...*x509.Certificate) []byte {
	var descriptors strings.Builder
	for _, cert := range certs {
		fmt.Fprintf(&descriptors, `
      <KeyDescriptor use="signing">
        <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
          <ds:X509Data>
            <ds:X509Certificate>%s</ds:X509Certificate>
          </ds:X509Data>
        </ds:KeyInfo>
      </KeyDescriptor>`, base64.StdEncoding.EncodeToString(cert.Raw))
	}

	return []byte(fmt.Sprintf(`<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
                  entityID="https://idp.example.test/metadata">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">%s
    <SingleSignOnService
      Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
      Location="https://idp.example.test/sso"/>
  </IDPSSODescriptor>
</EntityDescriptor>`, descriptors.String()))
}

// TestParseIdPMetadataKeepsEverySigningCertificate covers a scheduled outage.
//
// The parser stopped at the first signing certificate it found. During a key
// rollover an identity provider publishes both the outgoing and the incoming
// one, and switches which it signs with at a moment the relying party does not
// control. Keeping only the first means that when the IdP cuts over, every
// assertion fails signature verification and nobody can log in -- at a time
// chosen by the IdP, with nothing on the Kayan side having changed.
//
// The verifier already accepted a slice, and IdPConfig already had
// ExtraCertificates documented for exactly this case. Only the parser was
// discarding them.
func TestParseIdPMetadataKeepsEverySigningCertificate(t *testing.T) {
	_, first := testKeyPair(t)
	_, second := testKeyPair(t)

	idp, err := ParseIdPMetadata("idp-1", metadataWithCerts(first, second))
	if err != nil {
		t.Fatalf("ParseIdPMetadata: %v", err)
	}

	if idp.Certificate == nil {
		t.Fatal("no signing certificate was parsed")
	}
	if !idp.Certificate.Equal(first) {
		t.Error("the first advertised certificate is not the primary one")
	}
	if len(idp.ExtraCertificates) != 1 {
		t.Fatalf("ExtraCertificates has %d entries, want 1; the second signing "+
			"certificate was discarded and the IdP's rollover will break logins",
			len(idp.ExtraCertificates))
	}
	if !idp.ExtraCertificates[0].Equal(second) {
		t.Error("the retained extra certificate is not the second advertised one")
	}
}

// TestParseIdPMetadataIgnoresEncryptionKeys keeps the selection honest. A
// KeyDescriptor marked for encryption is not a signing key, and accepting one
// for signature verification would widen what the SP trusts.
func TestParseIdPMetadataIgnoresEncryptionKeys(t *testing.T) {
	_, signing := testKeyPair(t)
	_, encryption := testKeyPair(t)

	metadata := fmt.Sprintf(`<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
                  entityID="https://idp.example.test/metadata">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
      <KeyDescriptor use="signing">
        <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
          <ds:X509Data><ds:X509Certificate>%s</ds:X509Certificate></ds:X509Data>
        </ds:KeyInfo>
      </KeyDescriptor>
      <KeyDescriptor use="encryption">
        <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
          <ds:X509Data><ds:X509Certificate>%s</ds:X509Certificate></ds:X509Data>
        </ds:KeyInfo>
      </KeyDescriptor>
    <SingleSignOnService
      Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
      Location="https://idp.example.test/sso"/>
  </IDPSSODescriptor>
</EntityDescriptor>`,
		base64.StdEncoding.EncodeToString(signing.Raw),
		base64.StdEncoding.EncodeToString(encryption.Raw))

	idp, err := ParseIdPMetadata("idp-1", []byte(metadata))
	if err != nil {
		t.Fatalf("ParseIdPMetadata: %v", err)
	}
	if !idp.Certificate.Equal(signing) {
		t.Error("the signing certificate was not selected")
	}
	for _, extra := range idp.ExtraCertificates {
		if extra.Equal(encryption) {
			t.Error("an encryption certificate was accepted for signature verification")
		}
	}
}

// TestParseIdPMetadataWithOneCertificate keeps the ordinary case unchanged:
// most identity providers publish a single signing certificate and must not
// gain a spurious extra entry.
func TestParseIdPMetadataWithOneCertificate(t *testing.T) {
	_, only := testKeyPair(t)

	idp, err := ParseIdPMetadata("idp-1", metadataWithCerts(only))
	if err != nil {
		t.Fatalf("ParseIdPMetadata: %v", err)
	}
	if !idp.Certificate.Equal(only) {
		t.Error("the advertised certificate was not parsed")
	}
	if len(idp.ExtraCertificates) != 0 {
		t.Errorf("ExtraCertificates has %d entries, want 0", len(idp.ExtraCertificates))
	}
}
