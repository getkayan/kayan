package saml

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"fmt"
)

// XML namespaces declared once on the metadata root.
//
// Prefixed element names are used rather than fully-qualified ones because
// Go's encoder repeats an xmlns declaration on every child of a namespaced
// element. That is valid and semantically identical, but metadata is a file an
// administrator reads and pastes into a console, and some validators are
// stricter than the specification about the shape they accept.
const (
	nsMetadata  = "urn:oasis:names:tc:SAML:2.0:metadata"
	nsSignature = "http://www.w3.org/2000/09/xmldsig#"
)

// Metadata documents describing a SAML entity (SAML 2.0 Metadata, section 2).
//
// These are marshalling shapes rather than the parsing ones above: what a
// consumer needs to read is a subset of what a producer must emit, and mixing
// the two would mean every optional element a parser ignores has to be
// modelled anyway.
type spMetadata struct {
	XMLName    xml.Name        `xml:"md:EntityDescriptor"`
	XMLNSMD    string          `xml:"xmlns:md,attr"`
	XMLNSDS    string          `xml:"xmlns:ds,attr"`
	EntityID   string          `xml:"entityID,attr"`
	Descriptor spSSODescriptor `xml:"md:SPSSODescriptor"`
}

type spSSODescriptor struct {
	AuthnRequestsSigned        bool              `xml:"AuthnRequestsSigned,attr"`
	WantAssertionsSigned       bool              `xml:"WantAssertionsSigned,attr"`
	ProtocolSupportEnumeration string            `xml:"protocolSupportEnumeration,attr"`
	KeyDescriptors             []keyDescriptor   `xml:"md:KeyDescriptor"`
	SingleLogoutServices       []indexedEndpoint `xml:"md:SingleLogoutService"`
	NameIDFormats              []string          `xml:"md:NameIDFormat"`
	AssertionConsumerServices  []indexedEndpoint `xml:"md:AssertionConsumerService"`
}

type idpMetadata struct {
	XMLName    xml.Name         `xml:"md:EntityDescriptor"`
	XMLNSMD    string           `xml:"xmlns:md,attr"`
	XMLNSDS    string           `xml:"xmlns:ds,attr"`
	EntityID   string           `xml:"entityID,attr"`
	Descriptor idpSSODescriptor `xml:"md:IDPSSODescriptor"`
}

type idpSSODescriptor struct {
	WantAuthnRequestsSigned    bool              `xml:"WantAuthnRequestsSigned,attr"`
	ProtocolSupportEnumeration string            `xml:"protocolSupportEnumeration,attr"`
	KeyDescriptors             []keyDescriptor   `xml:"md:KeyDescriptor"`
	SingleLogoutServices       []indexedEndpoint `xml:"md:SingleLogoutService"`
	NameIDFormats              []string          `xml:"md:NameIDFormat"`
	SingleSignOnServices       []indexedEndpoint `xml:"md:SingleSignOnService"`
}

type keyDescriptor struct {
	Use     string          `xml:"use,attr,omitempty"`
	KeyInfo metadataKeyInfo `xml:"ds:KeyInfo"`
}

type metadataKeyInfo struct {
	X509Data metadataX509Data `xml:"ds:X509Data"`
}

type metadataX509Data struct {
	X509Certificate string `xml:"ds:X509Certificate"`
}

type indexedEndpoint struct {
	Binding  string `xml:"Binding,attr"`
	Location string `xml:"Location,attr"`
	Index    *int   `xml:"index,attr,omitempty"`
}

// GetMetadata returns this service provider's SAML metadata document.
//
// It is the file an administrator uploads to an identity provider to complete
// a federation. Everything the identity provider needs to talk back is in it:
// the certificate to verify signed AuthnRequests against and to encrypt
// assertions to, where to send responses and logout messages, and which
// assurances this service provider expects.
//
// Elements are omitted rather than emitted empty when the corresponding
// configuration is absent. Advertising a logout endpoint that does not exist
// sends the identity provider's logout requests into a 404 and leaves it
// reporting the federation inconsistent, which is worse than not offering the
// capability.
func (sp *ServiceProvider) GetMetadata() ([]byte, error) {
	descriptor := spSSODescriptor{
		AuthnRequestsSigned:        sp.config.SignRequests,
		ProtocolSupportEnumeration: ProtocolSAML2,
		// This service provider refuses unsigned assertions unless the caller
		// explicitly allows them, so its metadata says so. An identity
		// provider reading false may send unsigned assertions that are then
		// rejected -- an integration that fails at the last step, with the
		// cause in a file nobody re-reads.
		WantAssertionsSigned: true,
	}

	index := 0
	descriptor.AssertionConsumerServices = []indexedEndpoint{{
		Binding:  BindingHTTPPost,
		Location: sp.config.ACSUrl,
		Index:    &index,
	}}

	if sp.config.SLOUrl != "" {
		descriptor.SingleLogoutServices = []indexedEndpoint{
			{Binding: BindingHTTPRedirect, Location: sp.config.SLOUrl},
			{Binding: BindingHTTPPost, Location: sp.config.SLOUrl},
		}
	}

	nameIDFormat := sp.config.NameIDFormat
	if nameIDFormat == "" {
		nameIDFormat = NameIDFormatUnspecified
	}
	descriptor.NameIDFormats = []string{nameIDFormat}

	// A single certificate is advertised for both uses, which is the common
	// deployment. A separate encryption certificate replaces it for that use
	// when one is configured.
	if sp.config.Certificate != nil {
		descriptor.KeyDescriptors = append(descriptor.KeyDescriptors,
			newKeyDescriptor("signing", sp.config.Certificate))

		encryption := sp.config.EncryptionCertificate
		if encryption == nil {
			encryption = sp.config.Certificate
		}
		descriptor.KeyDescriptors = append(descriptor.KeyDescriptors,
			newKeyDescriptor("encryption", encryption))
	}

	return marshalMetadata(spMetadata{
		XMLNSMD:    nsMetadata,
		XMLNSDS:    nsSignature,
		EntityID:   sp.config.EntityID,
		Descriptor: descriptor,
	})
}

// GetMetadata returns this identity provider's SAML metadata document.
//
// A service provider reads it to learn which certificate verifies this
// provider's assertions and where to send requests.
func (idp *IdentityProvider) GetMetadata() ([]byte, error) {
	descriptor := idpSSODescriptor{
		ProtocolSupportEnumeration: ProtocolSAML2,
		SingleSignOnServices: []indexedEndpoint{
			{Binding: BindingHTTPRedirect, Location: idp.config.SSOUrl},
			{Binding: BindingHTTPPost, Location: idp.config.SSOUrl},
		},
		NameIDFormats: []string{NameIDFormatUnspecified},
	}

	if idp.config.SLOUrl != "" {
		descriptor.SingleLogoutServices = []indexedEndpoint{
			{Binding: BindingHTTPRedirect, Location: idp.config.SLOUrl},
			{Binding: BindingHTTPPost, Location: idp.config.SLOUrl},
		}
	}

	if idp.config.Certificate != nil {
		descriptor.KeyDescriptors = append(descriptor.KeyDescriptors,
			newKeyDescriptor("signing", idp.config.Certificate))
	}

	return marshalMetadata(idpMetadata{
		XMLNSMD:    nsMetadata,
		XMLNSDS:    nsSignature,
		EntityID:   idp.config.EntityID,
		Descriptor: descriptor,
	})
}

func newKeyDescriptor(use string, cert *x509.Certificate) keyDescriptor {
	return keyDescriptor{
		Use: use,
		KeyInfo: metadataKeyInfo{
			X509Data: metadataX509Data{
				X509Certificate: base64.StdEncoding.EncodeToString(cert.Raw),
			},
		},
	}
}

// marshalMetadata renders a document with the XML declaration consumers expect
// on an uploaded file.
func marshalMetadata(document any) ([]byte, error) {
	body, err := xml.MarshalIndent(document, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("saml: marshal metadata: %w", err)
	}
	return append([]byte(xml.Header), body...), nil
}
