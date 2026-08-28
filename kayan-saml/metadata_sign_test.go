package saml

import (
	"context"
	"crypto/x509"
	"encoding/xml"
	"errors"
	"strings"
	"testing"
	"time"
)

// parsedMetadata reads a metadata document back.
//
// The marshalling structs name their root "md:EntityDescriptor" -- a prefix
// baked into the element name rather than a real namespace binding -- so they
// cannot unmarshal what they produce. This mirrors only what the tests assert.
type parsedMetadata struct {
	XMLName    xml.Name `xml:"EntityDescriptor"`
	EntityID   string   `xml:"entityID,attr"`
	ID         string   `xml:"ID,attr"`
	ValidUntil string   `xml:"validUntil,attr"`
	Descriptor struct {
		AssertionConsumerServices []struct {
			Location string `xml:"Location,attr"`
		} `xml:"AssertionConsumerService"`
		KeyDescriptors []struct {
			Use string `xml:"use,attr"`
		} `xml:"KeyDescriptor"`
	} `xml:"SPSSODescriptor"`
}

// metadataSP returns a service provider with a signer, plus one without.
func metadataSP(t *testing.T) (signed *ServiceProvider, unsigned *ServiceProvider, cert *x509.Certificate) {
	t.Helper()
	signer, cert := testSigner(t)

	config := Config{
		EntityID:    testSPEntityID,
		ACSUrl:      testACSUrl,
		SLOUrl:      "http://sp.example.com/slo",
		Certificate: cert,
	}
	signed = NewServiceProvider(config, newMockSessionStore(), newMockIdentityRepo(),
		func() any { return &mockUser{} }, WithSPSigner(signer))
	unsigned = NewServiceProvider(config, newMockSessionStore(), newMockIdentityRepo(),
		func() any { return &mockUser{} })
	return signed, unsigned, cert
}

// TestSignedMetadataCarriesASignature is the point of the feature.
//
// A peer that fetched metadata over a network it does not control has nothing
// binding the certificate inside the document to the entity that claims it,
// except the transport. A federation that accepts metadata from a registry or
// by email has not even that, and will refuse an unsigned document.
func TestSignedMetadataCarriesASignature(t *testing.T) {
	sp, _, _ := metadataSP(t)

	doc, err := sp.SignedMetadata(context.Background(), time.Time{})
	if err != nil {
		t.Fatalf("SignedMetadata: %v", err)
	}

	raw := string(doc)
	if !strings.Contains(raw, "Signature") {
		t.Fatalf("the signed document carries no Signature element: %s", raw)
	}
	if !strings.Contains(raw, "SignatureValue") {
		t.Error("the Signature element carries no SignatureValue")
	}
	// The reference has to name the element it covers, or the signature says
	// nothing about which part of the document it protects.
	if !strings.Contains(raw, "URI=\"#"+metadataID(testSPEntityID)+"\"") {
		t.Errorf("the signature does not reference the EntityDescriptor by ID: %s", raw)
	}
}

// TestSignedMetadataVerifies checks the signature against the certificate the
// document itself advertises, which is what a peer does with it.
func TestSignedMetadataVerifies(t *testing.T) {
	sp, _, cert := metadataSP(t)

	doc, err := sp.SignedMetadata(context.Background(), time.Time{})
	if err != nil {
		t.Fatalf("SignedMetadata: %v", err)
	}

	verifier := NewXMLDSigVerifier()
	if _, err := verifier.Verify(context.Background(), doc, []*x509.Certificate{cert}); err != nil {
		t.Fatalf("the signed metadata does not verify against its own certificate: %v", err)
	}
}

// TestMetadataWithoutASignerFailsClosed.
//
// Returning the unsigned document would be the dangerous answer: a federation
// that requires signed metadata rejects it, and the operator is left
// debugging a file that looks entirely correct.
func TestMetadataWithoutASignerFailsClosed(t *testing.T) {
	_, sp, _ := metadataSP(t)

	doc, err := sp.SignedMetadata(context.Background(), time.Time{})
	if err == nil {
		t.Fatal("unsigned metadata was returned from SignedMetadata")
	}
	if doc != nil {
		t.Error("a document was returned alongside the error")
	}
	if !errors.Is(err, ErrNoMetadataSigner) {
		t.Errorf("error = %v, want ErrNoMetadataSigner", err)
	}
}

// TestSignedAndUnsignedMetadataDescribeTheSameEntity.
//
// The two renderings share one builder. If they did not, a deployment could
// publish a signed document that advertises different endpoints or a different
// certificate from the one its own unsigned endpoint serves, and only a peer
// comparing both would ever notice.
func TestSignedAndUnsignedMetadataDescribeTheSameEntity(t *testing.T) {
	sp, _, _ := metadataSP(t)

	unsigned, err := sp.GetMetadata()
	if err != nil {
		t.Fatalf("GetMetadata: %v", err)
	}
	signed, err := sp.SignedMetadata(context.Background(), time.Time{})
	if err != nil {
		t.Fatalf("SignedMetadata: %v", err)
	}

	var a, b parsedMetadata
	if err := xml.Unmarshal(unsigned, &a); err != nil {
		t.Fatalf("unmarshal unsigned: %v", err)
	}
	if err := xml.Unmarshal(signed, &b); err != nil {
		t.Fatalf("unmarshal signed: %v", err)
	}

	if a.EntityID != b.EntityID {
		t.Errorf("entityID differs: %q and %q", a.EntityID, b.EntityID)
	}
	if a.ID != b.ID {
		t.Errorf("ID differs: %q and %q", a.ID, b.ID)
	}
	if len(a.Descriptor.AssertionConsumerServices) != len(b.Descriptor.AssertionConsumerServices) {
		t.Fatal("the two documents advertise different ACS endpoint counts")
	}
	for i := range a.Descriptor.AssertionConsumerServices {
		if a.Descriptor.AssertionConsumerServices[i].Location !=
			b.Descriptor.AssertionConsumerServices[i].Location {
			t.Errorf("ACS %d differs: %q and %q", i,
				a.Descriptor.AssertionConsumerServices[i].Location,
				b.Descriptor.AssertionConsumerServices[i].Location)
		}
	}
	if len(a.Descriptor.KeyDescriptors) != len(b.Descriptor.KeyDescriptors) {
		t.Error("the two documents advertise different key descriptors")
	}
}

// TestValidUntilIsEmittedInUTC.
//
// Metadata with no expiry stays authoritative forever, so a certificate
// rotated out of it is still trusted by any peer holding an old copy. A
// local-zone offset is legal XML but read inconsistently by federation
// tooling, so the value is normalised rather than passed through.
func TestValidUntilIsEmittedInUTC(t *testing.T) {
	sp, _, _ := metadataSP(t)

	zone := time.FixedZone("UTC+7", 7*3600)
	expiry := time.Date(2027, 3, 4, 5, 6, 7, 0, zone)

	doc, err := sp.SignedMetadata(context.Background(), expiry)
	if err != nil {
		t.Fatalf("SignedMetadata: %v", err)
	}

	var parsed parsedMetadata
	if err := xml.Unmarshal(doc, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if parsed.ValidUntil != expiry.UTC().Format(time.RFC3339) {
		t.Errorf("validUntil = %q, want %q", parsed.ValidUntil, expiry.UTC().Format(time.RFC3339))
	}
	if strings.HasSuffix(parsed.ValidUntil, "+07:00") {
		t.Error("validUntil kept a local zone offset")
	}
}

// TestUnsignedMetadataHasNoValidUntil. A zero time means the caller declined
// to set an expiry; emitting a zero-valued one instead would publish a
// document that expired in the year 1.
func TestUnsignedMetadataHasNoValidUntil(t *testing.T) {
	_, sp, _ := metadataSP(t)

	doc, err := sp.GetMetadata()
	if err != nil {
		t.Fatalf("GetMetadata: %v", err)
	}
	if strings.Contains(string(doc), "validUntil") {
		t.Errorf("a document with no expiry emitted validUntil: %s", doc)
	}
}

// TestMetadataIDIsStable. A peer diffing two fetches should see only real
// changes; an ID regenerated per call makes every fetch look like a change and
// invalidates any cached signature comparison.
func TestMetadataIDIsStable(t *testing.T) {
	sp, _, _ := metadataSP(t)

	first, err := sp.GetMetadata()
	if err != nil {
		t.Fatalf("GetMetadata: %v", err)
	}
	second, err := sp.GetMetadata()
	if err != nil {
		t.Fatalf("GetMetadata: %v", err)
	}
	if string(first) != string(second) {
		t.Error("two consecutive metadata documents differ")
	}

	var parsed parsedMetadata
	if err := xml.Unmarshal(first, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if parsed.ID == "" {
		t.Error("the EntityDescriptor carries no ID, so a signature would have nothing to reference")
	}
}
