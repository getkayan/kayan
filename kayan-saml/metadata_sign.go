package saml

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// ErrNoMetadataSigner reports that a signed metadata document was requested
// but no signer is configured.
//
// It fails closed rather than returning the unsigned document. A federation
// that requires signed metadata rejects an unsigned one, and returning it
// anyway turns a configuration mistake into an onboarding failure whose cause
// is a file that looks correct.
var ErrNoMetadataSigner = errors.New("saml: signed metadata requires a signer")

// SignedMetadata returns this service provider's metadata with an enveloped
// XML-DSig signature over the EntityDescriptor.
//
// Signed metadata is what lets a peer trust a document it fetched over a
// network it does not control. Without a signature the only thing binding the
// certificate in the document to this entity is the TLS connection it arrived
// over -- and a federation operator who accepts metadata by email, or from a
// registry, has not even that.
//
// validUntil bounds how long the document may be believed. A zero value omits
// the attribute, which some federations refuse: metadata with no expiry
// remains authoritative forever, so a certificate rotated out of it stays
// trusted by any peer that keeps the old copy.
//
// Requires [WithSPSigner].
func (sp *ServiceProvider) SignedMetadata(ctx context.Context, validUntil time.Time) ([]byte, error) {
	if sp.signer == nil {
		return nil, fmt.Errorf("%w: supply WithSPSigner", ErrNoMetadataSigner)
	}

	document, err := sp.metadataDocument(validUntil)
	if err != nil {
		return nil, err
	}
	return signMetadata(ctx, sp.signer, document)
}

// SignedMetadata returns this identity provider's metadata with an enveloped
// XML-DSig signature over the EntityDescriptor.
//
// Requires a signer, which [NewIdentityProvider] builds from the configured
// key pair when one is present.
func (idp *IdentityProvider) SignedMetadata(ctx context.Context, validUntil time.Time) ([]byte, error) {
	if idp.signer == nil {
		return nil, fmt.Errorf("%w: supply WithIdPSigner or configure a key pair", ErrNoMetadataSigner)
	}

	document, err := idp.metadataDocument(validUntil)
	if err != nil {
		return nil, err
	}
	return signMetadata(ctx, idp.signer, document)
}

// signMetadata renders and signs a metadata document.
//
// The document is marshalled without the XML declaration, because the signer
// parses it as a tree and re-serialises it; a declaration written here would
// be discarded and the caller would receive a document that differs from what
// was signed in a way that is easy to mistake for a canonicalisation bug.
func signMetadata(ctx context.Context, signer Signer, document any) ([]byte, error) {
	raw, err := marshalMetadataBody(document)
	if err != nil {
		return nil, err
	}

	signed, err := signer.Sign(ctx, raw)
	if err != nil {
		return nil, fmt.Errorf("saml: sign metadata: %w", err)
	}
	return signed, nil
}

// metadataID builds the ID attribute an XML-DSig reference points at.
//
// A signature references the element it covers by ID. Without one the
// reference has nothing to name, and goxmldsig signs an empty URI -- a
// document whose signature covers, formally, the whole document, which some
// verifiers accept and others refuse. Deriving it from the entity ID keeps it
// stable across regenerations, so a peer diffing two fetches sees only real
// changes.
func metadataID(entityID string) string {
	return "_" + hashHex(entityID)
}
