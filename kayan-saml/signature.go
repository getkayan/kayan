package saml

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

// Errors reported by signature handling.
var (
	// ErrUnsigned reports a document carrying no signature.
	ErrUnsigned = errors.New("saml: document is not signed")
	// ErrInvalidSignature reports a signature that did not verify.
	ErrInvalidSignature = errors.New("saml: signature verification failed")
	// ErrNoSigner reports that signing was requested with no signer configured.
	ErrNoSigner = errors.New("saml: no signer configured")
	// ErrNoVerifier reports that verification was requested with no verifier.
	ErrNoVerifier = errors.New("saml: no signature verifier configured")
)

// ValidatedDocument is the portion of a SAML message whose signature has been
// verified.
//
// Claims must be read only from here. The unverified document is not carried
// alongside it, so the Signature Wrapping family of attacks — where a valid
// signature covers a decoy element while the parser reads an attacker's
// injected one — cannot be expressed: there is no unverified tree to read.
type ValidatedDocument struct {
	// Element is the signed element, as verified.
	Element *etree.Element

	// XML is Element serialized. Unmarshal from this, never from the original
	// request body.
	XML []byte

	// SignedAssertion reports whether the verified element was an Assertion
	// rather than the enclosing Response.
	SignedAssertion bool

	// CoveredResponse reports whether the signature covered the enclosing
	// Response. When it did, the response's own attributes — Destination,
	// InResponseTo, Issuer — are authenticated and may be validated. When only
	// the assertion was signed they are attacker-controlled and must not be.
	CoveredResponse bool
}

// SignatureVerifier verifies the XML signature on a SAML message.
//
// XML-DSig is the only signature format SAML defines, so the format is not
// configurable — but the implementation is. Supply your own to verify through
// an HSM, to pin a policy the default does not express, or to use a different
// library.
//
// Implementations must:
//   - reject a document with no signature;
//   - verify the signature against the supplied certificates only;
//   - return the *signed* element, so callers cannot read unsigned content.
type SignatureVerifier interface {
	Verify(ctx context.Context, doc []byte, certs []*x509.Certificate) (*ValidatedDocument, error)
}

// Signer signs an outgoing SAML message.
//
// Implement it to keep the private key in an HSM or KMS: Kayan calls Sign and
// never holds key material.
type Signer interface {
	Sign(ctx context.Context, doc []byte) ([]byte, error)
}

// XMLDSigVerifier verifies signatures with goxmldsig.
//
// It is the default [SignatureVerifier].
type XMLDSigVerifier struct {
	allowUnsigned bool
	idAttribute   string
}

var _ SignatureVerifier = (*XMLDSigVerifier)(nil)

// VerifierOption configures an [XMLDSigVerifier].
type VerifierOption func(*XMLDSigVerifier)

// WithAllowUnsigned accepts documents carrying no signature.
//
// This disables authentication of the assertion entirely: anyone able to reach
// the assertion consumer endpoint can then assert any identity. It exists for
// interoperability testing against a local IdP. Never enable it in production.
func WithAllowUnsigned() VerifierOption {
	return func(v *XMLDSigVerifier) { v.allowUnsigned = true }
}

// WithIDAttribute sets the attribute used to resolve signature references.
// Defaults to "ID", which is what SAML 2.0 uses.
func WithIDAttribute(name string) VerifierOption {
	return func(v *XMLDSigVerifier) { v.idAttribute = name }
}

// NewXMLDSigVerifier returns a verifier that requires a valid signature.
func NewXMLDSigVerifier(opts ...VerifierOption) *XMLDSigVerifier {
	v := &XMLDSigVerifier{idAttribute: "ID"}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// Verify implements [SignatureVerifier].
//
// It returns the element the signature actually covers. When a Response and
// its Assertion are both signed, the Assertion is returned, since that is the
// element carrying the identity claims.
func (v *XMLDSigVerifier) Verify(_ context.Context, doc []byte, certs []*x509.Certificate) (*ValidatedDocument, error) {
	if len(doc) == 0 {
		return nil, fmt.Errorf("%w: empty document", ErrInvalidSignature)
	}

	parsed := etree.NewDocument()
	if err := parsed.ReadFromBytes(doc); err != nil {
		return nil, fmt.Errorf("saml: parse document: %w", err)
	}
	root := parsed.Root()
	if root == nil {
		return nil, fmt.Errorf("saml: document has no root element")
	}

	if !hasSignature(root) {
		if v.allowUnsigned {
			return documentFrom(root, false, true)
		}
		return nil, ErrUnsigned
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("%w: no certificates configured for this issuer", ErrInvalidSignature)
	}

	ctx := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{
		Roots: certs,
	})
	ctx.IdAttribute = v.idAttribute

	// Prefer the Assertion when it carries its own signature: it is the
	// element that asserts the identity, and verifying the Response alone
	// would leave the Assertion unverified.
	if assertion := findSignedAssertion(root); assertion != nil {
		validated, err := ctx.Validate(assertion)
		if err != nil {
			return nil, fmt.Errorf("%w: assertion: %w", ErrInvalidSignature, err)
		}
		return documentFrom(validated, true, false)
	}

	validated, err := ctx.Validate(root)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidSignature, err)
	}

	// The Response was signed, so its attributes are authenticated and the
	// Assertion is covered as a descendant of the verified element. Read the
	// assertion from the validated tree.
	if assertion := validated.FindElement("./Assertion"); assertion != nil {
		return documentFrom(assertion, true, true)
	}
	return documentFrom(validated, false, true)
}

// hasSignature reports whether el or a direct child carries a Signature.
func hasSignature(el *etree.Element) bool {
	for _, child := range el.ChildElements() {
		if child.Tag == "Signature" {
			return true
		}
		if child.Tag == "Assertion" && hasSignature(child) {
			return true
		}
	}
	return false
}

// findSignedAssertion returns the Assertion child carrying its own signature.
func findSignedAssertion(root *etree.Element) *etree.Element {
	if root.Tag == "Assertion" && hasSignature(root) {
		return root
	}
	for _, child := range root.ChildElements() {
		if child.Tag == "Assertion" && hasSignature(child) {
			return child
		}
	}
	return nil
}

// documentFrom serializes a verified element.
func documentFrom(el *etree.Element, isAssertion, coveredResponse bool) (*ValidatedDocument, error) {
	doc := etree.NewDocument()
	doc.SetRoot(el.Copy())

	raw, err := doc.WriteToBytes()
	if err != nil {
		return nil, fmt.Errorf("saml: serialize validated element: %w", err)
	}
	return &ValidatedDocument{
		Element:         el,
		XML:             raw,
		SignedAssertion: isAssertion,
		CoveredResponse: coveredResponse,
	}, nil
}

// XMLDSigSigner signs documents with goxmldsig.
//
// It is the default [Signer].
type XMLDSigSigner struct {
	context *dsig.SigningContext
}

var _ Signer = (*XMLDSigSigner)(nil)

// NewXMLDSigSigner returns a signer using key and cert.
//
// Signatures are RSA-SHA256. To use a different algorithm, an HSM, or a KMS,
// implement [Signer] directly.
func NewXMLDSigSigner(key *rsa.PrivateKey, cert *x509.Certificate) (*XMLDSigSigner, error) {
	if key == nil {
		return nil, errors.New("saml: nil signing key")
	}
	if cert == nil {
		return nil, errors.New("saml: nil signing certificate")
	}

	store := dsig.TLSCertKeyStore(tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  key,
	})

	ctx, err := dsig.NewSigningContext(key, [][]byte{cert.Raw})
	if err != nil {
		return nil, fmt.Errorf("saml: build signing context: %w", err)
	}
	ctx.KeyStore = store
	if err := ctx.SetSignatureMethod(dsig.RSASHA256SignatureMethod); err != nil {
		return nil, fmt.Errorf("saml: set signature method: %w", err)
	}

	return &XMLDSigSigner{context: ctx}, nil
}

// Sign implements [Signer].
func (s *XMLDSigSigner) Sign(_ context.Context, doc []byte) ([]byte, error) {
	parsed := etree.NewDocument()
	if err := parsed.ReadFromBytes(doc); err != nil {
		return nil, fmt.Errorf("saml: parse document for signing: %w", err)
	}
	root := parsed.Root()
	if root == nil {
		return nil, errors.New("saml: document has no root element")
	}

	signed, err := s.context.SignEnveloped(root)
	if err != nil {
		return nil, fmt.Errorf("saml: sign document: %w", err)
	}

	out := etree.NewDocument()
	out.SetRoot(signed)
	raw, err := out.WriteToBytes()
	if err != nil {
		return nil, fmt.Errorf("saml: serialize signed document: %w", err)
	}
	return raw, nil
}
