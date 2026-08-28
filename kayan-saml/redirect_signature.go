package saml

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"

	// Registers the digests the signature algorithms below use.
	_ "crypto/sha256"
	_ "crypto/sha512"
)

// Signature algorithm identifiers for the HTTP-Redirect binding.
const (
	// SigAlgRSASHA256 is the default and what identity providers expect.
	SigAlgRSASHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"

	// SigAlgRSASHA512 is accepted for deployments that require it.
	SigAlgRSASHA512 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"

	// SigAlgRSASHA1 is refused. It is listed so the refusal can name it.
	SigAlgRSASHA1 = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
)

// ErrNoRedirectSigner is returned when signing is required but no signer is
// available.
var ErrNoRedirectSigner = errors.New("saml: signing is configured but no signer is available")

// RedirectSigner signs a message for the HTTP-Redirect binding.
//
// This is a different operation from [Signer], and the two are not
// interchangeable. Signer produces an enveloped XML-DSig signature inside the
// document. The redirect binding instead signs a detached octet string built
// from the URL query, and carries the result in SigAlg and Signature
// parameters, because a DEFLATE-compressed message has no XML for a signature
// to live in by the time it reaches the wire.
//
// Implement it to keep the key in an HSM or KMS, exactly as [Signer] allows.
type RedirectSigner interface {
	// SignRedirect signs a redirect-binding query.
	//
	// The implementation chooses its algorithm, calls build with that
	// algorithm's URI to obtain the exact octets to sign, and returns both the
	// algorithm and the signature.
	//
	// Algorithm and signature come from one call on purpose. SigAlg is itself
	// part of the signed octets, so an interface that reported the algorithm
	// separately would let the two disagree -- a signature whose declared
	// algorithm is not the one used. A strict verifier rejects every such
	// request; a lenient one accepts a downgrade the service provider never
	// chose. The single call makes that unrepresentable.
	SignRedirect(ctx context.Context, build func(sigAlg string) []byte) (sigAlg string, signature []byte, err error)
}

// RSARedirectSigner signs redirect-binding queries with an RSA key.
type RSARedirectSigner struct {
	key  *rsa.PrivateKey
	alg  string
	hash crypto.Hash
}

var _ RedirectSigner = (*RSARedirectSigner)(nil)

// NewRSARedirectSigner returns a signer for the given key and algorithm.
//
// signatureMethod is a SigAlg URI; empty selects [SigAlgRSASHA256]. RSA-SHA1 is
// refused rather than silently upgraded: an operator who configured it is
// entitled to know their stated policy is not being applied, and quietly
// substituting a different algorithm is how a deployment comes to believe a
// cryptographic policy is in force that is not.
func NewRSARedirectSigner(key *rsa.PrivateKey, signatureMethod string) (*RSARedirectSigner, error) {
	if key == nil {
		return nil, errors.New("saml: nil signing key")
	}

	switch signatureMethod {
	case "", SigAlgRSASHA256:
		return &RSARedirectSigner{key: key, alg: SigAlgRSASHA256, hash: crypto.SHA256}, nil
	case SigAlgRSASHA512:
		return &RSARedirectSigner{key: key, alg: SigAlgRSASHA512, hash: crypto.SHA512}, nil
	case SigAlgRSASHA1:
		return nil, fmt.Errorf("saml: RSA-SHA1 is not supported for request signing; "+
			"SHA-1 is not collision resistant and %q or %q should be configured instead",
			SigAlgRSASHA256, SigAlgRSASHA512)
	default:
		return nil, fmt.Errorf("saml: unsupported signature method %q", signatureMethod)
	}
}

// SignRedirect implements [RedirectSigner].
func (s *RSARedirectSigner) SignRedirect(_ context.Context, build func(sigAlg string) []byte) (string, []byte, error) {
	octets := build(s.alg)

	hasher := s.hash.New()
	hasher.Write(octets)

	signature, err := rsa.SignPKCS1v15(rand.Reader, s.key, s.hash, hasher.Sum(nil))
	if err != nil {
		return "", nil, fmt.Errorf("saml: sign redirect query: %w", err)
	}
	return s.alg, signature, nil
}

// redirectSignedOctets builds the exact octet string a redirect-binding
// signature covers (SAML 2.0 Bindings section 3.4.4.1).
//
// The parameters appear in this order, URL-encoded, with RelayState omitted
// when absent, and Signature never included -- it is the output. The order is
// fixed by the specification rather than by the query the caller happens to
// build, so this cannot be produced with url.Values.Encode, which sorts keys
// alphabetically and would yield a string no identity provider can verify.
func redirectSignedOctets(messageParam, message, relayState, sigAlg string) []byte {
	var b strings.Builder
	b.WriteString(messageParam)
	b.WriteString("=")
	b.WriteString(url.QueryEscape(message))
	if relayState != "" {
		b.WriteString("&RelayState=")
		b.WriteString(url.QueryEscape(relayState))
	}
	b.WriteString("&SigAlg=")
	b.WriteString(url.QueryEscape(sigAlg))
	return []byte(b.String())
}

// reservedRedirectParams are the query parameters the binding owns.
var reservedRedirectParams = []string{"SAMLRequest", "SAMLResponse", "RelayState", "SigAlg", "Signature"}

// redirectURL builds a redirect-binding URL, signing it when a signer is given.
//
// The endpoint is rejected when it already carries a parameter this binding
// owns. That check applies whether or not the message is signed: a duplicated
// SAMLRequest is HTTP parameter pollution, and which copy a recipient reads is
// a property of their parser rather than anything this library controls.
func redirectURL(
	ctx context.Context,
	endpoint, messageParam, message, relayState string,
	signer RedirectSigner,
) (string, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("saml: parse endpoint: %w", err)
	}

	existing := parsed.Query()
	for _, name := range reservedRedirectParams {
		if existing.Has(name) {
			return "", fmt.Errorf("saml: endpoint %q already carries the %s parameter", endpoint, name)
		}
	}

	// Built by hand rather than with url.Values.Encode, because the signature
	// covers this exact string in this exact order and Encode sorts keys.
	var query strings.Builder
	if prior := parsed.RawQuery; prior != "" {
		query.WriteString(prior)
		query.WriteString("&")
	}
	query.WriteString(messageParam)
	query.WriteString("=")
	query.WriteString(url.QueryEscape(message))
	if relayState != "" {
		query.WriteString("&RelayState=")
		query.WriteString(url.QueryEscape(relayState))
	}

	if signer != nil {
		sigAlg, signature, err := signer.SignRedirect(ctx, func(alg string) []byte {
			return redirectSignedOctets(messageParam, message, relayState, alg)
		})
		if err != nil {
			return "", err
		}
		if sigAlg == "" {
			return "", errors.New("saml: signer returned no signature algorithm")
		}
		query.WriteString("&SigAlg=")
		query.WriteString(url.QueryEscape(sigAlg))
		query.WriteString("&Signature=")
		query.WriteString(url.QueryEscape(base64.StdEncoding.EncodeToString(signature)))
	}

	parsed.RawQuery = query.String()
	return parsed.String(), nil
}
