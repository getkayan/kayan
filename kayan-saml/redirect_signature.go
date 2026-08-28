package saml

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
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

// ErrNoRedirectSignature reports a redirect-binding message carrying no
// detached signature.
var ErrNoRedirectSignature = errors.New("saml: redirect message carries no signature")

// VerifyRedirectSignature checks the detached signature on a redirect-binding
// query against a set of certificates.
//
// The redirect binding puts its signature in the URL rather than in the
// document, so the enveloped XML-DSig verifier cannot check it: a redirect
// message is DEFLATE-compressed and has no XML for a signature to live in.
// Without this, a service provider advertising a Redirect binding for single
// logout rejects every redirect-bound LogoutRequest it receives with
// ErrUnsigned -- an advertised capability that cannot work.
//
// Any of certs verifying is enough, which is what lets an identity provider
// roll its signing key over: during the overlap it publishes both, and either
// may have signed the message in hand.
func VerifyRedirectSignature(rawQuery string, certs []*x509.Certificate) error {
	if len(certs) == 0 {
		return errors.New("saml: no certificates configured for this issuer")
	}

	encodedSig, ok := rawQueryValue(rawQuery, "Signature")
	if !ok || encodedSig == "" {
		return ErrNoRedirectSignature
	}
	rawSigAlg, ok := rawQueryValue(rawQuery, "SigAlg")
	if !ok || rawSigAlg == "" {
		return fmt.Errorf("%w: no SigAlg parameter", ErrNoRedirectSignature)
	}

	sigAlg, err := url.QueryUnescape(rawSigAlg)
	if err != nil {
		return fmt.Errorf("saml: decode SigAlg: %w", err)
	}

	var hash crypto.Hash
	switch sigAlg {
	case SigAlgRSASHA256:
		hash = crypto.SHA256
	case SigAlgRSASHA512:
		hash = crypto.SHA512
	default:
		// RSA-SHA1 lands here deliberately. Accepting it on the reading side
		// would let an identity provider downgrade the algorithm unilaterally,
		// which is the whole value of refusing it on the writing side.
		return fmt.Errorf("%w: SigAlg %q", ErrUnsupportedAlgorithm, sigAlg)
	}

	unescaped, err := url.QueryUnescape(encodedSig)
	if err != nil {
		return fmt.Errorf("saml: decode Signature: %w", err)
	}
	signature, err := base64.StdEncoding.DecodeString(unescaped)
	if err != nil {
		return fmt.Errorf("saml: Signature is not valid base64: %w", err)
	}

	octets, err := redirectVerificationOctets(rawQuery)
	if err != nil {
		return err
	}

	hasher := hash.New()
	hasher.Write(octets)
	digest := hasher.Sum(nil)

	for _, cert := range certs {
		pub, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			continue
		}
		if err := rsa.VerifyPKCS1v15(pub, hash, digest, signature); err == nil {
			return nil
		}
	}
	return errors.New("saml: redirect signature does not verify against any configured certificate")
}

// redirectVerificationOctets rebuilds the octet string a redirect signature
// covers, from the raw query as received.
//
// It reassembles from the raw parameter values in the order the specification
// fixes, rather than taking everything before "&Signature=". Signature is
// usually last, but a sender that places it elsewhere would otherwise produce
// a verification failure that looks like a bad key -- and the values must stay
// exactly as they arrived, since re-encoding a decoded value can differ from
// the octets that were signed.
func redirectVerificationOctets(rawQuery string) ([]byte, error) {
	var b strings.Builder

	messageParam := "SAMLRequest"
	message, ok := rawQueryValue(rawQuery, messageParam)
	if !ok {
		messageParam = "SAMLResponse"
		message, ok = rawQueryValue(rawQuery, messageParam)
	}
	if !ok {
		return nil, errors.New("saml: query carries neither SAMLRequest nor SAMLResponse")
	}

	b.WriteString(messageParam)
	b.WriteString("=")
	b.WriteString(message)

	if relayState, ok := rawQueryValue(rawQuery, "RelayState"); ok {
		b.WriteString("&RelayState=")
		b.WriteString(relayState)
	}

	sigAlg, _ := rawQueryValue(rawQuery, "SigAlg")
	b.WriteString("&SigAlg=")
	b.WriteString(sigAlg)

	return []byte(b.String()), nil
}

// rawQueryValue returns the still-encoded value of a parameter.
//
// url.Values would decode, and the signature covers the encoded octets: a
// value that survives a decode/encode round trip unchanged is common but not
// guaranteed, and where it differs the signature fails for a reason nobody
// can see.
func rawQueryValue(rawQuery, name string) (string, bool) {
	for _, pair := range strings.Split(rawQuery, "&") {
		eq := strings.Index(pair, "=")
		if eq < 0 {
			continue
		}
		if pair[:eq] == name {
			return pair[eq+1:], true
		}
	}
	return "", false
}
