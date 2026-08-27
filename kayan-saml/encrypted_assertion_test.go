package saml

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// These tests cover the end-to-end path: what ProcessResponse does with a
// response carrying an EncryptedAssertion.
//
// The mistake this file exists to prevent is treating decryption as
// authentication. Anyone can encrypt to a service provider's public key --
// it is published in its metadata, that is the point of it -- so a decrypted
// assertion proves only that somebody had the public key. It has to be
// verified afterwards exactly like a plaintext one.

// encryptedResponse wraps an assertion's XML in an EncryptedAssertion inside a
// SAML Response envelope, the way an identity provider does.
func encryptedResponse(t testing.TB, pub *rsa.PublicKey, assertionXML string) string {
	t.Helper()

	encrypted := encryptAssertion(t, pub, []byte(assertionXML), encryptOptions{})
	envelope := fmt.Sprintf(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
  ID="_response-1" InResponseTo="%s" Version="2.0" Destination="%s">
  <saml:Issuer>%s</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value="%s"/></samlp:Status>
  <saml:EncryptedAssertion>%s</saml:EncryptedAssertion>
</samlp:Response>`,
		testRequestID, testACSUrl, testIdPEntity, StatusSuccess, encrypted)

	return base64.StdEncoding.EncodeToString([]byte(envelope))
}

// signedAssertionXML returns an assertion signed by the harness's IdP, as the
// standalone element that would be encrypted.
func signedAssertionXML(t testing.TB, h *attackHarness) string {
	t.Helper()

	resp := validResponse()
	raw, err := xml.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	signed, err := h.signer.Sign(h.context, raw)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return string(signed)
}

// TestEncryptedResponseWithoutADecrypterIsRefused covers the misconfiguration.
//
// An identity provider configured to encrypt, talking to a service provider
// with no decrypter, must produce a clear failure. Ignoring the encrypted
// element would surface as a login that fails for no stated reason, and the
// operator would have no way to tell that encryption is why.
func TestEncryptedResponseWithoutADecrypterIsRefused(t *testing.T) {
	h := newAttackHarness(t)
	spKey, _ := testKeyPair(t)

	response := encryptedResponse(t, &spKey.PublicKey, signedAssertionXML(t, h))

	_, err := h.sp.ProcessResponse(h.context, response, testSessionID)
	if !errors.Is(err, ErrNoDecrypter) {
		t.Errorf("error = %v, want ErrNoDecrypter", err)
	}
}

// TestDecryptedAssertionMustBeSigned is the central test of this file.
//
// Encrypting to a service provider requires only its public key, which is
// published. If a decrypted assertion were accepted without verifying the
// signature inside it, anyone could mint an assertion for any user, encrypt
// it, and post it to the ACS endpoint -- a complete authentication bypass
// requiring no secret at all.
func TestDecryptedAssertionMustBeSigned(t *testing.T) {
	h := newAttackHarness(t)
	spKey, _ := testKeyPair(t)
	decrypter, err := NewRSADecrypter(spKey)
	if err != nil {
		t.Fatalf("NewRSADecrypter: %v", err)
	}
	h.sp.decrypter = decrypter

	// An assertion the attacker wrote: well-formed, correctly addressed, and
	// carrying no signature.
	forged := fmt.Sprintf(`<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
  ID="_forged" Version="2.0" IssueInstant="2026-01-01T00:00:00Z">
  <saml:Issuer>%s</saml:Issuer>
  <saml:Subject><saml:NameID>attacker@evil.test</saml:NameID></saml:Subject>
</saml:Assertion>`, testIdPEntity)

	response := encryptedResponse(t, &spKey.PublicKey, forged)

	got, err := h.sp.ProcessResponse(h.context, response, testSessionID)
	if err == nil {
		t.Fatalf("an unsigned assertion was accepted after decryption: %+v", got)
	}
	// The rejection must come from verification, not from decryption failing
	// or the XML not parsing -- either would make this test pass without
	// exercising the property it is named for.
	if strings.Contains(strings.ToLower(err.Error()), "decrypt") {
		t.Errorf("the assertion was rejected before verification (%v); "+
			"this test must exercise the signature check", err)
	}
	if !strings.Contains(strings.ToLower(err.Error()), "sign") {
		t.Errorf("error = %v, want one naming the missing signature", err)
	}
}

// TestEncryptedAssertionSignedByAnotherKeyIsRefused covers the same bypass by
// a different route: a signature that exists but is not the identity
// provider's.
func TestEncryptedAssertionSignedByAnotherKeyIsRefused(t *testing.T) {
	h := newAttackHarness(t)
	spKey, _ := testKeyPair(t)
	decrypter, _ := NewRSADecrypter(spKey)
	h.sp.decrypter = decrypter

	// Sign with a key the service provider does not trust.
	attackerSigner, _ := testSigner(t)
	resp := validResponse()
	raw, err := xml.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	signed, err := attackerSigner.Sign(h.context, raw)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	response := encryptedResponse(t, &spKey.PublicKey, string(signed))

	if _, err := h.sp.ProcessResponse(h.context, response, testSessionID); err == nil {
		t.Error("an assertion signed by an untrusted key was accepted after decryption")
	}
}

// TestEncryptedAssertionThatCannotBeDecryptedIsRefused keeps a failed
// decryption from falling through to any other path.
func TestEncryptedAssertionThatCannotBeDecryptedIsRefused(t *testing.T) {
	h := newAttackHarness(t)
	ourKey, _ := testKeyPair(t)
	theirKey, _ := testKeyPair(t)
	decrypter, _ := NewRSADecrypter(ourKey)
	h.sp.decrypter = decrypter

	// Encrypted to a key this service provider does not hold.
	response := encryptedResponse(t, &theirKey.PublicKey, signedAssertionXML(t, h))

	_, err := h.sp.ProcessResponse(h.context, response, testSessionID)
	if !errors.Is(err, ErrDecryption) {
		t.Errorf("error = %v, want ErrDecryption", err)
	}
}
