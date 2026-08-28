package saml

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"
)

// encryptedNameID seals a NameID the way an identity provider that encrypts
// subject identifiers does.
func encryptedNameID(t testing.TB, pub *rsa.PublicKey, value string) string {
	t.Helper()
	plaintext := fmt.Sprintf(
		`<saml:NameID xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" `+
			`Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">%s</saml:NameID>`, value)
	return string(encryptAssertion(t, pub, []byte(plaintext), encryptOptions{}))
}

// idHarness returns a harness whose service provider can decrypt, plus the key
// an identity provider would encrypt to.
func idHarness(t *testing.T) (*attackHarness, *rsa.PrivateKey) {
	t.Helper()
	h := newAttackHarness(t)
	spKey, _ := testKeyPair(t)
	decrypter, err := NewRSADecrypter(spKey)
	if err != nil {
		t.Fatalf("NewRSADecrypter: %v", err)
	}
	h.sp.decrypter = decrypter
	return h, spKey
}

// recordSubject captures the subject the service provider resolved.
//
// The identity the repository hands back does not carry the NameID -- it is
// the application's own struct -- so the hook is the only place the resolved
// identifier is observable, and it is exactly what this feature produces.
func recordSubject(h *attackHarness) *string {
	var subject string
	hooks := h.sp.hooks
	hooks.AfterProcessResponse = func(_ context.Context, user *SAMLUser) {
		subject = user.NameID
	}
	h.sp.hooks = hooks
	return &subject
}

// responseWithEncryptedID builds a signed response whose subject is encrypted.
//
// It marshals the same Response struct the other tests use and then swaps the
// NameID element for an EncryptedID. Hand-writing the XML with namespace
// prefixes does not survive the signer, which re-serialises subtrees and drops
// an inherited prefix declaration.
func responseWithEncryptedID(t *testing.T, h *attackHarness, cipherXML string) string {
	t.Helper()
	return signRaw(t, h, replaceNameID(t, validResponse(), encryptedIDElement(cipherXML)))
}

// responseWithBothSubjects builds a signed response whose Subject carries a
// plaintext NameID and an EncryptedID.
func responseWithBothSubjects(t *testing.T, h *attackHarness, cipherXML string) string {
	t.Helper()
	response := validResponse()
	marshalled := replaceNameID(t, response, nameIDElement("plaintext@example.com")+encryptedIDElement(cipherXML))
	return signRaw(t, h, marshalled)
}

// encryptedIDElement wraps ciphertext in an EncryptedID with the assertion
// namespace declared on it.
func encryptedIDElement(cipherXML string) string {
	return `<EncryptedID xmlns="urn:oasis:names:tc:SAML:2.0:assertion">` + cipherXML + `</EncryptedID>`
}

// nameIDElement renders a plaintext NameID.
func nameIDElement(value string) string {
	return `<NameID xmlns="urn:oasis:names:tc:SAML:2.0:assertion">` + value + `</NameID>`
}

// replaceNameID marshals a response and swaps its NameID element for the given
// XML.
func replaceNameID(t *testing.T, response Response, replacement string) []byte {
	t.Helper()
	raw, err := xml.Marshal(response)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	pattern := regexp.MustCompile(`<NameID[^>]*>[^<]*</NameID>`)
	if !pattern.Match(raw) {
		t.Fatal("the marshalled response carries no NameID to replace")
	}
	return pattern.ReplaceAll(raw, []byte(replacement))
}

// signRaw signs a document with the harness's identity provider key.
func signRaw(t *testing.T, h *attackHarness, raw []byte) string {
	t.Helper()
	signed, err := h.signer.Sign(h.context, raw)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return base64.StdEncoding.EncodeToString(signed)
}

// TestEncryptedIDResolvesTheSubject is the feature.
//
// Federations that treat the subject identifier as personal data encrypt it,
// so it is readable only by the intended service provider. Without support,
// every one of their assertions arrives naming nobody.
func TestEncryptedIDResolvesTheSubject(t *testing.T) {
	h, spKey := idHarness(t)

	response := responseWithEncryptedID(t, h, encryptedNameID(t, &spKey.PublicKey, "victim@example.com"))

	subject := recordSubject(h)
	if _, err := h.sp.ProcessResponse(h.context, response, testSessionID); err != nil {
		t.Fatalf("ProcessResponse: %v", err)
	}
	if *subject != "victim@example.com" {
		t.Errorf("subject = %q, want the decrypted NameID", *subject)
	}
}

// TestEncryptedIDWithoutADecrypterFailsClosed.
//
// An encrypted identifier that silently yielded no subject would reach the
// caller as a login with an empty name. An auto-provisioning deployment turns
// that into an account with no owner -- and the second such login joins the
// first, so every user of that identity provider shares one account.
func TestEncryptedIDWithoutADecrypterFailsClosed(t *testing.T) {
	h, spKey := idHarness(t)
	h.sp.decrypter = nil

	response := responseWithEncryptedID(t, h, encryptedNameID(t, &spKey.PublicKey, "victim@example.com"))

	ident, err := h.sp.ProcessResponse(h.context, response, testSessionID)
	if err == nil {
		t.Fatal("an encrypted subject was accepted with no decrypter configured")
	}
	if ident != nil {
		t.Error("an identity was returned alongside the error")
	}
	if !errors.Is(err, ErrNoDecrypter) {
		t.Errorf("error = %v, want ErrNoDecrypter", err)
	}
}

// TestBothNameIDAndEncryptedIDIsRefused.
//
// There is no safe rule for choosing. A deployment that took the plaintext
// would ignore the encryption its federation mandated; one that took the
// ciphertext would silently disagree with any peer reading the other. Both
// name a subject, and picking is picking whom to disagree with.
func TestBothNameIDAndEncryptedIDIsRefused(t *testing.T) {
	h, spKey := idHarness(t)

	// A subject carrying both, as a misconfigured proxy would emit.
	full := responseWithBothSubjects(t, h, encryptedNameID(t, &spKey.PublicKey, "victim@example.com"))

	ident, err := h.sp.ProcessResponse(h.context, full, testSessionID)
	if err == nil {
		t.Fatal("a subject naming two identifiers was accepted")
	}
	if ident != nil {
		t.Error("an identity was returned alongside the error")
	}
	if !errors.Is(err, ErrAmbiguousNameID) {
		t.Errorf("error = %v, want ErrAmbiguousNameID", err)
	}
}

// TestEncryptedIDIsNotDecryptedBeforeVerification is the ordering test.
//
// Decryption is not authentication: anyone can encrypt to a public key
// published in metadata. An unsigned response carrying a perfectly valid
// EncryptedID must be refused, and refused for the missing signature -- not
// accepted because the ciphertext opened.
func TestEncryptedIDIsNotDecryptedBeforeVerification(t *testing.T) {
	h, spKey := idHarness(t)

	unsigned := replaceNameID(t, validResponse(),
		encryptedIDElement(encryptedNameID(t, &spKey.PublicKey, "attacker@evil.test")))

	ident, err := h.sp.ProcessResponse(h.context, base64.StdEncoding.EncodeToString(unsigned), testSessionID)
	if err == nil {
		t.Fatal("an unsigned response with an encrypted subject authenticated")
	}
	if ident != nil {
		t.Error("an identity was returned alongside the error")
	}
	// The refusal must be about the signature. If it were about decryption,
	// a future change that made decryption succeed would let this through.
	if strings.Contains(err.Error(), "EncryptedID did not decrypt") {
		t.Errorf("error = %v, want the signature to be what refuses it", err)
	}
}

// TestEmptyDecryptedNameIDIsRefused.
//
// An element that parses as a NameID but names nobody authenticates the empty
// string, which matches whatever an application stores for users with no
// external identifier.
func TestEmptyDecryptedNameIDIsRefused(t *testing.T) {
	h, spKey := idHarness(t)

	response := responseWithEncryptedID(t, h, encryptedNameID(t, &spKey.PublicKey, ""))

	if _, err := h.sp.ProcessResponse(h.context, response, testSessionID); !errors.Is(err, ErrEncryptedIDUnreadable) {
		t.Errorf("error = %v, want ErrEncryptedIDUnreadable", err)
	}
}

// TestPlainNameIDIsUnaffected keeps the change scoped: an ordinary assertion
// must behave exactly as before, or every existing deployment breaks.
func TestPlainNameIDIsUnaffected(t *testing.T) {
	h, _ := idHarness(t)

	subject := recordSubject(h)
	if _, err := h.sp.ProcessResponse(h.context, h.sign(t, validResponse()), testSessionID); err != nil {
		t.Fatalf("ProcessResponse: %v", err)
	}
	if *subject != "victim@example.com" {
		t.Errorf("subject = %q", *subject)
	}
}

// TestLogoutEncryptedIDIsResolved.
//
// A federation that encrypts assertion identifiers encrypts logout ones too.
// A service provider that could read the first but not the second would
// authenticate users it can never sign out.
func TestLogoutEncryptedIDIsResolved(t *testing.T) {
	h := logoutHarness(t)
	spKey, _ := testKeyPair(t)
	decrypter, err := NewRSADecrypter(spKey)
	if err != nil {
		t.Fatalf("NewRSADecrypter: %v", err)
	}
	h.sp.decrypter = decrypter

	request := LogoutRequest{
		ID:           "_logout-1",
		Version:      "2.0",
		IssueInstant: time.Now().UTC(),
		Destination:  "http://sp.example.com/slo",
		Issuer:       Issuer{Value: testIdPEntity},
		NameID:       NameID{Value: "placeholder"},
	}
	raw, err := xml.Marshal(request)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	pattern := regexp.MustCompile(`<NameID[^>]*>[^<]*</NameID>`)
	raw = pattern.ReplaceAll(raw, []byte(encryptedIDElement(
		encryptedNameID(t, &spKey.PublicKey, "victim@example.com"))))

	instruction, err := h.sp.ProcessLogoutRequest(context.Background(), signRaw(t, h, raw), "")
	if err != nil {
		t.Fatalf("ProcessLogoutRequest: %v", err)
	}
	if instruction.NameID != "victim@example.com" {
		t.Errorf("NameID = %q, want the decrypted subject", instruction.NameID)
	}
}
