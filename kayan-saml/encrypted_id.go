package saml

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
)

// Errors reported while resolving an encrypted name identifier.
var (
	// ErrAmbiguousNameID reports a subject carrying both a plaintext NameID
	// and an EncryptedID.
	//
	// There is no safe rule for choosing between them. A deployment that
	// picked the plaintext would ignore the encryption its federation
	// mandated; one that picked the ciphertext would silently disagree with
	// any peer that read the other. Both name a subject, and a subject with
	// two names is not a subject this library will authenticate.
	ErrAmbiguousNameID = errors.New("saml: subject carries both a NameID and an EncryptedID")

	// ErrEncryptedIDUnreadable reports an EncryptedID whose plaintext is not a
	// NameID.
	ErrEncryptedIDUnreadable = errors.New("saml: EncryptedID did not decrypt to a NameID")
)

// EncryptedID is a name identifier the identity provider encrypted to this
// service provider's public key (SAML 2.0 Core, section 2.2.4).
//
// Federations that treat the subject identifier as personal data require it:
// the identifier is then readable only by the intended service provider, not
// by anything on the path or by a proxying identity provider.
//
// It is captured as raw XML rather than parsed, because nothing in it is
// readable until it has been decrypted.
type EncryptedID struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion EncryptedID"`
	Raw     []byte   `xml:",innerxml"`
}

// resolveEncryptedID decrypts a subject's EncryptedID into its NameID.
//
// It runs after signature verification, never before. The signature covers the
// EncryptedID element, so decrypting the verified ciphertext yields a name the
// identity provider actually asserted. Decrypting first and verifying the
// result would verify a document this library had already rewritten, and
// decryption is not authentication in any case -- anyone can encrypt to a
// public key published in metadata.
//
// A subject with no encrypted identifier is left alone, so an ordinary
// assertion is unaffected.
func resolveEncryptedID(ctx context.Context, subject *Subject, decrypter Decrypter) error {
	if subject == nil || subject.EncryptedID == nil {
		return nil
	}

	// Both present is a configuration nobody meant to create, and choosing
	// between them is choosing which peer to silently disagree with.
	if subject.NameID.Value != "" {
		return ErrAmbiguousNameID
	}

	if decrypter == nil {
		// Fail closed. An encrypted identifier that silently yielded no
		// subject would reach the caller as a login with an empty name, which
		// an auto-provisioning deployment turns into an account with no owner.
		return fmt.Errorf("%w: the assertion carries an EncryptedID", ErrNoDecrypter)
	}

	plaintext, err := decrypter.Decrypt(ctx, subject.EncryptedID.Raw)
	if err != nil {
		return err
	}

	var nameID NameID
	if err := xml.Unmarshal(plaintext, &nameID); err != nil {
		return fmt.Errorf("%w: %v", ErrEncryptedIDUnreadable, err)
	}
	if nameID.Value == "" {
		// A decrypted element that parses as a NameID but names nobody is not
		// a subject. Accepting it authenticates the empty string, which
		// matches whatever an application stores for users who have no
		// external identifier.
		return fmt.Errorf("%w: the decrypted NameID is empty", ErrEncryptedIDUnreadable)
	}

	subject.NameID = nameID
	return nil
}
