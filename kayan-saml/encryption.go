package saml

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" // #nosec G505 -- RSA-OAEP mask generation, not a message digest
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"

	"github.com/beevik/etree"
)

// Errors returned when an encrypted assertion cannot be opened.
var (
	// ErrNoDecrypter is returned when a response carries an EncryptedAssertion
	// and no decrypter is configured.
	ErrNoDecrypter = errors.New("saml: response is encrypted and no decrypter is configured")

	// ErrDecryption is returned when an encrypted assertion cannot be opened.
	// It deliberately carries no detail about which step failed.
	ErrDecryption = errors.New("saml: cannot decrypt assertion")

	// ErrUnsupportedAlgorithm is returned for an encryption algorithm this
	// implementation does not accept.
	ErrUnsupportedAlgorithm = errors.New("saml: unsupported encryption algorithm")
)

// XML Encryption algorithm identifiers (W3C XML-Enc).
const (
	algRSA15      = "http://www.w3.org/2001/04/xmlenc#rsa-1_5"
	algRSAOAEP    = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
	algRSAOAEP11  = "http://www.w3.org/2009/xmlenc11#rsa-oaep"
	algAES128GCM  = "http://www.w3.org/2009/xmlenc11#aes128-gcm"
	algAES192GCM  = "http://www.w3.org/2009/xmlenc11#aes192-gcm"
	algAES256GCM  = "http://www.w3.org/2009/xmlenc11#aes256-gcm"
	algDigestSHA1 = "http://www.w3.org/2000/09/xmldsig#sha1"
	algMGF1SHA1   = "http://www.w3.org/2009/xmlenc11#mgf1sha1"
	algMGF1SHA256 = "http://www.w3.org/2009/xmlenc11#mgf1sha256"
)

// Decrypter opens an EncryptedAssertion.
//
// Supply your own to keep the private key in an HSM: Kayan hands over the
// encrypted key and the cipher value, and never holds the key material.
type Decrypter interface {
	// Decrypt returns the plaintext XML of an encrypted assertion element.
	Decrypt(ctx context.Context, encryptedAssertion []byte) ([]byte, error)
}

// RSADecrypter opens assertions encrypted to an RSA key.
//
// # What it accepts, and what it refuses
//
// Key transport is RSA-OAEP only. RSA-PKCS1v15 (rsa-1_5) is refused: it is
// vulnerable to the Bleichenbacher padding oracle, and a SAML endpoint is an
// unauthenticated attacker-reachable decryption oracle, which is exactly the
// setting that attack needs. It remains widely deployed, which is why refusing
// it has to be deliberate rather than incidental.
//
// Content encryption is AES-GCM only. CBC modes are refused for the same class
// of reason: without an authenticated cipher, XML Encryption is vulnerable to
// adaptive chosen-ciphertext attacks that recover plaintext a byte at a time
// from an endpoint's accept/reject behaviour, and no amount of care in this
// package makes an unauthenticated mode safe here.
//
// A deployment whose identity provider cannot be configured for either needs
// its own Decrypter, and should know what it is accepting.
type RSADecrypter struct {
	keys []*rsa.PrivateKey
}

// NewRSADecrypter builds a decrypter over one or more private keys.
//
// More than one key is accepted so an SP can rotate its encryption
// certificate: during the overlap the identity provider may still be
// encrypting to the outgoing key, and each is tried in turn.
func NewRSADecrypter(keys ...*rsa.PrivateKey) (*RSADecrypter, error) {
	if len(keys) == 0 {
		return nil, errors.New("saml: a decrypter needs at least one private key")
	}
	for i, key := range keys {
		if key == nil {
			return nil, fmt.Errorf("saml: private key %d is nil", i)
		}
	}
	return &RSADecrypter{keys: keys}, nil
}

// Decrypt implements [Decrypter].
//
// Every failure returns ErrDecryption with no detail about which step failed.
// Distinguishing "the key did not unwrap" from "the padding was wrong" from
// "the GCM tag did not verify" is what turns a decryption endpoint into an
// oracle, and this endpoint is reachable by anyone who can post to the ACS URL.
func (d *RSADecrypter) Decrypt(_ context.Context, encryptedAssertion []byte) ([]byte, error) {
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(encryptedAssertion); err != nil {
		return nil, ErrDecryption
	}

	encryptedData := doc.FindElement("//EncryptedData")
	if encryptedData == nil {
		return nil, ErrDecryption
	}

	// The session key is wrapped in an EncryptedKey, which may sit inside the
	// EncryptedData's KeyInfo or beside it in the EncryptedAssertion.
	encryptedKey := doc.FindElement("//EncryptedKey")
	if encryptedKey == nil {
		return nil, ErrDecryption
	}

	sessionKey, err := d.unwrapKey(encryptedKey)
	if err != nil {
		return nil, ErrDecryption
	}

	plaintext, err := decryptData(encryptedData, sessionKey)
	if err != nil {
		return nil, ErrDecryption
	}
	return plaintext, nil
}

// unwrapKey recovers the content-encryption key from an EncryptedKey element.
func (d *RSADecrypter) unwrapKey(encryptedKey *etree.Element) ([]byte, error) {
	algorithm := algorithmOf(encryptedKey)
	switch algorithm {
	case algRSAOAEP, algRSAOAEP11:
	default:
		// Named explicitly rather than falling through to a generic failure,
		// because an operator whose IdP is configured for rsa-1_5 needs to
		// know that is why, and refusing it is a deliberate policy.
		return nil, fmt.Errorf("%w: key transport %q", ErrUnsupportedAlgorithm, algorithm)
	}

	ciphertext, err := cipherValue(encryptedKey)
	if err != nil {
		return nil, err
	}

	hashFunc, err := oaepHash(encryptedKey)
	if err != nil {
		return nil, err
	}

	// Each key is tried in turn to support encryption-certificate rollover.
	// The loop deliberately keeps no record of which key failed and how.
	for _, key := range d.keys {
		sessionKey, err := rsa.DecryptOAEP(hashFunc(), rand.Reader, key, ciphertext, nil)
		if err == nil {
			return sessionKey, nil
		}
	}
	return nil, ErrDecryption
}

// oaepHash reads the OAEP digest, defaulting to SHA-1 as the xmlenc#rsa-oaep-mgf1p
// identifier implies.
//
// SHA-1 here is the OAEP mask generation function, not a message digest: its
// collision resistance is not what OAEP relies on, so this is not the weakness
// that using SHA-1 for signatures would be.
func oaepHash(encryptedKey *etree.Element) (func() hash.Hash, error) {
	digest := algDigestSHA1
	if method := encryptedKey.FindElement("./EncryptionMethod/DigestMethod"); method != nil {
		if alg := method.SelectAttrValue("Algorithm", ""); alg != "" {
			digest = alg
		}
	}
	if mgf := encryptedKey.FindElement("./EncryptionMethod/MGF"); mgf != nil {
		// RFC 4055 allows the MGF digest to differ from the label digest; Go's
		// DecryptOAEP uses one hash for both, so refuse a mismatch rather than
		// quietly using the wrong one.
		switch mgf.SelectAttrValue("Algorithm", "") {
		case algMGF1SHA1:
			if digest != algDigestSHA1 {
				return nil, ErrUnsupportedAlgorithm
			}
		case algMGF1SHA256:
			if digest != "http://www.w3.org/2001/04/xmlenc#sha256" {
				return nil, ErrUnsupportedAlgorithm
			}
		}
	}

	switch digest {
	case algDigestSHA1:
		return sha1.New, nil
	case "http://www.w3.org/2001/04/xmlenc#sha256":
		return sha256.New, nil
	default:
		return nil, fmt.Errorf("%w: OAEP digest %q", ErrUnsupportedAlgorithm, digest)
	}
}

// decryptData opens the EncryptedData with the recovered session key.
func decryptData(encryptedData *etree.Element, sessionKey []byte) ([]byte, error) {
	algorithm := algorithmOf(encryptedData)
	var wantKeyLen int
	switch algorithm {
	case algAES128GCM:
		wantKeyLen = 16
	case algAES192GCM:
		wantKeyLen = 24
	case algAES256GCM:
		wantKeyLen = 32
	default:
		return nil, fmt.Errorf("%w: content encryption %q", ErrUnsupportedAlgorithm, algorithm)
	}

	// The wrapped key's length must match the algorithm the document claims.
	// Without this an attacker who can influence the wrapped key could pair a
	// short key with an algorithm expecting a longer one.
	if len(sessionKey) != wantKeyLen {
		return nil, ErrDecryption
	}

	ciphertext, err := cipherValue(encryptedData)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(sessionKey)
	if err != nil {
		return nil, ErrDecryption
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrDecryption
	}
	if len(ciphertext) < gcm.NonceSize() {
		return nil, ErrDecryption
	}

	// XML-Enc prepends the IV to the ciphertext.
	nonce := ciphertext[:gcm.NonceSize()]
	sealed := ciphertext[gcm.NonceSize():]

	plaintext, err := gcm.Open(nil, nonce, sealed, nil)
	if err != nil {
		return nil, ErrDecryption
	}
	return plaintext, nil
}

func algorithmOf(element *etree.Element) string {
	method := element.FindElement("./EncryptionMethod")
	if method == nil {
		return ""
	}
	return method.SelectAttrValue("Algorithm", "")
}

func cipherValue(element *etree.Element) ([]byte, error) {
	value := element.FindElement("./CipherData/CipherValue")
	if value == nil {
		return nil, ErrDecryption
	}
	decoded, err := base64.StdEncoding.DecodeString(spaceStripped(value.Text()))
	if err != nil {
		return nil, ErrDecryption
	}
	return decoded, nil
}

// spaceStripped removes the whitespace identity providers insert when they
// pretty-print base64 payloads across lines.
func spaceStripped(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case ' ', '\t', '\r', '\n':
		default:
			out = append(out, s[i])
		}
	}
	return string(out)
}
