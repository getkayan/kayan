package saml

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" // #nosec G505 -- OAEP mask generation, matching the implementation
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// encryptAssertion builds an EncryptedAssertion the way an identity provider
// does: a random content key wrapped with RSA-OAEP, and the assertion sealed
// with AES-GCM.
//
// Tests own this rather than reusing production code so a bug in decryption
// cannot be masked by the same bug in encryption.
func encryptAssertion(t testing.TB, pub *rsa.PublicKey, plaintext []byte, opts encryptOptions) []byte {
	t.Helper()

	keyLen := opts.keyLen
	if keyLen == 0 {
		keyLen = 32
	}
	sessionKey := make([]byte, keyLen)
	if _, err := rand.Read(sessionKey); err != nil {
		t.Fatalf("generate session key: %v", err)
	}

	// PKCS1v15 wrapping is produced genuinely rather than mislabelled, so the
	// refusal test exercises a ciphertext a real identity provider would send
	// rather than only the algorithm string.
	var wrapped []byte
	var err error
	if opts.keyAlgorithm == algRSA15 {
		wrapped, err = rsa.EncryptPKCS1v15(rand.Reader, pub, sessionKey)
	} else {
		hashFunc := sha1.New
		if opts.oaepSHA256 {
			hashFunc = sha256.New
		}
		wrapped, err = rsa.EncryptOAEP(hashFunc(), rand.Reader, pub, sessionKey, nil)
	}
	if err != nil {
		t.Fatalf("wrap session key: %v", err)
	}

	block, err := aes.NewCipher(sessionKey)
	if err != nil {
		t.Fatalf("aes: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("gcm: %v", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("nonce: %v", err)
	}
	sealed := append(nonce, gcm.Seal(nil, nonce, plaintext, nil)...)

	keyAlg := algRSAOAEP
	if opts.keyAlgorithm != "" {
		keyAlg = opts.keyAlgorithm
	}
	dataAlg := algAES256GCM
	switch {
	case opts.dataAlgorithm != "":
		dataAlg = opts.dataAlgorithm
	case keyLen == 16:
		dataAlg = algAES128GCM
	}

	digest := ""
	if opts.oaepSHA256 {
		digest = `<DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>`
	}

	return []byte(fmt.Sprintf(`<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#" Type="http://www.w3.org/2001/04/xmlenc#Element">
  <EncryptionMethod Algorithm="%s"/>
  <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
    <EncryptedKey xmlns="http://www.w3.org/2001/04/xmlenc#">
      <EncryptionMethod Algorithm="%s">%s</EncryptionMethod>
      <CipherData><CipherValue>%s</CipherValue></CipherData>
    </EncryptedKey>
  </KeyInfo>
  <CipherData><CipherValue>%s</CipherValue></CipherData>
</EncryptedData>`,
		dataAlg, keyAlg, digest,
		base64.StdEncoding.EncodeToString(wrapped),
		base64.StdEncoding.EncodeToString(sealed)))
}

type encryptOptions struct {
	keyLen        int
	oaepSHA256    bool
	keyAlgorithm  string
	dataAlgorithm string
}

const samplePlaintext = `<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1"><Subject><NameID>alice@example.test</NameID></Subject></Assertion>`

func TestRSADecrypterOpensAValidAssertion(t *testing.T) {
	key, _ := testKeyPair(t)
	decrypter, err := NewRSADecrypter(key)
	if err != nil {
		t.Fatalf("NewRSADecrypter: %v", err)
	}

	encrypted := encryptAssertion(t, &key.PublicKey, []byte(samplePlaintext), encryptOptions{})
	got, err := decrypter.Decrypt(context.Background(), encrypted)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(got) != samplePlaintext {
		t.Errorf("plaintext = %q, want the original assertion", got)
	}
}

// TestRSADecrypterAcceptsSHA256OAEP covers the other digest identity providers
// configure.
func TestRSADecrypterAcceptsSHA256OAEP(t *testing.T) {
	key, _ := testKeyPair(t)
	decrypter, _ := NewRSADecrypter(key)

	encrypted := encryptAssertion(t, &key.PublicKey, []byte(samplePlaintext), encryptOptions{
		keyAlgorithm: algRSAOAEP11,
		oaepSHA256:   true,
	})
	if _, err := decrypter.Decrypt(context.Background(), encrypted); err != nil {
		t.Fatalf("Decrypt with SHA-256 OAEP: %v", err)
	}
}

// TestRSADecrypterTriesEveryKey covers encryption-certificate rollover, where
// the identity provider may still be encrypting to the outgoing key.
func TestRSADecrypterTriesEveryKey(t *testing.T) {
	outgoing, _ := testKeyPair(t)
	incoming, _ := testKeyPair(t)
	decrypter, _ := NewRSADecrypter(incoming, outgoing)

	encrypted := encryptAssertion(t, &outgoing.PublicKey, []byte(samplePlaintext), encryptOptions{})
	if _, err := decrypter.Decrypt(context.Background(), encrypted); err != nil {
		t.Fatalf("an assertion encrypted to the outgoing key was refused: %v", err)
	}
}

// TestRSADecrypterRefusesWeakAlgorithms is the central policy test.
//
// RSA-PKCS1v15 key transport and AES-CBC content encryption are both widely
// deployed and both unsafe here. A SAML ACS endpoint is an unauthenticated,
// attacker-reachable decryption oracle, which is precisely the setting
// Bleichenbacher and the XML-Enc chosen-ciphertext attacks need. Accepting
// them for compatibility would make every other precaution in this file
// pointless.
func TestRSADecrypterRefusesWeakAlgorithms(t *testing.T) {
	key, _ := testKeyPair(t)
	decrypter, _ := NewRSADecrypter(key)

	cases := []struct {
		name string
		opts encryptOptions
	}{
		{"rsa-1_5 key transport", encryptOptions{keyAlgorithm: algRSA15}},
		{"aes128-cbc content", encryptOptions{
			dataAlgorithm: "http://www.w3.org/2001/04/xmlenc#aes128-cbc",
		}},
		{"aes256-cbc content", encryptOptions{
			dataAlgorithm: "http://www.w3.org/2001/04/xmlenc#aes256-cbc",
		}},
		{"tripledes content", encryptOptions{
			dataAlgorithm: "http://www.w3.org/2001/04/xmlenc#tripledes-cbc",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			encrypted := encryptAssertion(t, &key.PublicKey, []byte(samplePlaintext), tc.opts)
			if _, err := decrypter.Decrypt(context.Background(), encrypted); err == nil {
				t.Errorf("%s was accepted", tc.name)
			}
		})
	}
}

// TestRSADecrypterRefusesAKeyLengthMismatch covers a substitution: pairing a
// short wrapped key with an algorithm that expects a longer one.
func TestRSADecrypterRefusesAKeyLengthMismatch(t *testing.T) {
	key, _ := testKeyPair(t)
	decrypter, _ := NewRSADecrypter(key)

	// A 16-byte key declared as AES-256.
	encrypted := encryptAssertion(t, &key.PublicKey, []byte(samplePlaintext), encryptOptions{
		keyLen:        16,
		dataAlgorithm: algAES256GCM,
	})
	if _, err := decrypter.Decrypt(context.Background(), encrypted); err == nil {
		t.Error("a session key shorter than the declared algorithm was accepted")
	}
}

// TestRSADecrypterRejectsTamperedCiphertext confirms the AEAD tag is actually
// checked. Without authenticated encryption an attacker can flip bits in the
// assertion, and this is the test that would fail if GCM were swapped for an
// unauthenticated mode.
func TestRSADecrypterRejectsTamperedCiphertext(t *testing.T) {
	key, _ := testKeyPair(t)
	decrypter, _ := NewRSADecrypter(key)

	encrypted := encryptAssertion(t, &key.PublicKey, []byte(samplePlaintext), encryptOptions{})

	// Flip a bit inside the last CipherValue, which is the EncryptedData's
	// sealed assertion rather than the wrapped key.
	text := string(encrypted)
	end := strings.LastIndex(text, "</CipherValue>")
	start := strings.LastIndex(text[:end], "<CipherValue>") + len("<CipherValue>")
	if start <= 0 || end <= start+8 {
		t.Fatal("could not locate the cipher value")
	}
	tampered := []byte(text)
	// Change a base64 character to a different valid one, so the payload still
	// decodes and the failure comes from the authentication tag.
	if tampered[start+8] == 'A' {
		tampered[start+8] = 'B'
	} else {
		tampered[start+8] = 'A'
	}

	if _, err := decrypter.Decrypt(context.Background(), tampered); err == nil {
		t.Error("a tampered ciphertext was accepted; the authentication tag is not being checked")
	}
}

// TestRSADecrypterRejectsAForeignKey covers the ordinary wrong-key case.
func TestRSADecrypterRejectsAForeignKey(t *testing.T) {
	ours, _ := testKeyPair(t)
	theirs, _ := testKeyPair(t)
	decrypter, _ := NewRSADecrypter(ours)

	encrypted := encryptAssertion(t, &theirs.PublicKey, []byte(samplePlaintext), encryptOptions{})
	if _, err := decrypter.Decrypt(context.Background(), encrypted); err == nil {
		t.Error("an assertion encrypted to another key was opened")
	}
}

// TestDecryptionFailuresAreIndistinguishable is the padding-oracle test.
//
// An ACS endpoint decrypts whatever an unauthenticated caller posts to it. If
// the error distinguishes "the RSA unwrap failed" from "the GCM tag did not
// verify", that difference is an oracle an attacker queries to recover
// plaintext -- which is the whole mechanism of the Bleichenbacher family of
// attacks. Every failure must look the same from outside.
func TestDecryptionFailuresAreIndistinguishable(t *testing.T) {
	key, _ := testKeyPair(t)
	other, _ := testKeyPair(t)
	decrypter, _ := NewRSADecrypter(key)
	ctx := context.Background()

	valid := encryptAssertion(t, &key.PublicKey, []byte(samplePlaintext), encryptOptions{})
	tampered := append([]byte(nil), valid...)
	tampered[len(tampered)-40] ^= 0x02

	inputs := map[string][]byte{
		"wrong key":         encryptAssertion(t, &other.PublicKey, []byte(samplePlaintext), encryptOptions{}),
		"tampered payload":  tampered,
		"not xml at all":    []byte("definitely not xml"),
		"no encrypted data": []byte(`<EncryptedAssertion/>`),
	}

	var messages []string
	for name, input := range inputs {
		_, err := decrypter.Decrypt(ctx, input)
		if err == nil {
			t.Fatalf("%s was accepted", name)
		}
		if !errors.Is(err, ErrDecryption) {
			t.Errorf("%s produced %v, want ErrDecryption", name, err)
		}
		messages = append(messages, err.Error())
	}

	for i := 1; i < len(messages); i++ {
		if messages[i] != messages[0] {
			t.Errorf("decryption failures are distinguishable: %q vs %q; "+
				"an attacker can use the difference as an oracle", messages[0], messages[i])
		}
	}
}

// TestNewRSADecrypterValidatesItsKeys keeps a misconfiguration from producing
// a decrypter that silently refuses everything at runtime.
func TestNewRSADecrypterValidatesItsKeys(t *testing.T) {
	if _, err := NewRSADecrypter(); err == nil {
		t.Error("a decrypter with no keys was accepted")
	}
	if _, err := NewRSADecrypter(nil); err == nil {
		t.Error("a nil key was accepted")
	}
}
