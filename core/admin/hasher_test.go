package admin

import (
	"testing"

	"github.com/getkayan/kayan/core/domain"
	"golang.org/x/crypto/bcrypt"
)

// recordingHasher notes which arguments it received, so a test can tell a
// correct call from a reversed one.
type recordingHasher struct {
	gotPassword string
	gotHash     string
	result      bool
}

func (h *recordingHasher) Hash(password string) (string, error) { return "hashed:" + password, nil }

// Verify takes (hash, password) — the opposite order from
// domain.Hasher.Compare.
func (h *recordingHasher) Verify(hash, password string) bool {
	h.gotHash = hash
	h.gotPassword = password
	return h.result
}

// TestHasherAdapterCorrectsArgumentOrder is the reason the adapter exists.
//
// PasswordHasher.Verify(hash, password) and domain.Hasher.Compare(password,
// hash) have identical types, so wiring one where the other is expected
// compiles cleanly and then compares a password against a password. The
// adapter is what keeps the two straight.
func TestHasherAdapterCorrectsArgumentOrder(t *testing.T) {
	legacy := &recordingHasher{result: true}
	adapted := hasherAdapter{inner: legacy}

	const (
		password = "correct horse battery staple"
		hash     = "$2a$12$storedhashvalue"
	)

	if !adapted.Compare(password, hash) {
		t.Fatal("Compare returned false for a hasher that reports a match")
	}

	if legacy.gotPassword != password {
		t.Errorf("the legacy hasher received password %q, want %q", legacy.gotPassword, password)
	}
	if legacy.gotHash != hash {
		t.Errorf("the legacy hasher received hash %q, want %q", legacy.gotHash, hash)
	}
}

// TestAdaptedHasherVerifiesRealHashes proves the adapter works end to end
// against bcrypt, not only against a recording double.
func TestAdaptedHasherVerifiesRealHashes(t *testing.T) {
	// A legacy hasher wrapping bcrypt with the old argument order.
	legacy := legacyBcrypt{}
	adapted := hasherAdapter{inner: legacy}

	const password = "correct horse battery staple"
	hash, err := adapted.Hash(password)
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}

	if !adapted.Compare(password, hash) {
		t.Error("the correct password was rejected")
	}
	if adapted.Compare("wrong password", hash) {
		t.Error("an incorrect password was accepted")
	}
	// Passing the hash where the password belongs must not verify. Under the
	// reversed wiring this is exactly the call that would succeed.
	if adapted.Compare(hash, password) {
		t.Error("arguments in the wrong order verified successfully")
	}
}

type legacyBcrypt struct{}

func (legacyBcrypt) Hash(password string) (string, error) {
	out, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	return string(out), err
}

func (legacyBcrypt) Verify(hash, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

// TestManagerAcceptsDomainHasher proves the current option takes the shared
// interface, so no adapter is needed for new code.
func TestManagerAcceptsDomainHasher(t *testing.T) {
	hasher := domain.NewBcryptHasher(bcrypt.MinCost)

	manager := NewManager(WithPasswordHasher(hasher))
	if manager.hasher == nil {
		t.Fatal("WithPasswordHasher did not set the hasher")
	}

	hash, err := manager.hasher.Hash("password")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if !manager.hasher.Compare("password", hash) {
		t.Error("the configured hasher rejected the password it hashed")
	}
}

// TestIDGeneratorIsTheDomainFunctionType proves the option takes the function
// type the rest of Kayan uses, rather than a second interface of the same name.
func TestIDGeneratorIsTheDomainFunctionType(t *testing.T) {
	var generator domain.IDGenerator = func() any { return "generated-id" }

	manager := NewManager(WithIDGenerator(generator))
	if manager.idGen == nil {
		t.Fatal("WithIDGenerator did not set the generator")
	}
	if got := manager.idGen(); got != "generated-id" {
		t.Errorf("generator returned %v", got)
	}
}
