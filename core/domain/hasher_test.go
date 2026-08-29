package domain

import (
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// The password hasher is the most security-critical primitive in the library
// and had no direct test. It was exercised only through the login path, where
// a passing sign-in shows that Hash and Compare agree with each other -- and
// says nothing about whether they agree with the wrong password too.

// testCost keeps these fast. The default cost of 12 is ~250ms per hash, which
// across a table of cases is minutes.
const testCost = bcrypt.MinCost

func TestHashAndCompareAgree(t *testing.T) {
	hasher := NewBcryptHasher(testCost)

	hash, err := hasher.Hash("correct-horse-battery-staple")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if !hasher.Compare("correct-horse-battery-staple", hash) {
		t.Error("the password that produced the hash does not verify against it")
	}
}

// TestCompareRejectsWhatItShould is the half a passing login never exercises.
//
// Every one of these must be false. A Compare that returned true for any of
// them authenticates without the password, and the login path would look
// entirely healthy.
func TestCompareRejectsWhatItShould(t *testing.T) {
	hasher := NewBcryptHasher(testCost)
	hash, err := hasher.Hash("the-real-password")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}

	cases := []struct {
		name     string
		password string
		hash     string
	}{
		{"wrong password", "not-the-password", hash},
		{"empty password", "", hash},
		{"password is the hash", hash, hash},
		{"prefix of the password", "the-real-passwor", hash},
		{"case differs", "The-Real-Password", hash},
		// An empty or malformed hash is what a caller reads from a row whose
		// column was never populated. bcrypt errors on it; the danger is a
		// Compare that treats "could not evaluate" as "matched".
		{"empty hash", "the-real-password", ""},
		{"garbage hash", "the-real-password", "not-a-bcrypt-hash"},
		{"truncated hash", "the-real-password", hash[:len(hash)-5]},
		{"both empty", "", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if hasher.Compare(tc.password, tc.hash) {
				t.Error("Compare returned true, which authenticates without the password")
			}
		})
	}
}

// TestLongSecretsAreRefusedNotTruncated locks the outcome of a trap bcrypt
// historically set: it ignored everything past 72 bytes, so two passphrases
// sharing a 72-byte prefix hashed the same and each verified against the
// other. A user who "changed" a long passphrase by editing the end would find
// the old one still worked.
//
// Being honest about what this proves: removing the length check in Hash does
// not make it fail. golang.org/x/crypto/bcrypt returns ErrPasswordTooLong
// itself, so the explicit check is defence in depth against a bcrypt that
// truncates silently rather than the guard doing the work today. The test
// pins the behaviour either way, since the consequence of losing it is a
// password that can be changed without changing.
func TestLongSecretsAreRefusedNotTruncated(t *testing.T) {
	hasher := NewBcryptHasher(testCost)

	atLimit := strings.Repeat("a", 72)
	if _, err := hasher.Hash(atLimit); err != nil {
		t.Errorf("a 72-byte secret was refused: %v", err)
	}

	overLimit := strings.Repeat("a", 73)
	if _, err := hasher.Hash(overLimit); err == nil {
		t.Fatal("a 73-byte secret was hashed; bcrypt would have ignored the tail")
	}

	// The property the refusal protects: two secrets differing only past the
	// limit must never both verify.
	first := strings.Repeat("a", 72) + "-original"
	second := strings.Repeat("a", 72) + "-changed"
	if _, err := hasher.Hash(first); err == nil {
		t.Fatal("an over-long secret was accepted")
	}
	if _, err := hasher.Hash(second); err == nil {
		t.Fatal("an over-long secret was accepted")
	}
}

// TestHashIsSalted. Two hashes of one password must differ, or the column
// leaks which accounts share a password and precomputation becomes worthwhile.
func TestHashIsSalted(t *testing.T) {
	hasher := NewBcryptHasher(testCost)

	first, err := hasher.Hash("same-password")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	second, err := hasher.Hash("same-password")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}

	if first == second {
		t.Error("two hashes of one password are identical, so the hash is unsalted")
	}
	// Both must still verify: differing hashes are only useful if either works.
	if !hasher.Compare("same-password", first) || !hasher.Compare("same-password", second) {
		t.Error("a salted hash failed to verify its own password")
	}
}

// TestZeroCostSelectsTheDefault. A caller passing the zero value must get the
// documented default rather than bcrypt's minimum, which is fast enough to
// brute-force offline.
func TestZeroCostSelectsTheDefault(t *testing.T) {
	if got := NewBcryptHasher(0).Cost; got != DefaultBcryptCost {
		t.Errorf("cost = %d, want DefaultBcryptCost (%d)", got, DefaultBcryptCost)
	}
	if DefaultBcryptCost < 10 {
		t.Errorf("DefaultBcryptCost is %d; below 10 offline cracking is cheap",
			DefaultBcryptCost)
	}
}

// TestCostIsRecordedInTheHash. bcrypt stores the work factor, which is what
// lets a deployment raise the cost without invalidating existing hashes.
func TestCostIsRecordedInTheHash(t *testing.T) {
	hash, err := NewBcryptHasher(testCost).Hash("password")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}

	cost, err := bcrypt.Cost([]byte(hash))
	if err != nil {
		t.Fatalf("the hash is not a valid bcrypt hash: %v", err)
	}
	if cost != testCost {
		t.Errorf("recorded cost = %d, want %d", cost, testCost)
	}

	// A hash written at one cost still verifies after the hasher's cost moves,
	// which is the migration path that property exists for.
	if !NewBcryptHasher(testCost+1).Compare("password", hash) {
		t.Error("raising the hasher's cost invalidated an existing hash")
	}
}
