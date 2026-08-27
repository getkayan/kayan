package main

import (
	"crypto/sha256"
	"fmt"
	"testing"
)

// This checksum is the command-line compatibility baseline. Changing help,
// documented commands, aliases, or flags requires an intentional update here
// and in the changelog.
func TestUsageCompatibility(t *testing.T) {
	const want = "2041fcb89f49d7acb2317ceffed496b7c4bc1b6a837a8cb2a74e9a6e34210ecd"
	got := fmt.Sprintf("%x", sha256.Sum256([]byte(usage)))
	if got != want {
		t.Fatalf("CLI usage changed: sha256 = %s, want %s", got, want)
	}
}
