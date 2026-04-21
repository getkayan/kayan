package flow

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// generateSecureToken returns a hex-encoded string of n random bytes.
// It uses crypto/rand and is safe for generating secrets, nonces, and state values.
func generateSecureToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("flow: generateSecureToken: %w", err)
	}
	return hex.EncodeToString(b), nil
}
