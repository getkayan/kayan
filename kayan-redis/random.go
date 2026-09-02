package redisstore

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

func redisRandomToken() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("redis: generate random token: %w", err)
	}
	return hex.EncodeToString(raw), nil
}
