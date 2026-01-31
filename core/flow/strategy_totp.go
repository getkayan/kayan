package flow

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"time"
)

// TOTPStrategy implements Multi-Factor Authentication using TOTP.
type TOTPStrategy struct{}

func (s *TOTPStrategy) ID() string { return "totp" }

// Verify checks a 6-digit TOTP code against a secret.
func (s *TOTPStrategy) Verify(secret string, code string) bool {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		return false
	}

	// Check current, previous, and next window (30s)
	now := time.Now().Unix() / 30
	for i := int64(-1); i <= 1; i++ {
		if s.generateCode(key, uint64(now+i)) == code {
			return true
		}
	}

	return false
}

func (s *TOTPStrategy) generateCode(key []byte, counter uint64) string {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)

	mac := hmac.New(sha1.New, key)
	mac.Write(buf)
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0xf
	binCode := int64(sum[offset]&0x7f)<<24 |
		int64(sum[offset+1])<<16 |
		int64(sum[offset+2])<<8 |
		int64(sum[offset+3])

	otp := binCode % 1000000
	return fmt.Sprintf("%06d", otp)
}
