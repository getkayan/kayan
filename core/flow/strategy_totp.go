package flow

import (
	"context"
	"crypto/hmac"
	"crypto/sha1" // #nosec G505 -- RFC 6238 requires HMAC-SHA-1 as the interoperable default; it is not used for password hashing.
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"time"
)

// TOTPReplayGuard records spent TOTP time steps, so a code cannot be used
// twice. MarkTOTPUsed must return an error if the counter was already used
// for that identity, and must be atomic against concurrent calls: two
// requests presenting the same code at the same moment must not both
// succeed. Every TOTPRepository is one.
type TOTPReplayGuard interface {
	MarkTOTPUsed(ctx context.Context, identityID any, counter uint64) error
}

// TOTPRepository is the storage contract for the totp strategy.
type TOTPRepository interface {
	// FindIdentityByField looks up an identity by a named field and value.
	FindIdentityByField(ctx context.Context, field, value string, factory func() any) (any, error)
	// FindTOTPSecret returns the base32-encoded TOTP secret for the given identity ID.
	FindTOTPSecret(ctx context.Context, identityID any) (string, error)
	// MarkTOTPUsed records that the given time-step counter has been used for the identity.
	// Implementations must return an error if that counter was already used (replay protection).
	MarkTOTPUsed(ctx context.Context, identityID any, counter uint64) error
}

// TOTPStrategy implements TOTP-based authentication as a LoginStrategy.
// It can also be used as a stateless verifier (e.g. via LoginManager.VerifyMFA)
// by creating a zero-value instance and calling Verify.
type TOTPStrategy struct {
	repo            TOTPRepository
	factory         func() any
	identifierField string
}

// NewTOTPStrategy creates a TOTP LoginStrategy that looks up identities by field.
//
//	strategy := flow.NewTOTPStrategy(repo, func() any { return &User{} }, "Email")
//	loginManager.RegisterStrategy(strategy)
func NewTOTPStrategy(repo TOTPRepository, factory func() any, identifierField string) *TOTPStrategy {
	return &TOTPStrategy{
		repo:            repo,
		factory:         factory,
		identifierField: identifierField,
	}
}

func (s *TOTPStrategy) ID() string { return "totp" }

// Authenticate verifies a 6-digit TOTP code for the given identifier.
// It accepts codes from the current, previous, and next 30-second windows
// (one-step drift tolerance). Replay protection is enforced by recording
// the matched time-step counter via MarkTOTPUsed.
func (s *TOTPStrategy) Authenticate(ctx context.Context, identifier, code string) (any, error) {
	ident, err := s.repo.FindIdentityByField(ctx, s.identifierField, identifier, s.factory)
	if err != nil {
		return nil, ErrTOTPSecretNotFound
	}

	fi, ok := ident.(FlowIdentity)
	if !ok {
		return nil, fmt.Errorf("flow: totp: identity does not implement FlowIdentity")
	}

	secretB32, err := s.repo.FindTOTPSecret(ctx, fi.GetID())
	if err != nil {
		return nil, ErrTOTPSecretNotFound
	}

	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secretB32)
	if err != nil {
		return nil, ErrTOTPSecretNotFound
	}

	counter, ok := s.findMatchingCounter(key, code)
	if !ok {
		return nil, ErrTOTPCodeInvalid
	}

	if err := s.repo.MarkTOTPUsed(ctx, fi.GetID(), counter); err != nil {
		return nil, ErrTOTPReplay
	}

	return ident, nil
}

// Verify checks a 6-digit TOTP code against a base32-encoded secret.
// It is stateless and does not enforce replay protection: a code it accepts
// can be accepted again for as long as its window lasts. Use Authenticate, or
// LoginManager.VerifyMFA with a TOTPReplayGuard, to verify a second factor.
func (s *TOTPStrategy) Verify(secret string, code string) bool {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		return false
	}
	_, ok := s.findMatchingCounter(key, code)
	return ok
}

// VerifyAndSpend checks a code against a base32-encoded secret and records
// the matched time step with guard, so the same code is refused next time.
// It returns ErrTOTPCodeInvalid for a code that matches no window and
// ErrTOTPReplay for one whose time step was already spent.
func (s *TOTPStrategy) VerifyAndSpend(ctx context.Context, guard TOTPReplayGuard, identityID any, secret, code string) error {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		return ErrTOTPSecretNotFound
	}
	counter, ok := s.findMatchingCounter(key, code)
	if !ok {
		return ErrTOTPCodeInvalid
	}
	if err := guard.MarkTOTPUsed(ctx, identityID, counter); err != nil {
		return fmt.Errorf("%w: %v", ErrTOTPReplay, err)
	}
	return nil
}

// findMatchingCounter checks the current, previous, and next 30-second windows.
// It uses constant-time comparison to avoid timing side-channels.
// Returns the matched counter and true, or 0 and false if no window matches.
func (s *TOTPStrategy) findMatchingCounter(key []byte, code string) (uint64, bool) {
	now := time.Now().Unix() / 30
	for i := int64(-1); i <= 1; i++ {
		step := now + i
		if step < 0 {
			continue
		}
		counter := uint64(step)
		generated := s.generateCode(key, counter)
		if subtle.ConstantTimeCompare([]byte(generated), []byte(code)) == 1 {
			return counter, true
		}
	}
	return 0, false
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
