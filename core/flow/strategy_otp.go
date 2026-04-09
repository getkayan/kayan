package flow

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"time"

	"github.com/getkayan/kayan/core/domain"
	"github.com/getkayan/kayan/core/identity"
)

// OTPSender is the interface that the user must implement to deliver OTP codes.
// Kayan is headless and never sends messages directly. The user provides their
// own delivery mechanism (Twilio, AWS SNS, email, etc.).
//
// Example:
//
//	type TwilioSender struct{ client *twilio.Client }
//	func (s *TwilioSender) Send(ctx context.Context, recipient, code string) error {
//	    _, err := s.client.SendSMS(recipient, "Your code is: "+code)
//	    return err
//	}
type OTPSender interface {
	Send(ctx context.Context, recipient, code string) error
}

// OTPStrategy implements passwordless login via one-time passwords delivered
// through SMS, voice, email, or any channel via the OTPSender interface.
//
// This strategy implements LoginStrategy and Initiator. It is not a
// RegistrationStrategy — OTP is used for login and verification, not registration.
//
// Usage:
//
//	sender := &TwilioSender{client: twilioClient}
//	otpStrategy := flow.NewOTPStrategy(repo, tokenStore, sender)
//	loginManager.RegisterStrategy(otpStrategy)
//
//	// 1. Initiate: sends code to user
//	result, _ := loginManager.InitiateLogin(ctx, "otp", "user@example.com")
//
//	// 2. Authenticate: user provides the code
//	ident, _ := loginManager.Authenticate(ctx, "otp", "user@example.com", "123456")
type OTPStrategy struct {
	repo       IdentityRepository
	tokenStore domain.TokenStore
	sender     OTPSender
	ttl        time.Duration
	codeLength int
}

// OTPOption configures an OTPStrategy.
type OTPOption func(*OTPStrategy)

// WithOTPTTL sets the expiration duration for OTP codes. Default is 5 minutes.
func WithOTPTTL(ttl time.Duration) OTPOption {
	return func(s *OTPStrategy) { s.ttl = ttl }
}

// WithOTPCodeLength sets the number of digits in the OTP code. Default is 6.
func WithOTPCodeLength(length int) OTPOption {
	return func(s *OTPStrategy) { s.codeLength = length }
}

// NewOTPStrategy creates a new OTP authentication strategy.
//
// Parameters:
//   - repo: identity storage for looking up users
//   - tokenStore: storage for OTP tokens (uses the existing AuthToken system)
//   - sender: user-provided delivery mechanism (SMS, voice, email, etc.)
//   - opts: optional configuration (TTL, code length)
func NewOTPStrategy(repo IdentityRepository, tokenStore domain.TokenStore, sender OTPSender, opts ...OTPOption) *OTPStrategy {
	s := &OTPStrategy{
		repo:       repo,
		tokenStore: tokenStore,
		sender:     sender,
		ttl:        5 * time.Minute,
		codeLength: 6,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

func (s *OTPStrategy) ID() string { return "otp" }

// Initiate generates an OTP code, stores it, and delivers it via the OTPSender.
// The identifier is typically a phone number or email address.
// Returns the AuthToken (the caller may use the token ID for flow tracking).
func (s *OTPStrategy) Initiate(ctx context.Context, identifier string) (any, error) {
	if s.sender == nil {
		return nil, fmt.Errorf("otp: sender not configured")
	}

	// 1. Find identity by credential identifier
	cred, err := s.repo.GetCredentialByIdentifier(identifier, "")
	if err != nil || cred == nil {
		return nil, fmt.Errorf("otp: user not found")
	}

	// 2. Generate cryptographically random numeric code
	code, err := s.generateCode()
	if err != nil {
		return nil, fmt.Errorf("otp: failed to generate code: %w", err)
	}

	// 3. Store the code as an AuthToken
	token := &domain.AuthToken{
		Token:      code,
		IdentityID: cred.IdentityID,
		Type:       "otp",
		ExpiresAt:  time.Now().Add(s.ttl),
	}
	if err := s.tokenStore.SaveToken(ctx, token); err != nil {
		return nil, fmt.Errorf("otp: failed to store code: %w", err)
	}

	// 4. Deliver the code via the sender
	if err := s.sender.Send(ctx, identifier, code); err != nil {
		// Clean up the token if delivery fails
		s.tokenStore.DeleteToken(ctx, code)
		return nil, fmt.Errorf("otp: failed to send code: %w", err)
	}

	return token, nil
}

// Authenticate verifies the OTP code provided by the user.
// The identifier is the phone number or email, and the secret is the OTP code.
func (s *OTPStrategy) Authenticate(ctx context.Context, identifier, secret string) (any, error) {
	// 1. Get the stored token by the code value
	token, err := s.tokenStore.GetToken(ctx, secret)
	if err != nil || token == nil {
		return nil, fmt.Errorf("otp: invalid or expired code")
	}

	// 2. Validate token type
	if token.Type != "otp" {
		return nil, fmt.Errorf("otp: invalid token type")
	}

	// 3. Check expiry
	if token.ExpiresAt.Before(time.Now()) {
		s.tokenStore.DeleteToken(ctx, secret)
		return nil, fmt.Errorf("otp: code expired")
	}

	// 4. Find the identity
	ident, err := s.repo.GetIdentity(func() any { return &identity.Identity{} }, token.IdentityID)
	if err != nil {
		return nil, fmt.Errorf("otp: identity not found")
	}

	// 5. Consume the token (one-time use)
	s.tokenStore.DeleteToken(ctx, secret)

	return ident, nil
}

// generateCode creates a cryptographically random numeric code of the configured length.
func (s *OTPStrategy) generateCode() (string, error) {
	max := new(big.Int)
	max.SetInt64(1)
	for i := 0; i < s.codeLength; i++ {
		max.Mul(max, big.NewInt(10))
	}

	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", err
	}

	format := fmt.Sprintf("%%0%dd", s.codeLength)
	return fmt.Sprintf(format, n.Int64()), nil
}
