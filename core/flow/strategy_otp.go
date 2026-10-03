package flow

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
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
	factory    func() any
}

// identityFactory returns the configured factory, falling back to the built-in
// identity type. The fallback keeps the zero-configuration path working; it is
// not correct for a caller with their own identity type, which is what
// WithOTPFactory is for.
func (s *OTPStrategy) identityFactory() func() any {
	if s.factory != nil {
		return s.factory
	}
	return func() any { return &identity.Identity{} }
}

// OTPOption configures an OTPStrategy.
type OTPOption func(*OTPStrategy)

// WithOTPFactory sets the identity factory used to load the identity a code
// belongs to.
//
// Without it the strategy falls back to *identity.Identity, which is wrong for
// any caller using their own identity type — the load either fails or returns
// a type the caller cannot use. Pass the same factory given to the rest of the
// flow.
func WithOTPFactory(factory func() any) OTPOption {
	return func(s *OTPStrategy) { s.factory = factory }
}

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

// otpTokenKey is the store key for a code: bound to the identity it was
// issued to, so two identities drawing the same code hold two different
// tokens. Keyed by the code alone, the second save overwrote the first (or
// failed on a unique key), and a guess under any identifier was matched
// against every identity's outstanding code.
func otpTokenKey(identityID, code string) string {
	sum := sha256.Sum256([]byte(identityID + "\x00" + code))
	return hex.EncodeToString(sum[:])
}

// revokeOutstanding deletes every live code issued to the identity, when the
// store can.
func (s *OTPStrategy) revokeOutstanding(ctx context.Context, identityID string) error {
	if revoker, ok := s.tokenStore.(domain.IdentityTokenRevoker); ok {
		return revoker.DeleteIdentityTokens(ctx, identityID, "otp")
	}
	return nil
}

// Initiate generates an OTP code, stores it, and delivers it via the OTPSender.
// The identifier is typically a phone number or email address.
//
// Returns the stored AuthToken. Its Token is the store key, not the code: the
// code exists only in what was delivered. When the store implements
// domain.IdentityTokenRevoker, a new code replaces any the identity still had.
func (s *OTPStrategy) Initiate(ctx context.Context, identifier string) (any, error) {
	if s.sender == nil {
		return nil, fmt.Errorf("otp: sender not configured")
	}

	// 1. Find identity by credential identifier
	cred, err := s.repo.GetCredentialByIdentifier(ctx, identifier, "")
	if err != nil || cred == nil {
		return nil, fmt.Errorf("otp: user not found")
	}

	// 2. Generate cryptographically random numeric code
	code, err := s.generateCode()
	if err != nil {
		return nil, fmt.Errorf("otp: failed to generate code: %w", err)
	}

	// 3. Store the code as an AuthToken, keyed to its identity.
	if err := s.revokeOutstanding(ctx, cred.IdentityID); err != nil {
		return nil, fmt.Errorf("otp: failed to revoke earlier codes: %w", err)
	}
	key := otpTokenKey(cred.IdentityID, code)
	token := &domain.AuthToken{
		Token:      key,
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
		if deleteErr := s.tokenStore.DeleteToken(ctx, key); deleteErr != nil {
			return nil, fmt.Errorf("otp: send failed: %v; delete undelivered code: %w", err, deleteErr)
		}
		return nil, fmt.Errorf("otp: failed to send code: %w", err)
	}

	return token, nil
}

// Authenticate verifies the OTP code provided by the user.
// The identifier is the phone number or email, and the secret is the OTP code.
//
// A code only matches the identity it was issued to: it is looked up under a
// key bound to that identity, so a guess can never reach, or spend, another
// identity's code. When the store implements domain.IdentityTokenRevoker, a
// wrong guess spends the identity's outstanding code, so each code issued
// allows one try. Throttling keyed on the identifier (a LockoutStrategy) then
// bounds the rest: every identifier guards only its own codes.
func (s *OTPStrategy) Authenticate(ctx context.Context, identifier, secret string) (any, error) {
	// 1. Whose code this would be. One error for every rejection:
	// distinguishing "no such account" from "wrong code" would make this an
	// enumeration oracle.
	cred, err := s.repo.GetCredentialByIdentifier(ctx, identifier, "")
	if err != nil || cred == nil || cred.IdentityID == "" {
		return nil, fmt.Errorf("otp: invalid or expired code")
	}

	// 2. Spend it, atomically, so two attempts racing on one code cannot both
	// succeed.
	token, err := s.tokenStore.ConsumeToken(ctx, otpTokenKey(cred.IdentityID, secret), "otp")
	if err != nil || token == nil || token.IdentityID != cred.IdentityID {
		// A wrong guess costs the code it was aimed at.
		if revokeErr := s.revokeOutstanding(ctx, cred.IdentityID); revokeErr != nil {
			return nil, fmt.Errorf("otp: invalid or expired code; revoke outstanding code: %w", revokeErr)
		}
		return nil, fmt.Errorf("otp: invalid or expired code")
	}

	// 3. Find the identity
	ident, err := s.repo.GetIdentity(ctx, s.identityFactory(), token.IdentityID)
	if err != nil {
		return nil, fmt.Errorf("otp: identity not found")
	}

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
