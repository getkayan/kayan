package saml

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/getkayan/kayan/core/domain"
)

// Errors reported by assertion validation.
//
// Each corresponds to a check that, if skipped, allows a distinct attack.
var (
	// ErrReplay reports an assertion ID that has been seen before.
	ErrReplay = errors.New("saml: assertion replayed")
	// ErrAssertionExpired reports an assertion outside its validity window.
	ErrAssertionExpired = errors.New("saml: assertion is expired")
	// ErrAssertionNotYetValid reports an assertion whose NotBefore is ahead.
	ErrAssertionNotYetValid = errors.New("saml: assertion is not yet valid")
	// ErrWrongAudience reports an assertion minted for a different service
	// provider.
	ErrWrongAudience = errors.New("saml: assertion audience does not match this service provider")
	// ErrWrongDestination reports an assertion delivered to the wrong endpoint.
	ErrWrongDestination = errors.New("saml: assertion destination does not match this endpoint")
	// ErrWrongIssuer reports an assertion from an unexpected identity provider.
	ErrWrongIssuer = errors.New("saml: assertion issuer does not match the configured identity provider")
	// ErrUnsolicited reports an unsolicited response where one was not allowed.
	ErrUnsolicited = errors.New("saml: unsolicited response")
	// ErrMissingAssertionID reports an assertion with no ID, which cannot be
	// tracked for replay.
	ErrMissingAssertionID = errors.New("saml: assertion has no ID")
)

// DefaultClockSkew is the tolerance applied to assertion validity windows.
//
// Clocks between a service provider and an identity provider are rarely
// exactly aligned, and a strict comparison rejects assertions that are
// legitimately fresh.
const DefaultClockSkew = time.Minute

// ReplayCache records assertion IDs that have been accepted.
//
// A SAML assertion is a bearer credential: anyone holding a valid one can
// present it. Only single-use enforcement stops an attacker who captures one
// from replaying it until it expires.
type ReplayCache interface {
	// CheckAndStore records id, or returns [ErrReplay] if it was already
	// recorded. The check and the store must be atomic — two concurrent
	// presentations of the same assertion must not both succeed.
	CheckAndStore(ctx context.Context, id string, expiresAt time.Time) error
}

// MemoryReplayCache is an in-process [ReplayCache].
//
// It is correct for a single instance only. Running several replicas gives
// each its own cache, so an assertion can be replayed once per replica — use a
// shared cache (kayan-redis) in that case.
type MemoryReplayCache struct {
	mu    sync.Mutex
	seen  map[string]time.Time
	clock domain.Clock
}

var _ ReplayCache = (*MemoryReplayCache)(nil)

// NewMemoryReplayCache returns an empty in-process replay cache.
func NewMemoryReplayCache(clock domain.Clock) *MemoryReplayCache {
	return &MemoryReplayCache{
		seen:  make(map[string]time.Time),
		clock: domain.ClockOrDefault(clock),
	}
}

// CheckAndStore implements [ReplayCache].
func (c *MemoryReplayCache) CheckAndStore(_ context.Context, id string, expiresAt time.Time) error {
	if id == "" {
		return ErrMissingAssertionID
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.clock.Now()

	// Drop entries that can no longer be replayed, so the cache does not grow
	// for the life of the process.
	for seenID, seenExpiry := range c.seen {
		if !now.Before(seenExpiry) {
			delete(c.seen, seenID)
		}
	}

	if _, replayed := c.seen[id]; replayed {
		return fmt.Errorf("%w: %s", ErrReplay, id)
	}

	c.seen[id] = expiresAt
	return nil
}

// ValidationOptions carries what an assertion is checked against.
type ValidationOptions struct {
	// Audience is this service provider's entity ID. An assertion whose
	// AudienceRestriction names someone else was minted for a different
	// service and must not be accepted here.
	Audience string

	// Destination is this endpoint's URL, checked against the Destination
	// attribute and the SubjectConfirmationData Recipient.
	Destination string

	// ExpectedIssuer is the identity provider's entity ID.
	ExpectedIssuer string

	// ExpectedInResponseTo is the ID of the AuthnRequest this responds to.
	// Empty means the response is unsolicited.
	ExpectedInResponseTo string

	// AllowUnsolicited permits identity-provider-initiated sign-on. Such a
	// response has no InResponseTo to correlate, so nothing ties it to a
	// request this service provider made.
	AllowUnsolicited bool

	// ClockSkew tolerates clock differences. Defaults to [DefaultClockSkew].
	ClockSkew time.Duration
}

// validateAssertion applies every check an assertion must pass.
//
// Each is load-bearing:
//   - Issuer: without it, any identity provider whose certificate is
//     configured can assert users belonging to another.
//   - Audience: without it, an assertion minted for a different service is
//     accepted here.
//   - Destination and Recipient: without them, an assertion captured at one
//     endpoint can be delivered to another.
//   - NotBefore/NotOnOrAfter: without them, an assertion is valid forever.
//   - InResponseTo: without it, an attacker can inject a response into a
//     sign-on the user did not begin.
//   - Replay: without it, a captured assertion works until it expires.
func validateAssertion(ctx context.Context, a *Assertion, response *Response, opts ValidationOptions, clock domain.Clock, replay ReplayCache) error {
	if a == nil {
		return errors.New("saml: response carries no assertion")
	}

	skew := opts.ClockSkew
	if skew <= 0 {
		skew = DefaultClockSkew
	}
	now := clock.Now()

	if opts.ExpectedIssuer != "" {
		issuer := a.Issuer.Value
		if issuer == "" && response != nil {
			issuer = response.Issuer.Value
		}
		if issuer != opts.ExpectedIssuer {
			return fmt.Errorf("%w: got %q, want %q", ErrWrongIssuer, issuer, opts.ExpectedIssuer)
		}
	}

	if !a.Conditions.NotBefore.IsZero() && now.Add(skew).Before(a.Conditions.NotBefore) {
		return fmt.Errorf("%w: valid from %s", ErrAssertionNotYetValid, a.Conditions.NotBefore)
	}
	if !a.Conditions.NotOnOrAfter.IsZero() && !now.Add(-skew).Before(a.Conditions.NotOnOrAfter) {
		return fmt.Errorf("%w: expired at %s", ErrAssertionExpired, a.Conditions.NotOnOrAfter)
	}

	if opts.Audience != "" {
		if !a.Conditions.allowsAudience(opts.Audience) {
			return fmt.Errorf("%w: %q", ErrWrongAudience, opts.Audience)
		}
	}

	if opts.Destination != "" && response != nil && response.Destination != "" {
		if response.Destination != opts.Destination {
			return fmt.Errorf("%w: got %q, want %q", ErrWrongDestination, response.Destination, opts.Destination)
		}
	}

	for _, confirmation := range a.Subject.SubjectConfirmations {
		data := confirmation.SubjectConfirmationData
		if opts.Destination != "" && data.Recipient != "" && data.Recipient != opts.Destination {
			return fmt.Errorf("%w: recipient %q", ErrWrongDestination, data.Recipient)
		}
		if !data.NotOnOrAfter.IsZero() && !now.Add(-skew).Before(data.NotOnOrAfter) {
			return fmt.Errorf("%w: subject confirmation expired at %s", ErrAssertionExpired, data.NotOnOrAfter)
		}
		if opts.ExpectedInResponseTo != "" && data.InResponseTo != "" &&
			data.InResponseTo != opts.ExpectedInResponseTo {
			return fmt.Errorf("saml: subject confirmation InResponseTo %q does not match request %q",
				data.InResponseTo, opts.ExpectedInResponseTo)
		}
	}

	if response != nil {
		switch {
		case opts.ExpectedInResponseTo != "":
			if response.InResponseTo != opts.ExpectedInResponseTo {
				return fmt.Errorf("saml: InResponseTo %q does not match request %q",
					response.InResponseTo, opts.ExpectedInResponseTo)
			}
		case response.InResponseTo != "":
			// The response answers a request this service provider has no
			// record of.
			return fmt.Errorf("%w: InResponseTo %q matches no pending request",
				ErrUnsolicited, response.InResponseTo)
		case !opts.AllowUnsolicited:
			return ErrUnsolicited
		}
	}

	if replay != nil {
		if a.ID == "" {
			return ErrMissingAssertionID
		}
		expiry := a.Conditions.NotOnOrAfter
		if expiry.IsZero() {
			expiry = now.Add(time.Hour)
		}
		if err := replay.CheckAndStore(ctx, a.ID, expiry.Add(skew)); err != nil {
			return err
		}
	}

	return nil
}
