package flow

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/go-webauthn/webauthn/webauthn"
)

// Attestation formats an authenticator may report (WebAuthn Level 2, section 8).
const (
	// AttestationNone means the authenticator vouched for nothing. It is what
	// a browser returns when the relying party asked for no attestation, and
	// also what some platform authenticators return regardless.
	AttestationNone = "none"

	// AttestationSelf means the credential's own key signed the attestation.
	// It proves the key exists and nothing about what holds it.
	AttestationSelf = "self"

	// AttestationBasic and AttestationAttCA are the forms that chain to a
	// manufacturer root, which is the only kind that says anything about which
	// device the credential lives on.
	AttestationBasic = "basic"
	AttestationAttCA = "attca"
)

// Errors reported when an authenticator fails the deployment's attestation
// policy.
var (
	// ErrAttestationMissing reports a registration that carried no usable
	// attestation where the policy required one.
	//
	// This is the failure that makes requesting attestation worth anything.
	// Asking for "direct" and accepting whatever comes back collects a
	// certificate chain, shows the user a consent prompt on some platforms,
	// and proves nothing -- while looking, in a configuration review, exactly
	// like a deployment that enforces authenticator provenance.
	ErrAttestationMissing = errors.New("webauthn: the authenticator provided no attestation")

	// ErrAuthenticatorNotAllowed reports an authenticator model the policy
	// does not accept.
	ErrAuthenticatorNotAllowed = errors.New("webauthn: authenticator model is not permitted")
)

// AttestationInfo describes a newly created credential, for a policy to judge.
type AttestationInfo struct {
	// Format is the attestation type the authenticator reported, as verified
	// by the WebAuthn library: [AttestationNone], [AttestationSelf],
	// [AttestationBasic], [AttestationAttCA], and so on.
	//
	// The statement's own signature has already been checked by the time a
	// policy sees this. What is left is the trust decision -- whether this
	// deployment accepts that authenticator -- which is the deployment's,
	// because it depends on a hardware inventory this library has no view of.
	Format string

	// AAGUID identifies the authenticator model. It is all zeroes for
	// attestation formats that vouch for nothing, and for platform
	// authenticators that decline to identify themselves.
	AAGUID []byte

	// CredentialID is the credential being registered.
	CredentialID []byte

	// BackupEligible reports that the credential may be synchronised to other
	// devices, and BackupState that it currently is.
	//
	// A synchronised passkey lives wherever the user's account provider puts
	// it. Deployments that require the credential to stay on one piece of
	// hardware refuse a backup-eligible one here -- not because syncing is
	// insecure, but because it changes what the credential proves from "this
	// device" to "this cloud account".
	BackupEligible bool
	BackupState    bool
}

// AttestationPolicy decides whether a newly registered authenticator is
// acceptable.
//
// It is a seam rather than a built-in list because the decision needs a
// hardware inventory, or the FIDO Metadata Service, and Kayan makes no
// outbound requests. What the library does is verify the statement and hand
// over what it found; which models a deployment trusts is the deployment's.
//
// [AllowedAuthenticators] and [RequireTrustedAttestation] cover the common
// cases.
type AttestationPolicy interface {
	// AllowAuthenticator returns nil to accept the registration, or an error
	// to refuse it. The credential is not stored when it refuses.
	AllowAuthenticator(ctx context.Context, info AttestationInfo) error
}

// AttestationPolicyFunc adapts a function to [AttestationPolicy].
type AttestationPolicyFunc func(ctx context.Context, info AttestationInfo) error

// AllowAuthenticator implements [AttestationPolicy].
func (f AttestationPolicyFunc) AllowAuthenticator(ctx context.Context, info AttestationInfo) error {
	return f(ctx, info)
}

// RequireTrustedAttestation refuses a registration whose attestation vouches
// for nothing.
//
// "none" says the authenticator asserted nothing; "self" says the credential's
// own key signed for itself, which proves the key exists and nothing about
// what holds it. Only a statement chaining to a manufacturer root identifies
// the device, and that is the whole reason to ask for attestation.
//
// It says nothing about which models are acceptable -- compose it with
// [AllowedAuthenticators] for that.
func RequireTrustedAttestation() AttestationPolicy {
	return AttestationPolicyFunc(func(_ context.Context, info AttestationInfo) error {
		switch info.Format {
		case "", AttestationNone, AttestationSelf:
			return fmt.Errorf("%w: format %q", ErrAttestationMissing, info.Format)
		}
		return nil
	})
}

// AllowedAuthenticators accepts only the listed authenticator models, by
// AAGUID.
//
// An empty list is an error rather than an allow-all: a policy that permits
// everything is what a deployment believes it has when its configuration
// failed to load, and the whole point of this policy is refusing.
//
// The all-zero AAGUID is refused as an entry. It is what an authenticator
// reports when it vouches for nothing, so an allowlist containing it accepts
// every unattested credential while reading like a hardware allowlist.
func AllowedAuthenticators(aaguids ...[]byte) (AttestationPolicy, error) {
	if len(aaguids) == 0 {
		return nil, errors.New("webauthn: an authenticator allowlist must name at least one model")
	}

	allowed := make([][]byte, 0, len(aaguids))
	for _, aaguid := range aaguids {
		if isZeroAAGUID(aaguid) {
			return nil, errors.New("webauthn: the all-zero AAGUID cannot be allowlisted; " +
				"it is what an authenticator reports when it identifies nothing, so " +
				"allowing it accepts every unattested credential")
		}
		allowed = append(allowed, bytes.Clone(aaguid))
	}

	return AttestationPolicyFunc(func(_ context.Context, info AttestationInfo) error {
		for _, aaguid := range allowed {
			if bytes.Equal(aaguid, info.AAGUID) {
				return nil
			}
		}
		return fmt.Errorf("%w: AAGUID %s", ErrAuthenticatorNotAllowed, hex.EncodeToString(info.AAGUID))
	}), nil
}

// RequireDeviceBoundCredential refuses a credential that may be synchronised
// to other devices.
//
// A synchronised passkey lives wherever the user's account provider puts it,
// which changes what the credential proves from "this device" to "this cloud
// account". Deployments that issued hardware to their staff care about the
// difference; most others should not use this, because refusing synced
// passkeys refuses the majority of what users actually have.
func RequireDeviceBoundCredential() AttestationPolicy {
	return AttestationPolicyFunc(func(_ context.Context, info AttestationInfo) error {
		if info.BackupEligible {
			return fmt.Errorf("%w: the credential is eligible for backup to other devices",
				ErrAuthenticatorNotAllowed)
		}
		return nil
	})
}

// CombineAttestationPolicies requires every policy to accept.
//
// The first refusal is returned, so the error names the specific reason rather
// than a summary the operator has to decompose.
func CombineAttestationPolicies(policies ...AttestationPolicy) AttestationPolicy {
	return AttestationPolicyFunc(func(ctx context.Context, info AttestationInfo) error {
		for _, policy := range policies {
			if policy == nil {
				continue
			}
			if err := policy.AllowAuthenticator(ctx, info); err != nil {
				return err
			}
		}
		return nil
	})
}

// applyAttestationPolicy judges a newly created credential.
//
// It is a named method so it can be exercised without a real authenticator:
// reaching it through FinishRegistration needs a genuine credential-creation
// response, and a check nobody can test is a check nobody knows is running.
func (s *WebAuthnStrategy) applyAttestationPolicy(ctx context.Context, credential *webauthn.Credential) error {
	policy := s.config.AttestationPolicy
	if policy == nil {
		return nil
	}
	return policy.AllowAuthenticator(ctx, AttestationInfo{
		Format:         credential.AttestationType,
		AAGUID:         credential.Authenticator.AAGUID,
		CredentialID:   credential.ID,
		BackupEligible: credential.Flags.BackupEligible,
		BackupState:    credential.Flags.BackupState,
	})
}

// isZeroAAGUID reports whether an AAGUID identifies nothing.
func isZeroAAGUID(aaguid []byte) bool {
	if len(aaguid) == 0 {
		return true
	}
	for _, b := range aaguid {
		if b != 0 {
			return false
		}
	}
	return true
}
