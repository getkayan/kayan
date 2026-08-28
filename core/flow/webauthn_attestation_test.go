package flow

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/go-webauthn/webauthn/webauthn"
)

var (
	yubikeyAAGUID = []byte{0xcb, 0x69, 0x48, 0x1e, 0x8f, 0xf7, 0x40, 0x39,
		0x93, 0xec, 0x0a, 0x27, 0x29, 0xa1, 0x54, 0xa8}
	unknownAAGUID = []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
	zeroAAGUID = make([]byte, 16)
)

// TestRequireTrustedAttestationRefusesWhatVouchesForNothing is the check that
// makes requesting attestation mean anything.
//
// "none" says the authenticator asserted nothing. "self" says the credential's
// own key signed for itself, which proves the key exists and nothing about
// what holds it. A deployment that asks for attestation and accepts either has
// a consent prompt, a certificate chain in its database, and no more assurance
// than one that asked for nothing.
func TestRequireTrustedAttestationRefusesWhatVouchesForNothing(t *testing.T) {
	policy := RequireTrustedAttestation()

	for _, format := range []string{"", AttestationNone, AttestationSelf} {
		err := policy.AllowAuthenticator(context.Background(),
			AttestationInfo{Format: format, AAGUID: yubikeyAAGUID})
		if err == nil {
			t.Errorf("attestation format %q was accepted as trusted", format)
			continue
		}
		if !errors.Is(err, ErrAttestationMissing) {
			t.Errorf("format %q: error = %v, want ErrAttestationMissing", format, err)
		}
	}

	for _, format := range []string{AttestationBasic, AttestationAttCA} {
		if err := policy.AllowAuthenticator(context.Background(),
			AttestationInfo{Format: format, AAGUID: yubikeyAAGUID}); err != nil {
			t.Errorf("format %q was refused: %v", format, err)
		}
	}
}

// TestAllowlistRefusesTheZeroAAGUID.
//
// The all-zero AAGUID is what an authenticator reports when it identifies
// nothing. An allowlist containing it accepts every unattested credential
// while reading, in a configuration file, exactly like a hardware allowlist --
// the failure would be invisible to review and total in effect.
func TestAllowlistRefusesTheZeroAAGUID(t *testing.T) {
	policy, err := AllowedAuthenticators(yubikeyAAGUID, zeroAAGUID)
	if err == nil {
		t.Fatal("an allowlist containing the all-zero AAGUID was built")
	}
	if policy != nil {
		t.Error("a policy was returned alongside the error")
	}
	if !strings.Contains(err.Error(), "all-zero AAGUID") {
		t.Errorf("error = %v, want it to name the problem", err)
	}
}

// TestEmptyAllowlistIsAnError. A policy that permits everything is what a
// deployment believes it has when its configuration failed to load, and
// refusing is the entire purpose of this policy.
func TestEmptyAllowlistIsAnError(t *testing.T) {
	if _, err := AllowedAuthenticators(); err == nil {
		t.Fatal("an empty allowlist was accepted as a policy")
	}
}

// TestAllowlistMatchesByModel covers the working path in both directions.
func TestAllowlistMatchesByModel(t *testing.T) {
	policy, err := AllowedAuthenticators(yubikeyAAGUID)
	if err != nil {
		t.Fatalf("AllowedAuthenticators: %v", err)
	}

	if err := policy.AllowAuthenticator(context.Background(),
		AttestationInfo{Format: AttestationBasic, AAGUID: yubikeyAAGUID}); err != nil {
		t.Errorf("an allowlisted model was refused: %v", err)
	}

	err = policy.AllowAuthenticator(context.Background(),
		AttestationInfo{Format: AttestationBasic, AAGUID: unknownAAGUID})
	if !errors.Is(err, ErrAuthenticatorNotAllowed) {
		t.Errorf("error = %v, want ErrAuthenticatorNotAllowed", err)
	}

	// An unattested credential reports the zero AAGUID, which must not match
	// an allowlist that never contained it.
	err = policy.AllowAuthenticator(context.Background(),
		AttestationInfo{Format: AttestationNone, AAGUID: zeroAAGUID})
	if !errors.Is(err, ErrAuthenticatorNotAllowed) {
		t.Errorf("an unattested credential matched a hardware allowlist: %v", err)
	}
}

// TestAllowlistCopiesItsInput. A caller that reuses the slice it passed --
// reading AAGUIDs into one buffer in a loop is the obvious way to write it --
// would otherwise rewrite the policy after construction.
func TestAllowlistCopiesItsInput(t *testing.T) {
	buffer := make([]byte, 16)
	copy(buffer, yubikeyAAGUID)

	policy, err := AllowedAuthenticators(buffer)
	if err != nil {
		t.Fatalf("AllowedAuthenticators: %v", err)
	}

	copy(buffer, unknownAAGUID)

	if err := policy.AllowAuthenticator(context.Background(),
		AttestationInfo{Format: AttestationBasic, AAGUID: yubikeyAAGUID}); err != nil {
		t.Errorf("the allowlist changed when the caller reused its buffer: %v", err)
	}
}

// TestRequireDeviceBoundCredential. A synchronised passkey lives wherever the
// user's account provider puts it, which changes what the credential proves
// from "this device" to "this cloud account".
func TestRequireDeviceBoundCredential(t *testing.T) {
	policy := RequireDeviceBoundCredential()

	if err := policy.AllowAuthenticator(context.Background(),
		AttestationInfo{Format: AttestationBasic, BackupEligible: false}); err != nil {
		t.Errorf("a device-bound credential was refused: %v", err)
	}

	err := policy.AllowAuthenticator(context.Background(),
		AttestationInfo{Format: AttestationBasic, BackupEligible: true})
	if !errors.Is(err, ErrAuthenticatorNotAllowed) {
		t.Errorf("error = %v, want a backup-eligible credential refused", err)
	}
}

// TestCombinedPoliciesReportTheFirstRefusal. A combined error that summarised
// would leave the operator decomposing it; naming the specific reason is what
// makes a refusal actionable.
func TestCombinedPoliciesReportTheFirstRefusal(t *testing.T) {
	allowlist, err := AllowedAuthenticators(yubikeyAAGUID)
	if err != nil {
		t.Fatalf("AllowedAuthenticators: %v", err)
	}
	policy := CombineAttestationPolicies(RequireTrustedAttestation(), allowlist, nil)

	// Fails the first policy: unattested.
	err = policy.AllowAuthenticator(context.Background(),
		AttestationInfo{Format: AttestationNone, AAGUID: yubikeyAAGUID})
	if !errors.Is(err, ErrAttestationMissing) {
		t.Errorf("error = %v, want ErrAttestationMissing", err)
	}

	// Fails the second: attested, wrong model.
	err = policy.AllowAuthenticator(context.Background(),
		AttestationInfo{Format: AttestationBasic, AAGUID: unknownAAGUID})
	if !errors.Is(err, ErrAuthenticatorNotAllowed) {
		t.Errorf("error = %v, want ErrAuthenticatorNotAllowed", err)
	}

	// Passes both.
	if err := policy.AllowAuthenticator(context.Background(),
		AttestationInfo{Format: AttestationBasic, AAGUID: yubikeyAAGUID}); err != nil {
		t.Errorf("a credential satisfying every policy was refused: %v", err)
	}
}

// TestNoPolicyAcceptsAnything keeps the feature opt-in. A deployment that
// configured nothing must keep registering credentials exactly as before.
func TestNoPolicyAcceptsAnything(t *testing.T) {
	strategy := passkeyStrategy(t, WebAuthnHooks{})
	if strategy.config.AttestationPolicy != nil {
		t.Error("an unconfigured strategy has an attestation policy")
	}
}

// TestFinishRegistrationConsultsThePolicy is the integration point.
//
// A policy that is configured but never called is worse than none: the
// deployment reads its own configuration as enforcing authenticator
// provenance, the operator signs off on it, and every authenticator is
// accepted.
func TestFinishRegistrationConsultsThePolicy(t *testing.T) {
	strategy := passkeyStrategy(t, WebAuthnHooks{})

	consulted := false
	refusal := errors.New("model refused")
	strategy.config.AttestationPolicy = AttestationPolicyFunc(
		func(_ context.Context, info AttestationInfo) error {
			consulted = true
			if !bytes.Equal(info.AAGUID, unknownAAGUID) {
				t.Errorf("AAGUID = %x, want the credential's", info.AAGUID)
			}
			if info.Format != AttestationNone {
				t.Errorf("Format = %q, want the credential's", info.Format)
			}
			if !info.BackupEligible {
				t.Error("BackupEligible was not carried through")
			}
			return refusal
		})

	credential := &webauthn.Credential{
		ID:              []byte("credential-1"),
		AttestationType: AttestationNone,
		Authenticator:   webauthn.Authenticator{AAGUID: unknownAAGUID},
		Flags:           webauthn.CredentialFlags{BackupEligible: true},
	}

	err := strategy.applyAttestationPolicy(context.Background(), credential)
	if !consulted {
		t.Fatal("the configured attestation policy was never consulted")
	}
	if !errors.Is(err, refusal) {
		t.Errorf("error = %v, want the policy's refusal to propagate", err)
	}
}

// TestNoPolicyLetsRegistrationThrough keeps the feature opt-in.
func TestNoPolicyLetsRegistrationThrough(t *testing.T) {
	strategy := passkeyStrategy(t, WebAuthnHooks{})

	if err := strategy.applyAttestationPolicy(context.Background(), &webauthn.Credential{
		AttestationType: AttestationNone,
	}); err != nil {
		t.Errorf("an unconfigured strategy refused a credential: %v", err)
	}
}
