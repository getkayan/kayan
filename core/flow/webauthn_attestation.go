package flow

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

// AttestationNone is the statement format of an authenticator that vouched
// for nothing (WebAuthn Level 2, section 8.7). It is what a browser returns
// when the relying party asked for no attestation, and also what some platform
// authenticators return regardless.
const AttestationNone = "none"

// Attestation types (WebAuthn Level 2, section 6.5.3).
//
// Deprecated: these name attestation types, but [AttestationInfo.Format]
// carries the statement format ("packed", "tpm", "none", ...), which is what
// the WebAuthn library reports. No registration ever produces these values, so
// a policy comparing Format against them never matches. Use
// [AttestationInfo.ChainVerified] to tell an attested device from one that
// vouched only for itself.
const (
	AttestationSelf  = "self"
	AttestationBasic = "basic"
	AttestationAttCA = "attca"
)

// AttestationRoots supplies trusted root certificates per authenticator model.
//
// Keying by AAGUID is the point: a root that vouches for one vendor's devices
// must not vouch for another's AAGUID, or one vendor's leaked or test CA would
// let any authenticator claim to be any model.
//
// Kayan makes no outbound requests, so the source is the deployment's: a
// hardware inventory, or the FIDO Metadata Service fetched and verified by the
// host. Return no roots, not an error, for a model the deployment does not
// recognise.
type AttestationRoots interface {
	RootsFor(ctx context.Context, aaguid []byte) ([]*x509.Certificate, error)
}

// AttestationRootsFunc adapts a function to [AttestationRoots].
type AttestationRootsFunc func(ctx context.Context, aaguid []byte) ([]*x509.Certificate, error)

// RootsFor implements [AttestationRoots].
func (f AttestationRootsFunc) RootsFor(ctx context.Context, aaguid []byte) ([]*x509.Certificate, error) {
	return f(ctx, aaguid)
}

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
	// Format is the attestation statement format the authenticator used:
	// "packed", "tpm", "android-key", "apple", "fido-u2f", [AttestationNone].
	//
	// It is not the attestation type. "packed" covers both a statement signed
	// by a manufacturer certificate and one the credential signed for itself,
	// so Format alone never says whether the device was attested.
	Format string

	// AAGUID identifies the authenticator model, as the authenticator claims.
	// It is covered by the attestation signature but proves nothing unless
	// ChainVerified is true: an unattested or self-attested authenticator can
	// report any AAGUID it likes.
	AAGUID []byte

	// TrustPath is the statement's certificate chain (x5c), leaf first, whose
	// leaf the WebAuthn library verified the statement signature against.
	// Empty for "none" and for self attestation.
	TrustPath []*x509.Certificate

	// ChainVerified reports that TrustPath chains to a root that
	// [WebAuthnConfig.AttestationRoots] supplied for this AAGUID, at the time
	// of registration. It is false whenever no roots are configured.
	ChainVerified bool

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

// RequireTrustedAttestation refuses a registration whose attestation does not
// chain to a trusted root for its model.
//
// "none" asserts nothing; self attestation proves the key exists and nothing
// about what holds it; and a certificate chain proves nothing until it reaches
// a root the deployment trusts, because anyone can mint a CA. Only
// [AttestationInfo.ChainVerified] identifies the device, so this requires it --
// which means [WebAuthnConfig.AttestationRoots] must be configured, or every
// registration is refused.
//
// It says nothing about which models are acceptable -- compose it with
// [AllowedAuthenticators] for that.
func RequireTrustedAttestation() AttestationPolicy {
	return AttestationPolicyFunc(func(_ context.Context, info AttestationInfo) error {
		if !info.ChainVerified {
			return fmt.Errorf("%w: format %q does not chain to a trusted root for this model",
				ErrAttestationMissing, info.Format)
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
//
// An AAGUID is only believed when [AttestationInfo.ChainVerified] is true. An
// unattested authenticator chooses its own AAGUID, so an allowlist that
// trusted it unverified would admit any software authenticator claiming to be
// a listed model. Configure [WebAuthnConfig.AttestationRoots], or every
// registration is refused.
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
		if !info.ChainVerified {
			return fmt.Errorf("%w: AAGUID %s is not backed by a verified attestation chain",
				ErrAuthenticatorNotAllowed, hex.EncodeToString(info.AAGUID))
		}
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
func (s *WebAuthnStrategy) applyAttestationPolicy(ctx context.Context, credential *webauthn.Credential, statement map[string]any) error {
	policy := s.config.AttestationPolicy
	if policy == nil {
		return nil
	}

	info := AttestationInfo{
		Format:         credential.AttestationType,
		AAGUID:         credential.Authenticator.AAGUID,
		CredentialID:   credential.ID,
		BackupEligible: credential.Flags.BackupEligible,
		BackupState:    credential.Flags.BackupState,
	}

	trustPath, err := attestationTrustPath(statement)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrAttestationMissing, err)
	}
	info.TrustPath = trustPath

	if len(trustPath) > 0 && s.config.AttestationRoots != nil {
		verified, err := verifyAttestationChain(ctx, s.config.AttestationRoots, info.AAGUID, trustPath, s.clock.Now())
		if err != nil {
			// A roots source that cannot answer is not a "no": report it
			// rather than let the policy judge an unverified chain.
			return err
		}
		info.ChainVerified = verified
	}

	return policy.AllowAuthenticator(ctx, info)
}

// attestationTrustPath parses the x5c chain from an attestation statement.
//
// The statement is the one the WebAuthn library verified: its signature was
// checked against x5c[0], and authData -- which carries the AAGUID -- is part
// of what that signature covers.
func attestationTrustPath(statement map[string]any) ([]*x509.Certificate, error) {
	raw, ok := statement["x5c"]
	if !ok {
		return nil, nil
	}
	entries, ok := raw.([]any)
	if !ok {
		return nil, errors.New("attestation x5c is not an array")
	}
	chain := make([]*x509.Certificate, 0, len(entries))
	for i, entry := range entries {
		der, ok := entry.([]byte)
		if !ok {
			return nil, fmt.Errorf("attestation x5c[%d] is not a certificate", i)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("attestation x5c[%d]: %w", i, err)
		}
		chain = append(chain, cert)
	}
	return chain, nil
}

// verifyAttestationChain reports whether chain leads from its leaf to a root
// supplied for aaguid.
//
// Attestation certificates carry no TLS key usage, so any extended key usage
// is accepted; what is being established is who issued the leaf, not what it
// may be used for.
func verifyAttestationChain(ctx context.Context, source AttestationRoots, aaguid []byte, chain []*x509.Certificate, now time.Time) (bool, error) {
	if isZeroAAGUID(aaguid) {
		return false, nil
	}
	roots, err := source.RootsFor(ctx, aaguid)
	if err != nil {
		return false, fmt.Errorf("webauthn: attestation roots for AAGUID %s: %w", hex.EncodeToString(aaguid), err)
	}
	if len(roots) == 0 {
		return false, nil
	}

	pool := x509.NewCertPool()
	for _, root := range roots {
		pool.AddCert(root)
	}
	intermediates := x509.NewCertPool()
	for _, cert := range chain[1:] {
		intermediates.AddCert(cert)
	}
	_, err = chain[0].Verify(x509.VerifyOptions{
		Roots:         pool,
		Intermediates: intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	return err == nil, nil
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
