// Package keys defines how Kayan obtains signing keys and produces signed tokens.
//
// Kayan does not choose an algorithm for you. A [Key] carries its own
// [jwt.SigningMethod], so RS256, ES256, EdDSA, and HS256 are all equally
// supported, and adding a new one requires no change here.
//
// # Choosing an algorithm
//
//	// RSA
//	k := &keys.Key{KID: "2026-01", Method: jwt.SigningMethodRS256,
//	    Private: rsaKey, Public: &rsaKey.PublicKey}
//
//	// Ed25519 instead — nothing else changes
//	k := &keys.Key{KID: "2026-01", Method: jwt.SigningMethodEdDSA,
//	    Private: edPriv, Public: edPub}
//
//	provider := keys.NewStaticProvider(k)
//
// # Rotation
//
// Pass superseded keys to [NewStaticProvider] after the active one. New tokens
// are signed with the active key; tokens already issued under a retired key
// keep verifying until it is dropped, and every key still listed appears in
// JWKS so relying parties can validate both.
//
//	provider := keys.NewStaticProvider(current, previous)
//
// # Keys Kayan never sees
//
// [Provider] hands out key material. When the private key lives in an HSM or a
// cloud KMS, implement [Signer] instead — Kayan calls Sign and never holds the
// private key:
//
//	type kmsSigner struct{ client *kms.Client }
//
//	func (s *kmsSigner) Sign(ctx context.Context, claims jwt.Claims, hdr map[string]any) (string, error) {
//	    // marshal, call KMS, assemble the compact serialization
//	}
package keys

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
	"fmt"
	"sync"

	"github.com/golang-jwt/jwt/v5"
)

// Errors returned by this package.
var (
	// ErrNoKey reports that no key is available for signing.
	ErrNoKey = errors.New("keys: no active key")
	// ErrKeyNotFound reports that no key matches the requested key ID.
	ErrKeyNotFound = errors.New("keys: key not found")
	// ErrUnsupportedKey reports a key type this package cannot represent as a JWK.
	ErrUnsupportedKey = errors.New("keys: unsupported key type")
	// ErrInvalidKey reports a key that is missing a required field.
	ErrInvalidKey = errors.New("keys: invalid key")
)

// Use values for [Key.Use], per RFC 7517 section 4.2.
const (
	UseSignature  = "sig"
	UseEncryption = "enc"
)

// Key is a single signing key together with the algorithm it is used with.
//
// Private and Public are typed as any so that any algorithm — including one
// this package has never heard of — can be carried without a type parameter.
// Private holds *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey, or
// []byte for HMAC; Public holds the corresponding public key, and is unused
// for symmetric algorithms.
type Key struct {
	// KID identifies the key. It is written to the token header and to JWKS so
	// a verifier can select the right key. Required.
	KID string

	// Method is the JWS algorithm this key signs with. Required.
	Method jwt.SigningMethod

	// Private signs. Required for the active key; may be nil for a key that is
	// retained only to verify already-issued tokens.
	Private any

	// Public verifies. Required for asymmetric algorithms.
	Public any

	// Use is "sig" or "enc". Defaults to "sig" when empty.
	Use string
}

// Validate reports whether k is usable.
func (k *Key) Validate() error {
	switch {
	case k == nil:
		return fmt.Errorf("%w: nil key", ErrInvalidKey)
	case k.KID == "":
		return fmt.Errorf("%w: missing KID", ErrInvalidKey)
	case k.Method == nil:
		return fmt.Errorf("%w: key %q has no signing method", ErrInvalidKey, k.KID)
	}
	return nil
}

// CanSign reports whether k carries private key material.
func (k *Key) CanSign() bool { return k != nil && k.Private != nil }

// Algorithm returns the JWS algorithm name, or "" when the key has no method.
func (k *Key) Algorithm() string {
	if k == nil || k.Method == nil {
		return ""
	}
	return k.Method.Alg()
}

// keyUse returns the key's use, defaulting to "sig".
func (k *Key) keyUse() string {
	if k.Use == "" {
		return UseSignature
	}
	return k.Use
}

// Provider supplies signing keys.
//
// Implementations must be safe for concurrent use: Active and ByKID are called
// on every token operation.
type Provider interface {
	// Active returns the key that new tokens are signed with. It returns
	// [ErrNoKey] when no key can sign.
	Active(ctx context.Context) (*Key, error)

	// ByKID returns the key with the given ID for verification. Retired keys
	// remain resolvable until they are removed, so tokens issued before a
	// rotation keep verifying. It returns [ErrKeyNotFound] when the ID is
	// unknown.
	ByKID(ctx context.Context, kid string) (*Key, error)

	// Verification returns every key that should be published in JWKS: the
	// active key plus any retired keys still accepted.
	Verification(ctx context.Context) ([]*Key, error)
}

// Signer produces a signed compact JWS.
//
// Implement this — rather than [Provider] — when the private key must not
// leave an HSM or KMS. Kayan calls Sign and never inspects key material.
type Signer interface {
	// Sign returns the signed compact serialization of claims. Entries in
	// header are added to the JOSE header; implementations set "alg" and
	// should set "kid" themselves.
	Sign(ctx context.Context, claims jwt.Claims, header map[string]any) (string, error)
}

// StaticProvider serves a fixed set of keys held in memory.
//
// It is the default Provider and is safe for concurrent use. Keys are supplied
// at construction, so rotating means building a new provider — see
// [StaticProvider.Rotate] for in-place rotation.
type StaticProvider struct {
	mu      sync.RWMutex
	active  *Key
	byKID   map[string]*Key
	ordered []*Key // active first, then retired in the order given
}

// compile-time check
var _ Provider = (*StaticProvider)(nil)

// NewStaticProvider returns a Provider serving active for signing, and active
// plus retired for verification.
//
// It panics if active is unusable or cannot sign, or if any key is invalid —
// these are wiring mistakes that should surface at startup rather than on the
// first authentication. Use [NewStaticProviderWithError] to handle them.
func NewStaticProvider(active *Key, retired ...*Key) *StaticProvider {
	p, err := NewStaticProviderWithError(active, retired...)
	if err != nil {
		panic(err)
	}
	return p
}

// NewStaticProviderWithError is [NewStaticProvider] that reports an error
// instead of panicking.
func NewStaticProviderWithError(active *Key, retired ...*Key) (*StaticProvider, error) {
	if err := active.Validate(); err != nil {
		return nil, err
	}
	if !active.CanSign() {
		return nil, fmt.Errorf("%w: active key %q has no private key", ErrInvalidKey, active.KID)
	}

	p := &StaticProvider{
		active:  active,
		byKID:   map[string]*Key{active.KID: active},
		ordered: append([]*Key{active}, retired...),
	}
	for _, k := range retired {
		if err := k.Validate(); err != nil {
			return nil, err
		}
		if _, dup := p.byKID[k.KID]; dup {
			return nil, fmt.Errorf("%w: duplicate KID %q", ErrInvalidKey, k.KID)
		}
		p.byKID[k.KID] = k
	}
	return p, nil
}

// Active implements [Provider].
func (p *StaticProvider) Active(context.Context) (*Key, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.active == nil {
		return nil, ErrNoKey
	}
	return p.active, nil
}

// ByKID implements [Provider].
func (p *StaticProvider) ByKID(_ context.Context, kid string) (*Key, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if k, ok := p.byKID[kid]; ok {
		return k, nil
	}
	return nil, fmt.Errorf("%w: %q", ErrKeyNotFound, kid)
}

// Verification implements [Provider]. The active key is first.
func (p *StaticProvider) Verification(context.Context) ([]*Key, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]*Key, len(p.ordered))
	copy(out, p.ordered)
	return out, nil
}

// Rotate promotes next to the active key, keeping the previous active key for
// verification. Tokens already issued keep verifying; new tokens use next.
func (p *StaticProvider) Rotate(next *Key) error {
	if err := next.Validate(); err != nil {
		return err
	}
	if !next.CanSign() {
		return fmt.Errorf("%w: key %q has no private key", ErrInvalidKey, next.KID)
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if existing, ok := p.byKID[next.KID]; ok && existing != next {
		return fmt.Errorf("%w: duplicate KID %q", ErrInvalidKey, next.KID)
	}

	previous := p.active
	p.active = next
	p.byKID[next.KID] = next

	ordered := make([]*Key, 0, len(p.ordered)+1)
	ordered = append(ordered, next)
	for _, k := range p.ordered {
		if k.KID != next.KID {
			ordered = append(ordered, k)
		}
	}
	_ = previous
	p.ordered = ordered
	return nil
}

// SignerOption configures a [JWTSigner].
type SignerOption func(*JWTSigner)

// JWTSigner signs claims with the active key from a [Provider].
//
// It is the default [Signer].
type JWTSigner struct {
	provider Provider
}

// compile-time check
var _ Signer = (*JWTSigner)(nil)

// NewJWTSigner returns a Signer that signs with p's active key.
func NewJWTSigner(p Provider, opts ...SignerOption) *JWTSigner {
	s := &JWTSigner{provider: p}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Sign implements [Signer]. It sets "alg" from the key's method and "kid" from
// the key's ID, then applies header on top.
func (s *JWTSigner) Sign(ctx context.Context, claims jwt.Claims, header map[string]any) (string, error) {
	if s.provider == nil {
		return "", ErrNoKey
	}
	key, err := s.provider.Active(ctx)
	if err != nil {
		return "", err
	}
	if !key.CanSign() {
		return "", fmt.Errorf("%w: key %q has no private key", ErrInvalidKey, key.KID)
	}

	token := jwt.NewWithClaims(key.Method, claims)
	token.Header["kid"] = key.KID
	for k, v := range header {
		token.Header[k] = v
	}

	signed, err := token.SignedString(key.Private)
	if err != nil {
		return "", fmt.Errorf("keys: sign with %q: %w", key.KID, err)
	}
	return signed, nil
}

// Keyfunc returns a [jwt.Keyfunc] that resolves the verification key by the
// token's "kid" header.
//
// It rejects any token whose "alg" does not match the algorithm recorded for
// that key, which is what prevents an attacker from re-signing an RSA-issued
// token as HMAC using the public key as the secret.
func Keyfunc(ctx context.Context, p Provider) jwt.Keyfunc {
	return func(token *jwt.Token) (any, error) {
		kid, _ := token.Header["kid"].(string)
		if kid == "" {
			return nil, fmt.Errorf("%w: token has no kid header", ErrKeyNotFound)
		}

		key, err := p.ByKID(ctx, kid)
		if err != nil {
			return nil, err
		}
		if token.Method.Alg() != key.Method.Alg() {
			return nil, fmt.Errorf(
				"keys: token alg %q does not match key %q alg %q",
				token.Method.Alg(), kid, key.Method.Alg(),
			)
		}

		return verificationKey(key), nil
	}
}

// verificationKey returns the material used to verify a signature made with k.
// Symmetric algorithms verify with the same secret they sign with.
func verificationKey(k *Key) any {
	if k.Public != nil {
		return k.Public
	}
	return k.Private
}

// PublicKeyOf derives the public key for k, falling back to deriving it from
// the private key when Public is unset.
func PublicKeyOf(k *Key) (crypto.PublicKey, error) {
	if k.Public != nil {
		return k.Public, nil
	}
	switch priv := k.Private.(type) {
	case *rsa.PrivateKey:
		return &priv.PublicKey, nil
	case *ecdsa.PrivateKey:
		return &priv.PublicKey, nil
	case ed25519.PrivateKey:
		return priv.Public(), nil
	case crypto.Signer:
		return priv.Public(), nil
	default:
		return nil, fmt.Errorf("%w: cannot derive public key for %q", ErrUnsupportedKey, k.KID)
	}
}
