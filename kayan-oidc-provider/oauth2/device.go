package oauth2

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/getkayan/kayan/core/tenant"
)

// GrantDeviceCode is the device authorization grant (RFC 8628).
const GrantDeviceCode = "urn:ietf:params:oauth:grant-type:device_code"

// DeviceAuthorizationStatus is where a device authorization stands.
type DeviceAuthorizationStatus string

const (
	DeviceAuthorizationPending  DeviceAuthorizationStatus = "pending"
	DeviceAuthorizationApproved DeviceAuthorizationStatus = "approved"
	DeviceAuthorizationDenied   DeviceAuthorizationStatus = "denied"
)

// Defaults for [DeviceAuthorizationConfig].
const (
	DefaultDeviceAuthorizationLifetime = 10 * time.Minute
	DefaultDevicePollInterval          = 5 * time.Second

	// DeviceSlowDownIncrement is added to the polling interval each time a
	// client polls too fast (RFC 8628 section 3.5).
	DeviceSlowDownIncrement = 5 * time.Second

	// DefaultUserCodeAlphabet has no vowels, so a code cannot spell a word,
	// and no digits, so it cannot be confused with them (RFC 8628 section
	// 6.1).
	DefaultUserCodeAlphabet = "BCDFGHJKLMNPQRSTVWXZ"

	// MinUserCodeEntropyBits is the smallest user-code space the provider
	// accepts. The attempt limits are what make a short code safe, and their
	// arithmetic assumes a space at least this large; 8 characters of the
	// default alphabet give about 34.6 bits.
	MinUserCodeEntropyBits = 30
)

// Errors reported by the device authorization grant.
var (
	// ErrDeviceAuthorizationNotFound reports a user code, device code, or
	// verification handle that is unknown, expired, already completed, or
	// belongs to another client or tenant. The cases are not distinguished,
	// so the verification page is not an oracle for which codes exist.
	ErrDeviceAuthorizationNotFound = errors.New("oauth2: unknown, expired, or completed device authorization")

	// ErrDeviceAuthorizationNotPending reports an approval or denial of an
	// authorization that has already been decided.
	ErrDeviceAuthorizationNotPending = errors.New("oauth2: device authorization is no longer pending")

	// ErrUserCodeCollision reports a user code already held by a live
	// authorization. The provider generates another.
	ErrUserCodeCollision = errors.New("oauth2: user code already in use")

	// ErrUserCodeAttemptsExceeded reports that the user-code attempt limit
	// was reached. Serve it as HTTP 429.
	ErrUserCodeAttemptsExceeded = errors.New("oauth2: too many user code attempts")

	// ErrDeviceAuthorizationDisabled reports a device authorization call on a
	// provider configured without [WithDeviceAuthorization].
	ErrDeviceAuthorizationDisabled = errors.New("oauth2: device authorization is not enabled")
)

// Token endpoint errors specific to the device grant (RFC 8628 section 3.5).
var (
	ErrAuthorizationPending = &Error{Code: "authorization_pending", status: 400}
	ErrSlowDown             = &Error{Code: "slow_down", status: 400}
	ErrExpiredToken         = &Error{Code: "expired_token", status: 400}

	// errDeviceAccessDenied is access_denied with the token endpoint's 400
	// status (RFC 6749 section 5.2). errors.Is matches ErrAccessDenied.
	errDeviceAccessDenied = &Error{Code: "access_denied", status: 400}
)

// DeviceAuthorization is a stored device authorization.
type DeviceAuthorization struct {
	// DeviceCode is the bearer secret the device polls with.
	DeviceCode string

	// UserCode is the normalised code the user types.
	UserCode string

	ClientID string

	// TenantID is the tenant in context when the device asked. A user
	// verifying from another tenant does not find it.
	TenantID string

	Scopes    []string
	ExpiresAt time.Time

	// Interval is the current minimum time between polls. It grows by
	// [DeviceSlowDownIncrement] each time the client polls too fast.
	Interval     time.Duration
	LastPolledAt time.Time

	Status DeviceAuthorizationStatus

	// VerificationHandle is the single-use handle [Provider.VerifyUserCode]
	// issued, and VerifiedBy the identity it was issued to. Only a holder of
	// the handle, acting as that identity, can approve or deny.
	VerificationHandle string
	VerifiedBy         string

	// IdentityID is the identity that approved, and Authentication what was
	// known about that sign-in.
	IdentityID     string
	Authentication AuthenticationInfo
}

// DeviceAuthorizationStore persists device authorizations.
//
// Every state change is one atomic method, as with [PushedRequestStore]: an
// interface that let the provider read, decide, and write would put a race in
// every implementation. Every time-dependent method takes now, so liveness is
// decided by the provider's clock, not the store's.
type DeviceAuthorizationStore interface {
	// SaveDeviceAuthorization stores a new authorization. It returns
	// [ErrUserCodeCollision] when a live authorization holds the same user
	// code.
	SaveDeviceAuthorization(ctx context.Context, a *DeviceAuthorization, now time.Time) error

	// BeginDeviceVerification finds the live, pending authorization with
	// userCode in tenantID, records handle and identityID on it -- replacing
	// any earlier handle -- and returns it. Anything else is
	// [ErrDeviceAuthorizationNotFound], with nothing changed.
	BeginDeviceVerification(ctx context.Context, userCode, tenantID, handle, identityID string, now time.Time) (*DeviceAuthorization, error)

	// CompleteDeviceAuthorization moves the live, pending authorization whose
	// handle and VerifiedBy match to status, records identityID and auth, and
	// clears the handle. A handle that matches nothing live and pending is
	// [ErrDeviceAuthorizationNotFound].
	CompleteDeviceAuthorization(ctx context.Context, handle, identityID string, status DeviceAuthorizationStatus, auth AuthenticationInfo, now time.Time) error

	// PollDeviceAuthorization records a poll of deviceCode by clientID and
	// returns the authorization as it was before the poll, with slowDown
	// reporting that now fell inside LastPolledAt+Interval -- in which case
	// Interval has been increased by [DeviceSlowDownIncrement]. LastPolledAt
	// becomes now either way. A deviceCode unknown for clientID is
	// [ErrDeviceAuthorizationNotFound] and changes nothing, so another client
	// presenting the code cannot throttle the real one.
	PollDeviceAuthorization(ctx context.Context, deviceCode, clientID string, now time.Time) (a *DeviceAuthorization, slowDown bool, err error)

	// ConsumeDeviceAuthorization removes and returns the live, approved
	// authorization for deviceCode and clientID. Anything else is
	// [ErrDeviceAuthorizationNotFound]. Two concurrent calls never both
	// succeed.
	ConsumeDeviceAuthorization(ctx context.Context, deviceCode, clientID string, now time.Time) (*DeviceAuthorization, error)

	// DeleteExpiredDeviceAuthorizations removes authorizations expired at now.
	DeleteExpiredDeviceAuthorizations(ctx context.Context, now time.Time) error
}

// UserCodeAttemptLimiter bounds user-code guessing.
//
// It has the shape of flow.RateLimiter, so flow.MemoryRateLimiter and the
// kayan-redis limiter satisfy it without this module importing core/flow.
// Share one across replicas: a per-process limit multiplies by the replica
// count.
type UserCodeAttemptLimiter interface {
	Allow(ctx context.Context, key string, limit int, window time.Duration) (allowed bool, remaining int, err error)
}

type unlimitedAttempts struct{}

func (unlimitedAttempts) Allow(context.Context, string, int, time.Duration) (bool, int, error) {
	return true, math.MaxInt, nil
}

// UnlimitedUserCodeAttempts disables the attempt limit.
//
// It gives up the brute-force bound on user codes: with no limit the code
// space can be enumerated from the verification page, and a hit approves the
// victim's device into the attacker's account. It exists for tests and for
// deployments that enforce an equivalent limit in front of Kayan.
var UnlimitedUserCodeAttempts UserCodeAttemptLimiter = unlimitedAttempts{}

// UserCodeFormat is the alphabet and length of user codes. Generation,
// normalisation, and display all use it, so a custom format is accepted
// wherever it is typed.
type UserCodeFormat struct {
	Alphabet string
	Length   int
}

// DefaultUserCodeFormat is 8 characters of [DefaultUserCodeAlphabet], shown
// as XXXX-XXXX.
var DefaultUserCodeFormat = UserCodeFormat{Alphabet: DefaultUserCodeAlphabet, Length: 8}

// EntropyBits is the size of the code space in bits.
func (f UserCodeFormat) EntropyBits() float64 {
	if len(f.Alphabet) < 2 || f.Length < 1 {
		return 0
	}
	return float64(f.Length) * math.Log2(float64(len(f.Alphabet)))
}

func (f UserCodeFormat) validate() error {
	seen := map[rune]bool{}
	for _, ch := range f.Alphabet {
		if ch > 0x7f || ch == '-' || ch <= ' ' || ch != toUpperASCII(ch) {
			return fmt.Errorf("oauth2: user code alphabet must be uppercase printable ASCII without '-', got %q", ch)
		}
		if seen[ch] {
			return fmt.Errorf("oauth2: user code alphabet repeats %q", ch)
		}
		seen[ch] = true
	}
	if bits := f.EntropyBits(); bits < MinUserCodeEntropyBits {
		return fmt.Errorf("oauth2: user code format has %.1f bits of entropy, below the %d-bit floor", bits, MinUserCodeEntropyBits)
	}
	return nil
}

// generate draws a code with rejection sampling. Reducing a random byte
// modulo the alphabet size would make the first (256 mod size) characters
// likelier than the rest, shrinking the space the attempt limits assume.
func (f UserCodeFormat) generate(r io.Reader) (string, error) {
	size := len(f.Alphabet)
	limit := 256 - (256 % size)
	out := make([]byte, 0, f.Length)
	buf := make([]byte, 1)
	for len(out) < f.Length {
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", fmt.Errorf("oauth2: generate user code: %w", err)
		}
		if int(buf[0]) >= limit {
			continue
		}
		out = append(out, f.Alphabet[int(buf[0])%size])
	}
	return string(out), nil
}

// Normalize turns what a user typed into the stored form: uppercased, with
// hyphens and whitespace removed. A character outside the alphabet, or the
// wrong length, is an error.
func (f UserCodeFormat) Normalize(input string) (string, error) {
	var b strings.Builder
	for _, ch := range input {
		switch {
		case ch == '-' || ch == ' ' || ch == '\t':
			continue
		case !strings.ContainsRune(f.Alphabet, toUpperASCII(ch)):
			return "", ErrDeviceAuthorizationNotFound
		}
		b.WriteRune(toUpperASCII(ch))
	}
	if b.Len() != f.Length {
		return "", ErrDeviceAuthorizationNotFound
	}
	return b.String(), nil
}

// Display formats a normalised code in two hyphenated halves.
func (f UserCodeFormat) Display(code string) string {
	if len(code) < 4 {
		return code
	}
	half := (len(code) + 1) / 2
	return code[:half] + "-" + code[half:]
}

func toUpperASCII(ch rune) rune {
	if ch >= 'a' && ch <= 'z' {
		return ch - 'a' + 'A'
	}
	return ch
}

// DeviceAuthorizationConfig configures the device authorization grant.
type DeviceAuthorizationConfig struct {
	// VerificationURI is the page where the user enters the code. Required.
	VerificationURI string

	// IncludeVerificationURIComplete adds verification_uri_complete, a link
	// with the code embedded, to the response. Off by default: a link that
	// needs no typing is what device-code phishing sends the victim (RFC 8628
	// section 5.4).
	IncludeVerificationURIComplete bool

	// Lifetime is how long a device code stays usable. Defaults to
	// [DefaultDeviceAuthorizationLifetime].
	Lifetime time.Duration

	// Interval is the initial minimum time between polls. Defaults to
	// [DefaultDevicePollInterval].
	Interval time.Duration

	// UserCodes is the user-code format. Defaults to [DefaultUserCodeFormat];
	// a format below [MinUserCodeEntropyBits] is refused.
	UserCodes UserCodeFormat

	// Limiter bounds user-code attempts. Required; pass
	// [UnlimitedUserCodeAttempts] to disable the bound explicitly.
	Limiter UserCodeAttemptLimiter

	// MaxAttemptsPerIdentity and MaxAttemptsGlobal cap user-code attempts per
	// signed-in identity and across the deployment, per Lifetime. Default 10
	// and 1000.
	MaxAttemptsPerIdentity int
	MaxAttemptsGlobal      int
}

// WithDeviceAuthorization enables the device authorization grant (RFC 8628).
//
// It panics on a nil store, a nil limiter, an empty verification URI, or a
// user-code format below the entropy floor: each is a deployment that would
// otherwise run with a brute-forceable or unusable verification page while
// looking configured.
//
// A client may use the grant only when [GrantDeviceCode] is listed in its
// GrantTypes; an empty list does not count. Issuance at the device
// authorization endpoint is not rate limited here -- the endpoint accepts
// public clients, so limit it by source address in front of Kayan.
func WithDeviceAuthorization(store DeviceAuthorizationStore, cfg DeviceAuthorizationConfig) ProviderOption {
	if store == nil {
		panic("oauth2: WithDeviceAuthorization needs a store")
	}
	if cfg.Limiter == nil {
		panic("oauth2: WithDeviceAuthorization needs a Limiter; pass UnlimitedUserCodeAttempts to disable it explicitly")
	}
	if cfg.VerificationURI == "" {
		panic("oauth2: WithDeviceAuthorization needs a VerificationURI")
	}
	if cfg.UserCodes == (UserCodeFormat{}) {
		cfg.UserCodes = DefaultUserCodeFormat
	}
	if err := cfg.UserCodes.validate(); err != nil {
		panic(err.Error())
	}
	if cfg.Lifetime <= 0 {
		cfg.Lifetime = DefaultDeviceAuthorizationLifetime
	}
	if cfg.Interval <= 0 {
		cfg.Interval = DefaultDevicePollInterval
	}
	if cfg.MaxAttemptsPerIdentity <= 0 {
		cfg.MaxAttemptsPerIdentity = 10
	}
	if cfg.MaxAttemptsGlobal <= 0 {
		cfg.MaxAttemptsGlobal = 1000
	}
	return func(p *Provider) {
		p.deviceStore = store
		p.deviceConfig = cfg
	}
}

// SupportsDeviceAuthorization reports whether the device grant is enabled.
func (p *Provider) SupportsDeviceAuthorization() bool { return p.deviceStore != nil }

// DeviceAuthorizationResponse is the device authorization endpoint's answer
// (RFC 8628 section 3.2). Serve it as JSON.
type DeviceAuthorizationResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete,omitempty"`
	ExpiresIn               int64  `json:"expires_in"`
	Interval                int64  `json:"interval"`
}

// RequestDeviceAuthorization handles the device authorization endpoint
// (RFC 8628 section 3.1). The client authenticates as at the token endpoint;
// a public client sends only client_id.
func (p *Provider) RequestDeviceAuthorization(ctx context.Context, values url.Values, authorization string) (*DeviceAuthorizationResponse, error) {
	if !p.SupportsDeviceAuthorization() {
		return nil, ErrInvalidRequest.WithDescription("device authorization is not enabled").WithCause(ErrDeviceAuthorizationDisabled)
	}

	creds, err := clientCredentials(values, authorization)
	if err != nil {
		return nil, err
	}
	client, err := p.authenticateWith(ctx, creds, GrantDeviceCode)
	if err != nil {
		return nil, err
	}
	if !explicitlyAllowsGrant(client, GrantDeviceCode) {
		return nil, ErrUnauthorizedClient.WithDescription("client may not use the device authorization grant")
	}

	scopes := splitSpace(values.Get("scope"))
	if err := checkScopes(client, scopes); err != nil {
		return nil, err
	}

	deviceCode, err := p.tokens()
	if err != nil {
		return nil, ErrServerError.WithCause(err)
	}

	cfg := p.deviceConfig
	now := p.clock.Now()
	record := &DeviceAuthorization{
		DeviceCode: deviceCode,
		ClientID:   client.ID,
		TenantID:   tenant.IDFromContext(ctx),
		Scopes:     scopes,
		ExpiresAt:  now.Add(cfg.Lifetime),
		Interval:   cfg.Interval,
		Status:     DeviceAuthorizationPending,
	}

	// A collision is regenerated rather than reported: two live
	// authorizations sharing a code would let the user approving their own
	// device approve a stranger's.
	const attempts = 5
	for i := 0; ; i++ {
		record.UserCode, err = cfg.UserCodes.generate(p.random())
		if err != nil {
			return nil, ErrServerError.WithCause(err)
		}
		err = p.deviceStore.SaveDeviceAuthorization(ctx, record, now)
		if err == nil {
			break
		}
		if !errors.Is(err, ErrUserCodeCollision) || i == attempts-1 {
			return nil, ErrServerError.WithCause(err)
		}
	}

	p.logAudit(ctx, "oauth2.device.authorization", client.ID, "", "success", "")

	display := cfg.UserCodes.Display(record.UserCode)
	response := &DeviceAuthorizationResponse{
		DeviceCode:      deviceCode,
		UserCode:        display,
		VerificationURI: cfg.VerificationURI,
		ExpiresIn:       int64(cfg.Lifetime / time.Second),
		Interval:        int64(cfg.Interval / time.Second),
	}
	if cfg.IncludeVerificationURIComplete {
		response.VerificationURIComplete = withQueryParam(cfg.VerificationURI, "user_code", display)
	}
	return response, nil
}

// DeviceVerification is what the verification page shows a signed-in user
// before they approve: which application is asking, and for what.
type DeviceVerification struct {
	// Handle is the single-use reference to pass to
	// [Provider.ApproveDeviceAuthorization] or
	// [Provider.DenyDeviceAuthorization]. Carry it in the confirmation form;
	// it is a secret, bound to the identity it was issued to.
	Handle string

	// Client is the requesting application. Show its name: telling the user
	// which application they are about to authorise is the main defence
	// against device-code phishing (RFC 8628 section 5.4).
	Client *Client

	Scopes    []string
	ExpiresAt time.Time
}

// VerifyUserCode looks up the code a signed-in user typed and issues the
// handle that approving or denying it requires.
//
// Every call counts against the attempt limits -- per identity and across
// the deployment -- before the store is touched, whether or not the code
// exists. A limiter that fails is reported, not treated as an allowance.
// Unknown, expired, decided, and other-tenant codes are all
// [ErrDeviceAuthorizationNotFound].
func (p *Provider) VerifyUserCode(ctx context.Context, userCode, identityID string) (*DeviceVerification, error) {
	if !p.SupportsDeviceAuthorization() {
		return nil, ErrDeviceAuthorizationDisabled
	}
	if identityID == "" {
		return nil, errors.New("oauth2: VerifyUserCode needs the signed-in identity")
	}

	if err := p.checkUserCodeAttempts(ctx, identityID); err != nil {
		p.logAudit(ctx, "oauth2.device.verify", identityID, "", "failure", err.Error())
		return nil, err
	}

	normalized, err := p.deviceConfig.UserCodes.Normalize(userCode)
	if err != nil {
		return nil, err
	}

	handle, err := p.tokens()
	if err != nil {
		return nil, ErrServerError.WithCause(err)
	}
	record, err := p.deviceStore.BeginDeviceVerification(ctx, normalized, tenant.IDFromContext(ctx), handle, identityID, p.clock.Now())
	if err != nil {
		if errors.Is(err, ErrDeviceAuthorizationNotFound) {
			return nil, ErrDeviceAuthorizationNotFound
		}
		return nil, err
	}

	client, err := p.clientStore.GetClient(ctx, record.ClientID)
	if err != nil || client == nil {
		return nil, ErrDeviceAuthorizationNotFound
	}

	return &DeviceVerification{
		Handle:    handle,
		Client:    client,
		Scopes:    append([]string(nil), record.Scopes...),
		ExpiresAt: record.ExpiresAt,
	}, nil
}

// checkUserCodeAttempts applies both attempt limits. Keys are namespaced and
// carry the tenant, so a limiter shared with core/flow cannot collide with
// this one, and identities with the same ID in two tenants have separate
// budgets.
func (p *Provider) checkUserCodeAttempts(ctx context.Context, identityID string) error {
	cfg := p.deviceConfig
	keys := []struct {
		key   string
		limit int
	}{
		{"kayan:oauth2:device:tenant:" + tenant.IDFromContext(ctx) + ":identity:" + identityID, cfg.MaxAttemptsPerIdentity},
		// One bucket for the deployment: user codes share a single space, so
		// guessing spread across many accounts or tenants is still guessing.
		{"kayan:oauth2:device:global", cfg.MaxAttemptsGlobal},
	}
	for _, k := range keys {
		allowed, _, err := cfg.Limiter.Allow(ctx, k.key, k.limit, cfg.Lifetime)
		if err != nil {
			return ErrServerError.WithDescription("attempt limit unavailable").WithCause(err)
		}
		if !allowed {
			return ErrUserCodeAttemptsExceeded
		}
	}
	return nil
}

// ApproveDeviceAuthorization approves the authorization a handle from
// [Provider.VerifyUserCode] refers to, for the identity it was issued to.
// The handle is single use; an authorization decided by anyone already is
// not changed.
func (p *Provider) ApproveDeviceAuthorization(ctx context.Context, handle, identityID string, auth AuthenticationInfo) error {
	return p.completeDevice(ctx, handle, identityID, DeviceAuthorizationApproved, auth)
}

// DenyDeviceAuthorization denies the authorization a handle refers to.
func (p *Provider) DenyDeviceAuthorization(ctx context.Context, handle, identityID string) error {
	return p.completeDevice(ctx, handle, identityID, DeviceAuthorizationDenied, AuthenticationInfo{})
}

func (p *Provider) completeDevice(ctx context.Context, handle, identityID string, status DeviceAuthorizationStatus, auth AuthenticationInfo) error {
	if !p.SupportsDeviceAuthorization() {
		return ErrDeviceAuthorizationDisabled
	}
	if handle == "" || identityID == "" {
		return ErrDeviceAuthorizationNotFound
	}
	if err := p.deviceStore.CompleteDeviceAuthorization(ctx, handle, identityID, status, auth, p.clock.Now()); err != nil {
		p.logAudit(ctx, "oauth2.device."+string(status), identityID, identityID, "failure", err.Error())
		return err
	}
	p.logAudit(ctx, "oauth2.device."+string(status), identityID, identityID, "success", "")
	return nil
}

// DeviceToken answers a device_code token request (RFC 8628 section 3.4).
func (p *Provider) DeviceToken(ctx context.Context, req *TokenRequest) (*TokenResponse, error) {
	if req == nil || req.Client == nil {
		return nil, ErrInvalidRequest.WithDescription("no token request")
	}
	if req.GrantType != GrantDeviceCode {
		return nil, ErrUnsupportedGrantType.WithDescription("not a device code request")
	}
	if !p.SupportsDeviceAuthorization() {
		return nil, ErrUnsupportedGrantType.WithCause(ErrDeviceAuthorizationDisabled)
	}

	now := p.clock.Now()
	clientID := req.Client.ID
	record, slowDown, err := p.deviceStore.PollDeviceAuthorization(ctx, req.DeviceCode, clientID, now)
	if err != nil {
		if errors.Is(err, ErrDeviceAuthorizationNotFound) {
			return nil, ErrInvalidGrant.WithDescription("unknown device code")
		}
		return nil, ErrServerError.WithCause(err)
	}
	if !now.Before(record.ExpiresAt) {
		return nil, ErrExpiredToken
	}
	if slowDown {
		return nil, ErrSlowDown
	}

	switch record.Status {
	case DeviceAuthorizationPending:
		return nil, ErrAuthorizationPending
	case DeviceAuthorizationDenied:
		return nil, errDeviceAccessDenied
	case DeviceAuthorizationApproved:
	default:
		return nil, ErrServerError.WithDescription("unknown device authorization status")
	}

	approved, err := p.deviceStore.ConsumeDeviceAuthorization(ctx, req.DeviceCode, clientID, now)
	if err != nil {
		if errors.Is(err, ErrDeviceAuthorizationNotFound) {
			return nil, ErrInvalidGrant.WithDescription("device code already redeemed")
		}
		return nil, ErrServerError.WithCause(err)
	}

	accessToken, err := p.GenerateAccessToken(clientID, approved.IdentityID, approved.Scopes)
	if err != nil {
		return nil, ErrServerError.WithCause(err)
	}

	// The client lists its grants explicitly, so it can use a refresh token
	// only if refresh_token is among them; issuing one it could never redeem
	// would leave a live credential nothing can use or rotate.
	var refreshValue string
	if req.Client.AllowsGrantType(GrantRefreshToken) {
		refreshValue, err = p.issueRefreshToken(ctx, clientID, approved.IdentityID, approved.Scopes, "")
		if err != nil {
			return nil, err
		}
	}

	p.logAudit(ctx, "oauth2.device.token", clientID, approved.IdentityID, "success", "")

	return &TokenResponse{
		AccessToken:    accessToken,
		TokenType:      "Bearer",
		ExpiresIn:      int64(accessTokenTTL.Seconds()),
		RefreshToken:   refreshValue,
		Sub:            approved.IdentityID,
		Authentication: approved.Authentication,
	}, nil
}

// explicitlyAllowsGrant reports whether grant is listed in the client's
// GrantTypes. Unlike [Client.AllowsGrantType], an empty list does not count:
// enabling the device grant must not turn every client registered without a
// grant list -- a trusted first-party app among them -- into one an attacker
// can start a phishing flow under.
func explicitlyAllowsGrant(client *Client, grant string) bool {
	for _, allowed := range client.GrantTypes {
		if allowed == grant {
			return true
		}
	}
	return false
}

func withQueryParam(base, name, value string) string {
	u, err := url.Parse(base)
	if err != nil {
		return base
	}
	q := u.Query()
	q.Set(name, value)
	u.RawQuery = q.Encode()
	return u.String()
}

// random returns the randomness source for user codes.
func (p *Provider) random() io.Reader {
	if p.deviceRandom != nil {
		return p.deviceRandom
	}
	return rand.Reader
}

// MemoryDeviceAuthorizationStore is a single-process
// [DeviceAuthorizationStore].
//
// It is wrong for more than one process: a code entered on one replica is
// unknown to the replica the device polls. Use a shared store behind a load
// balancer.
type MemoryDeviceAuthorizationStore struct {
	mu      sync.Mutex
	records map[string]*DeviceAuthorization // by device code
}

// NewMemoryDeviceAuthorizationStore creates an empty store.
func NewMemoryDeviceAuthorizationStore() *MemoryDeviceAuthorizationStore {
	return &MemoryDeviceAuthorizationStore{records: map[string]*DeviceAuthorization{}}
}

func cloneDeviceAuthorization(a *DeviceAuthorization) *DeviceAuthorization {
	c := *a
	c.Scopes = append([]string(nil), a.Scopes...)
	c.Authentication.AMR = append([]string(nil), a.Authentication.AMR...)
	return &c
}

// SaveDeviceAuthorization implements [DeviceAuthorizationStore].
func (s *MemoryDeviceAuthorizationStore) SaveDeviceAuthorization(_ context.Context, a *DeviceAuthorization, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for code, r := range s.records {
		if !now.Before(r.ExpiresAt) {
			delete(s.records, code)
			continue
		}
		if r.UserCode == a.UserCode {
			return ErrUserCodeCollision
		}
	}
	s.records[a.DeviceCode] = cloneDeviceAuthorization(a)
	return nil
}

// BeginDeviceVerification implements [DeviceAuthorizationStore].
func (s *MemoryDeviceAuthorizationStore) BeginDeviceVerification(_ context.Context, userCode, tenantID, handle, identityID string, now time.Time) (*DeviceAuthorization, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.records {
		if r.UserCode == userCode && r.TenantID == tenantID &&
			r.Status == DeviceAuthorizationPending && now.Before(r.ExpiresAt) {
			r.VerificationHandle = handle
			r.VerifiedBy = identityID
			return cloneDeviceAuthorization(r), nil
		}
	}
	return nil, ErrDeviceAuthorizationNotFound
}

// CompleteDeviceAuthorization implements [DeviceAuthorizationStore].
func (s *MemoryDeviceAuthorizationStore) CompleteDeviceAuthorization(_ context.Context, handle, identityID string, status DeviceAuthorizationStatus, auth AuthenticationInfo, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.records {
		if r.VerificationHandle != "" && r.VerificationHandle == handle {
			if r.VerifiedBy != identityID || r.Status != DeviceAuthorizationPending || !now.Before(r.ExpiresAt) {
				return ErrDeviceAuthorizationNotFound
			}
			r.Status = status
			r.IdentityID = identityID
			r.Authentication = auth
			r.VerificationHandle = ""
			return nil
		}
	}
	return ErrDeviceAuthorizationNotFound
}

// PollDeviceAuthorization implements [DeviceAuthorizationStore].
func (s *MemoryDeviceAuthorizationStore) PollDeviceAuthorization(_ context.Context, deviceCode, clientID string, now time.Time) (*DeviceAuthorization, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.records[deviceCode]
	if !ok || r.ClientID != clientID {
		return nil, false, ErrDeviceAuthorizationNotFound
	}
	before := cloneDeviceAuthorization(r)
	slowDown := !r.LastPolledAt.IsZero() && now.Before(r.LastPolledAt.Add(r.Interval))
	if slowDown {
		r.Interval += DeviceSlowDownIncrement
	}
	r.LastPolledAt = now
	return before, slowDown, nil
}

// ConsumeDeviceAuthorization implements [DeviceAuthorizationStore].
func (s *MemoryDeviceAuthorizationStore) ConsumeDeviceAuthorization(_ context.Context, deviceCode, clientID string, now time.Time) (*DeviceAuthorization, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.records[deviceCode]
	if !ok || r.ClientID != clientID || r.Status != DeviceAuthorizationApproved || !now.Before(r.ExpiresAt) {
		return nil, ErrDeviceAuthorizationNotFound
	}
	delete(s.records, deviceCode)
	return cloneDeviceAuthorization(r), nil
}

// DeleteExpiredDeviceAuthorizations implements [DeviceAuthorizationStore].
func (s *MemoryDeviceAuthorizationStore) DeleteExpiredDeviceAuthorizations(_ context.Context, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for code, r := range s.records {
		if !now.Before(r.ExpiresAt) {
			delete(s.records, code)
		}
	}
	return nil
}
