package oauth2

import (
	"bytes"
	"context"
	"errors"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/getkayan/kayan/core/tenant"
)

const (
	deviceClientID  = "tv-app"
	deviceVerifyURI = "https://issuer.example.test/device"
)

type manualClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *manualClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *manualClock) advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

// countingLimiter allows limit calls per key and records every key it sees.
type countingLimiter struct {
	mu     sync.Mutex
	counts map[string]int
	err    error
}

func (l *countingLimiter) Allow(_ context.Context, key string, limit int, _ time.Duration) (bool, int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.err != nil {
		return false, 0, l.err
	}
	if l.counts == nil {
		l.counts = map[string]int{}
	}
	l.counts[key]++
	return l.counts[key] <= limit, limit - l.counts[key], nil
}

type deviceFixture struct {
	provider *Provider
	store    *MemoryDeviceAuthorizationStore
	clients  *securityStore
	clock    *manualClock
	limiter  *countingLimiter
}

func newDeviceFixture(t *testing.T, grants []string, mutate ...func(*DeviceAuthorizationConfig)) *deviceFixture {
	t.Helper()
	clock := &manualClock{now: time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)}
	limiter := &countingLimiter{}
	store := NewMemoryDeviceAuthorizationStore()
	cfg := DeviceAuthorizationConfig{VerificationURI: deviceVerifyURI, Limiter: limiter}
	for _, m := range mutate {
		m(&cfg)
	}
	provider, clients := newSecureProvider(t, WithProviderClock(clock), WithDeviceAuthorization(store, cfg))
	clients.clients[deviceClientID] = &Client{
		ID:                      deviceClientID,
		TokenEndpointAuthMethod: AuthMethodNone,
		GrantTypes:              grants,
	}
	return &deviceFixture{provider: provider, store: store, clients: clients, clock: clock, limiter: limiter}
}

func (f *deviceFixture) request(t *testing.T) *DeviceAuthorizationResponse {
	t.Helper()
	resp, err := f.provider.RequestDeviceAuthorization(context.Background(),
		url.Values{"client_id": {deviceClientID}, "scope": {"openid"}}, "")
	if err != nil {
		t.Fatalf("RequestDeviceAuthorization: %v", err)
	}
	return resp
}

func (f *deviceFixture) poll(deviceCode string) (*TokenResponse, error) {
	return f.pollAs(deviceClientID, deviceCode)
}

func (f *deviceFixture) pollAs(clientID, deviceCode string) (*TokenResponse, error) {
	req, err := f.provider.ParseTokenRequest(context.Background(), url.Values{
		"grant_type":  {GrantDeviceCode},
		"client_id":   {clientID},
		"device_code": {deviceCode},
	}, "")
	if err != nil {
		return nil, err
	}
	return f.provider.DeviceToken(context.Background(), req)
}

func (f *deviceFixture) approve(t *testing.T, userCode, identity string) {
	t.Helper()
	v, err := f.provider.VerifyUserCode(context.Background(), userCode, identity)
	if err != nil {
		t.Fatalf("VerifyUserCode: %v", err)
	}
	if err := f.provider.ApproveDeviceAuthorization(context.Background(), v.Handle, identity, AuthenticationInfo{ACR: "pwd"}); err != nil {
		t.Fatalf("ApproveDeviceAuthorization: %v", err)
	}
}

var deviceGrants = []string{GrantDeviceCode, GrantRefreshToken}

func TestDeviceFlowIssuesTokensOnceToTheApprovingUser(t *testing.T) {
	f := newDeviceFixture(t, deviceGrants)
	resp := f.request(t)
	if resp.VerificationURI != deviceVerifyURI || resp.VerificationURIComplete != "" {
		t.Errorf("verification URIs = %q / %q", resp.VerificationURI, resp.VerificationURIComplete)
	}
	if resp.Interval != 5 || resp.ExpiresIn != 600 {
		t.Errorf("interval=%d expires_in=%d", resp.Interval, resp.ExpiresIn)
	}

	if _, err := f.poll(resp.DeviceCode); !errors.Is(err, ErrAuthorizationPending) {
		t.Fatalf("before approval: err = %v, want authorization_pending", err)
	}

	// Typed in lowercase without the hyphen, as users do.
	f.approve(t, strings.ToLower(strings.ReplaceAll(resp.UserCode, "-", "")), "alice")

	f.clock.advance(5 * time.Second)
	tokens, err := f.poll(resp.DeviceCode)
	if err != nil {
		t.Fatalf("after approval: %v", err)
	}
	if tokens.Sub != "alice" || tokens.AccessToken == "" || tokens.RefreshToken == "" || tokens.Authentication.ACR != "pwd" {
		t.Errorf("tokens = %+v", tokens)
	}

	f.clock.advance(5 * time.Second)
	if _, err := f.poll(resp.DeviceCode); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("second redemption: err = %v, want invalid_grant", err)
	}
}

// TestDeviceGrantMustBeListedExplicitly. An empty GrantTypes means
// unrestricted for every other grant; for this one it must not, or enabling
// the grant turns every existing client into a phishing vector.
func TestDeviceGrantMustBeListedExplicitly(t *testing.T) {
	f := newDeviceFixture(t, nil)
	_, err := f.provider.RequestDeviceAuthorization(context.Background(), url.Values{"client_id": {deviceClientID}}, "")
	if !errors.Is(err, ErrUnauthorizedClient) {
		t.Errorf("request: err = %v, want unauthorized_client", err)
	}
	if _, err := f.poll("any"); !errors.Is(err, ErrUnauthorizedClient) {
		t.Errorf("token: err = %v, want unauthorized_client", err)
	}
}

func TestPollingTooFastSlowsTheClientDown(t *testing.T) {
	f := newDeviceFixture(t, deviceGrants)
	resp := f.request(t)

	_, _ = f.poll(resp.DeviceCode)
	f.clock.advance(time.Second)
	if _, err := f.poll(resp.DeviceCode); !errors.Is(err, ErrSlowDown) {
		t.Fatalf("err = %v, want slow_down", err)
	}
	// The interval is now 10s. Waiting the original 5s is still too fast.
	f.clock.advance(5 * time.Second)
	if _, err := f.poll(resp.DeviceCode); !errors.Is(err, ErrSlowDown) {
		t.Fatalf("after the old interval: err = %v, want slow_down", err)
	}
	f.clock.advance(15 * time.Second)
	if _, err := f.poll(resp.DeviceCode); !errors.Is(err, ErrAuthorizationPending) {
		t.Fatalf("after the new interval: err = %v, want authorization_pending", err)
	}
}

// TestAnotherClientCannotRedeemOrThrottle. A leaked device code presented by
// another client must neither yield tokens nor move the real client's polling
// state.
func TestAnotherClientCannotRedeemOrThrottle(t *testing.T) {
	f := newDeviceFixture(t, deviceGrants)
	f.clients.clients["other"] = &Client{ID: "other", TokenEndpointAuthMethod: AuthMethodNone, GrantTypes: deviceGrants}
	resp := f.request(t)

	// The real client polls, waits its interval, and the foreign client polls
	// in between. If that poll moved the shared state, the real client's next
	// poll would be answered slow_down.
	if _, err := f.poll(resp.DeviceCode); !errors.Is(err, ErrAuthorizationPending) {
		t.Fatalf("first poll: %v", err)
	}
	f.clock.advance(4 * time.Second)
	if _, err := f.pollAs("other", resp.DeviceCode); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("foreign client: err = %v, want invalid_grant", err)
	}
	f.clock.advance(1 * time.Second)
	if _, err := f.poll(resp.DeviceCode); !errors.Is(err, ErrAuthorizationPending) {
		t.Fatalf("real client after a foreign poll: err = %v, want authorization_pending", err)
	}

	f.approve(t, resp.UserCode, "alice")
	f.clock.advance(5 * time.Second)
	if _, err := f.pollAs("other", resp.DeviceCode); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("foreign client after approval: err = %v, want invalid_grant", err)
	}
}

// TestStoreTransitionsAreGuarded pins the store contract directly, below the
// provider's own checks: a handle is spent by its first use, and only an
// approved authorization can be consumed.
func TestStoreTransitionsAreGuarded(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryDeviceAuthorizationStore()
	now := time.Now()
	_ = store.SaveDeviceAuthorization(ctx, &DeviceAuthorization{
		DeviceCode: "dc", UserCode: "BBBBBBBB", ClientID: "c", ExpiresAt: now.Add(time.Minute),
		Status: DeviceAuthorizationPending,
	}, now)

	if _, err := store.ConsumeDeviceAuthorization(ctx, "dc", "c", now); !errors.Is(err, ErrDeviceAuthorizationNotFound) {
		t.Fatalf("consumed a pending authorization: err = %v", err)
	}

	if _, err := store.BeginDeviceVerification(ctx, "BBBBBBBB", "", "h1", "alice", now); err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteDeviceAuthorization(ctx, "h1", "alice", DeviceAuthorizationDenied, AuthenticationInfo{}, now); err != nil {
		t.Fatal(err)
	}
	if store.records["dc"].VerificationHandle != "" {
		t.Error("the handle survived its use")
	}
}

func TestDeniedAuthorizationReportsAccessDenied(t *testing.T) {
	f := newDeviceFixture(t, deviceGrants)
	resp := f.request(t)
	v, err := f.provider.VerifyUserCode(context.Background(), resp.UserCode, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.provider.DenyDeviceAuthorization(context.Background(), v.Handle, "alice"); err != nil {
		t.Fatal(err)
	}
	_, err = f.poll(resp.DeviceCode)
	if !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("err = %v, want access_denied", err)
	}
	var protocolErr *Error
	if errors.As(err, &protocolErr) && protocolErr.StatusCode() != 400 {
		t.Errorf("status = %d, want 400 at the token endpoint", protocolErr.StatusCode())
	}
}

// TestApprovalNeedsTheHandleItsIdentityWasIssued. The brute-force limit sits
// on VerifyUserCode. If approve took the user code, a handler wired straight
// to it would be an unlimited guessing oracle.
func TestApprovalNeedsTheHandleItsIdentityWasIssued(t *testing.T) {
	ctx := context.Background()
	f := newDeviceFixture(t, deviceGrants)
	resp := f.request(t)
	normalized := strings.ReplaceAll(resp.UserCode, "-", "")

	for _, guess := range []string{resp.UserCode, normalized, ""} {
		if err := f.provider.ApproveDeviceAuthorization(ctx, guess, "mallory", AuthenticationInfo{}); !errors.Is(err, ErrDeviceAuthorizationNotFound) {
			t.Errorf("approve with %q: err = %v, want not found", guess, err)
		}
	}

	v, err := f.provider.VerifyUserCode(ctx, resp.UserCode, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.provider.ApproveDeviceAuthorization(ctx, v.Handle, "mallory", AuthenticationInfo{}); !errors.Is(err, ErrDeviceAuthorizationNotFound) {
		t.Errorf("handle used by another identity: err = %v, want not found", err)
	}
	if err := f.provider.ApproveDeviceAuthorization(ctx, v.Handle, "alice", AuthenticationInfo{}); err != nil {
		t.Fatalf("own handle: %v", err)
	}
	if err := f.provider.DenyDeviceAuthorization(ctx, v.Handle, "alice"); !errors.Is(err, ErrDeviceAuthorizationNotFound) {
		t.Errorf("reused handle overturned the decision: err = %v", err)
	}
	if _, err := f.provider.VerifyUserCode(ctx, resp.UserCode, "bob"); !errors.Is(err, ErrDeviceAuthorizationNotFound) {
		t.Errorf("a decided code verified again: err = %v", err)
	}
}

// TestUserCodeAttemptsAreCapped. Every attempt counts, hit or miss, so the
// code space cannot be enumerated from the verification page.
func TestUserCodeAttemptsAreCapped(t *testing.T) {
	f := newDeviceFixture(t, deviceGrants, func(c *DeviceAuthorizationConfig) { c.MaxAttemptsPerIdentity = 3 })
	resp := f.request(t)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		if _, err := f.provider.VerifyUserCode(ctx, "BBBB-BBBB", "mallory"); !errors.Is(err, ErrDeviceAuthorizationNotFound) {
			t.Fatalf("attempt %d: err = %v", i, err)
		}
	}
	// The fourth attempt is refused even for the right code.
	if _, err := f.provider.VerifyUserCode(ctx, resp.UserCode, "mallory"); !errors.Is(err, ErrUserCodeAttemptsExceeded) {
		t.Fatalf("err = %v, want ErrUserCodeAttemptsExceeded", err)
	}
	// Another identity has its own budget.
	if _, err := f.provider.VerifyUserCode(ctx, resp.UserCode, "alice"); err != nil {
		t.Fatalf("another identity was throttled: %v", err)
	}
}

// TestLimiterKeysAreNamespacedPerTenant. A limiter shared with core/flow, or
// across tenants whose identity IDs overlap, must not share buckets.
func TestLimiterKeysAreNamespacedPerTenant(t *testing.T) {
	f := newDeviceFixture(t, deviceGrants)
	for _, tid := range []string{"tenant-a", "tenant-b"} {
		ctx := tenant.WithTenant(context.Background(), &tenant.Tenant{ID: tid})
		_, _ = f.provider.VerifyUserCode(ctx, "BBBB-BBBB", "42")
	}
	var identityKeys []string
	for key := range f.limiter.counts {
		if !strings.HasPrefix(key, "kayan:oauth2:device:") {
			t.Errorf("limiter key %q is not namespaced", key)
		}
		if strings.Contains(key, ":identity:") {
			identityKeys = append(identityKeys, key)
		}
	}
	if len(identityKeys) != 2 {
		t.Errorf("identity keys = %v, want one per tenant", identityKeys)
	}
}

func TestLimiterFailureFailsClosed(t *testing.T) {
	f := newDeviceFixture(t, deviceGrants)
	resp := f.request(t)
	f.limiter.err = errors.New("redis down")
	if _, err := f.provider.VerifyUserCode(context.Background(), resp.UserCode, "alice"); !errors.Is(err, ErrServerError) {
		t.Fatalf("err = %v, want server_error", err)
	}
}

func TestCodeFromAnotherTenantIsNotFound(t *testing.T) {
	f := newDeviceFixture(t, deviceGrants)
	ctxA := tenant.WithTenant(context.Background(), &tenant.Tenant{ID: "tenant-a"})
	resp, err := f.provider.RequestDeviceAuthorization(ctxA, url.Values{"client_id": {deviceClientID}}, "")
	if err != nil {
		t.Fatal(err)
	}
	ctxB := tenant.WithTenant(context.Background(), &tenant.Tenant{ID: "tenant-b"})
	if _, err := f.provider.VerifyUserCode(ctxB, resp.UserCode, "bob"); !errors.Is(err, ErrDeviceAuthorizationNotFound) {
		t.Fatalf("err = %v, want not found", err)
	}
}

func TestExpiredAuthorizationCannotBeApprovedOrRedeemed(t *testing.T) {
	f := newDeviceFixture(t, deviceGrants)
	resp := f.request(t)
	v, err := f.provider.VerifyUserCode(context.Background(), resp.UserCode, "alice")
	if err != nil {
		t.Fatal(err)
	}
	f.clock.advance(11 * time.Minute)
	if err := f.provider.ApproveDeviceAuthorization(context.Background(), v.Handle, "alice", AuthenticationInfo{}); !errors.Is(err, ErrDeviceAuthorizationNotFound) {
		t.Errorf("approve after expiry: err = %v", err)
	}
	if _, err := f.poll(resp.DeviceCode); !errors.Is(err, ErrExpiredToken) {
		t.Errorf("poll after expiry: err = %v, want expired_token", err)
	}
}

func TestNoRefreshTokenUnlessTheClientMayRefresh(t *testing.T) {
	f := newDeviceFixture(t, []string{GrantDeviceCode})
	resp := f.request(t)
	f.approve(t, resp.UserCode, "alice")
	tokens, err := f.poll(resp.DeviceCode)
	if err != nil {
		t.Fatal(err)
	}
	if tokens.RefreshToken != "" {
		t.Error("a refresh token was issued to a client that may not use the refresh grant")
	}
}

func TestConcurrentRedemptionYieldsOneTokenSet(t *testing.T) {
	store := NewMemoryDeviceAuthorizationStore()
	now := time.Now()
	_ = store.SaveDeviceAuthorization(context.Background(), &DeviceAuthorization{
		DeviceCode: "dc", UserCode: "BBBBBBBB", ClientID: "c", ExpiresAt: now.Add(time.Minute),
		Status: DeviceAuthorizationApproved, IdentityID: "alice",
	}, now)

	var wins int
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := store.ConsumeDeviceAuthorization(context.Background(), "dc", "c", now); err == nil {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("%d redemptions succeeded, want 1", wins)
	}
}

// TestUserCodeGenerationRejectsBiasedBytes. Bytes at or above 240 (the
// largest multiple of 20 below 256) must be skipped, not reduced modulo 20.
func TestUserCodeGenerationRejectsBiasedBytes(t *testing.T) {
	input := []byte{255, 240, 0, 1, 2, 3, 4, 5, 6, 7}
	code, err := DefaultUserCodeFormat.generate(bytes.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if code != "BCDFGHJK" {
		t.Fatalf("code = %q, want BCDFGHJK (bytes 255 and 240 skipped)", code)
	}
}

func TestWeakOrMissingConfigurationPanics(t *testing.T) {
	store := NewMemoryDeviceAuthorizationStore()
	for name, cfg := range map[string]DeviceAuthorizationConfig{
		"no limiter":    {VerificationURI: deviceVerifyURI},
		"no verify URI": {Limiter: UnlimitedUserCodeAttempts},
		"six digits": {VerificationURI: deviceVerifyURI, Limiter: UnlimitedUserCodeAttempts,
			UserCodes: UserCodeFormat{Alphabet: "0123456789", Length: 6}},
		"repeated alphabet": {VerificationURI: deviceVerifyURI, Limiter: UnlimitedUserCodeAttempts,
			UserCodes: UserCodeFormat{Alphabet: "BBCDFGHJKLMNPQRSTVWX", Length: 8}},
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s: WithDeviceAuthorization did not panic", name)
				}
			}()
			WithDeviceAuthorization(store, cfg)
		}()
	}
}

func TestDeviceGrantDisabledByDefault(t *testing.T) {
	provider, _ := newSecureProvider(t)
	if provider.SupportsDeviceAuthorization() {
		t.Fatal("device grant enabled without configuration")
	}
	if _, err := provider.VerifyUserCode(context.Background(), "BBBB-BBBB", "alice"); !errors.Is(err, ErrDeviceAuthorizationDisabled) {
		t.Errorf("err = %v", err)
	}
}
