package gormstore

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/getkayan/kayan/kayan-oidc-provider/oauth2"
)

var deviceNow = time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)

func pendingDevice(code, user string) *oauth2.DeviceAuthorization {
	return &oauth2.DeviceAuthorization{
		DeviceCode: code,
		UserCode:   user,
		ClientID:   "tv",
		TenantID:   "t1",
		Scopes:     []string{"openid"},
		ExpiresAt:  deviceNow.Add(10 * time.Minute),
		Interval:   5 * time.Second,
		Status:     oauth2.DeviceAuthorizationPending,
	}
}

// TestDeviceAuthorizationRoundTripsEveryField. The drift test's fillStruct
// does not recurse into AuthenticationInfo, which is exactly where AuthTime,
// ACR, and AMR live -- the fields this adapter dropped from AuthCode once
// already. So the round trip is spelled out.
func TestDeviceAuthorizationRoundTripsEveryField(t *testing.T) {
	ctx := context.Background()
	repo := setupRepo(t)

	want := pendingDevice("dc", "BBBBBBBB")
	if err := repo.SaveDeviceAuthorization(ctx, want, deviceNow); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.BeginDeviceVerification(ctx, "BBBBBBBB", "t1", "h", "alice", deviceNow); err != nil {
		t.Fatal(err)
	}
	auth := oauth2.AuthenticationInfo{Nonce: "n", AuthTime: deviceNow.Add(-time.Minute), ACR: "mfa", AMR: []string{"pwd", "otp"}}
	if err := repo.CompleteDeviceAuthorization(ctx, "h", "alice", oauth2.DeviceAuthorizationApproved, auth, deviceNow); err != nil {
		t.Fatal(err)
	}
	got, err := repo.ConsumeDeviceAuthorization(ctx, "dc", "tv", deviceNow)
	if err != nil {
		t.Fatal(err)
	}

	want.Status = oauth2.DeviceAuthorizationApproved
	want.IdentityID = "alice"
	want.VerifiedBy = "alice"
	want.Authentication = auth
	got.ExpiresAt, want.ExpiresAt = got.ExpiresAt.UTC(), want.ExpiresAt.UTC()
	got.Authentication.AuthTime = got.Authentication.AuthTime.UTC()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round trip:\n got %+v\nwant %+v", got, want)
	}
}

func TestGormUserCodeCollision(t *testing.T) {
	ctx := context.Background()
	repo := setupRepo(t)
	if err := repo.SaveDeviceAuthorization(ctx, pendingDevice("dc1", "BBBBBBBB"), deviceNow); err != nil {
		t.Fatal(err)
	}
	if err := repo.SaveDeviceAuthorization(ctx, pendingDevice("dc2", "BBBBBBBB"), deviceNow); !errors.Is(err, oauth2.ErrUserCodeCollision) {
		t.Fatalf("live collision: err = %v, want ErrUserCodeCollision", err)
	}
	// Once the first has expired its code is free again.
	if err := repo.SaveDeviceAuthorization(ctx, pendingDevice("dc3", "BBBBBBBB"), deviceNow.Add(11*time.Minute)); err != nil {
		t.Fatalf("an expired authorization kept its code: %v", err)
	}
}

func TestGormVerificationIsScopedAndGuarded(t *testing.T) {
	ctx := context.Background()
	repo := setupRepo(t)
	_ = repo.SaveDeviceAuthorization(ctx, pendingDevice("dc", "BBBBBBBB"), deviceNow)

	if _, err := repo.BeginDeviceVerification(ctx, "BBBBBBBB", "t2", "h", "bob", deviceNow); !errors.Is(err, oauth2.ErrDeviceAuthorizationNotFound) {
		t.Errorf("other tenant: err = %v", err)
	}
	if _, err := repo.BeginDeviceVerification(ctx, "BBBBBBBB", "t1", "h", "alice", deviceNow.Add(11*time.Minute)); !errors.Is(err, oauth2.ErrDeviceAuthorizationNotFound) {
		t.Errorf("expired: err = %v", err)
	}
	if _, err := repo.BeginDeviceVerification(ctx, "BBBBBBBB", "t1", "h", "alice", deviceNow); err != nil {
		t.Fatal(err)
	}
	if err := repo.CompleteDeviceAuthorization(ctx, "h", "mallory", oauth2.DeviceAuthorizationApproved, oauth2.AuthenticationInfo{}, deviceNow); !errors.Is(err, oauth2.ErrDeviceAuthorizationNotFound) {
		t.Errorf("another identity's handle: err = %v", err)
	}
	if err := repo.CompleteDeviceAuthorization(ctx, "h", "alice", oauth2.DeviceAuthorizationApproved, oauth2.AuthenticationInfo{}, deviceNow.Add(11*time.Minute)); !errors.Is(err, oauth2.ErrDeviceAuthorizationNotFound) {
		t.Errorf("expired completion: err = %v", err)
	}
	if err := repo.CompleteDeviceAuthorization(ctx, "h", "alice", oauth2.DeviceAuthorizationDenied, oauth2.AuthenticationInfo{}, deviceNow); err != nil {
		t.Fatal(err)
	}
	if err := repo.CompleteDeviceAuthorization(ctx, "h", "alice", oauth2.DeviceAuthorizationApproved, oauth2.AuthenticationInfo{}, deviceNow); !errors.Is(err, oauth2.ErrDeviceAuthorizationNotFound) {
		t.Errorf("approve after deny: err = %v", err)
	}
	if err := repo.CompleteDeviceAuthorization(ctx, "", "alice", oauth2.DeviceAuthorizationApproved, oauth2.AuthenticationInfo{}, deviceNow); !errors.Is(err, oauth2.ErrDeviceAuthorizationNotFound) {
		t.Errorf("empty handle: err = %v", err)
	}
}

func TestGormPollingIsClientBoundAndPersistsSlowDown(t *testing.T) {
	ctx := context.Background()
	repo := setupRepo(t)
	_ = repo.SaveDeviceAuthorization(ctx, pendingDevice("dc", "BBBBBBBB"), deviceNow)

	if _, _, err := repo.PollDeviceAuthorization(ctx, "dc", "other", deviceNow); !errors.Is(err, oauth2.ErrDeviceAuthorizationNotFound) {
		t.Fatalf("foreign client: err = %v", err)
	}
	if _, slow, err := repo.PollDeviceAuthorization(ctx, "dc", "tv", deviceNow); err != nil || slow {
		t.Fatalf("first poll: slow=%v err=%v", slow, err)
	}
	if _, slow, _ := repo.PollDeviceAuthorization(ctx, "dc", "tv", deviceNow.Add(time.Second)); !slow {
		t.Fatal("polling inside the interval was not slowed down")
	}
	// The interval grew to 10s and that was persisted: 6s later is still fast.
	if _, slow, _ := repo.PollDeviceAuthorization(ctx, "dc", "tv", deviceNow.Add(7*time.Second)); !slow {
		t.Fatal("the increased interval was not persisted")
	}
	snapshot, slow, _ := repo.PollDeviceAuthorization(ctx, "dc", "tv", deviceNow.Add(30*time.Second))
	if slow || snapshot.Interval != 15*time.Second {
		t.Fatalf("slow=%v interval=%v, want an ordinary poll at 15s", slow, snapshot.Interval)
	}
}

func TestGormConsumeIsSingleUseAndApprovedOnly(t *testing.T) {
	ctx := context.Background()
	repo := setupRepo(t)
	_ = repo.SaveDeviceAuthorization(ctx, pendingDevice("dc", "BBBBBBBB"), deviceNow)

	if _, err := repo.ConsumeDeviceAuthorization(ctx, "dc", "tv", deviceNow); !errors.Is(err, oauth2.ErrDeviceAuthorizationNotFound) {
		t.Fatalf("consumed a pending authorization: err = %v", err)
	}
	_, _ = repo.BeginDeviceVerification(ctx, "BBBBBBBB", "t1", "h", "alice", deviceNow)
	_ = repo.CompleteDeviceAuthorization(ctx, "h", "alice", oauth2.DeviceAuthorizationApproved, oauth2.AuthenticationInfo{}, deviceNow)

	if _, err := repo.ConsumeDeviceAuthorization(ctx, "dc", "other", deviceNow); !errors.Is(err, oauth2.ErrDeviceAuthorizationNotFound) {
		t.Fatalf("another client consumed it: err = %v", err)
	}
	if _, err := repo.ConsumeDeviceAuthorization(ctx, "dc", "tv", deviceNow); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.ConsumeDeviceAuthorization(ctx, "dc", "tv", deviceNow); !errors.Is(err, oauth2.ErrDeviceAuthorizationNotFound) {
		t.Fatalf("second consume: err = %v", err)
	}
}

type fixedClock struct{ now time.Time }

func (c *fixedClock) Now() time.Time { return c.now }

// TestDeviceFlowEndToEndOnGorm runs the provider against this adapter.
func TestDeviceFlowEndToEndOnGorm(t *testing.T) {
	ctx := context.Background()
	repo := setupRepo(t)
	if err := repo.CreateClient(ctx, &oauth2.Client{
		ID: "tv", TokenEndpointAuthMethod: oauth2.AuthMethodNone,
		GrantTypes: []string{oauth2.GrantDeviceCode, oauth2.GrantRefreshToken},
	}); err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	clock := &fixedClock{now: time.Now()}
	provider := oauth2.NewProvider(repo, repo, repo, "https://issuer.example.test", key, "kid",
		oauth2.WithProviderClock(clock),
		oauth2.WithDeviceAuthorization(repo, oauth2.DeviceAuthorizationConfig{
			VerificationURI: "https://issuer.example.test/device",
			Limiter:         oauth2.UnlimitedUserCodeAttempts,
		}))

	resp, err := provider.RequestDeviceAuthorization(ctx, url.Values{"client_id": {"tv"}}, "")
	if err != nil {
		t.Fatal(err)
	}
	v, err := provider.VerifyUserCode(ctx, resp.UserCode, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if err := provider.ApproveDeviceAuthorization(ctx, v.Handle, "alice", oauth2.AuthenticationInfo{ACR: "mfa"}); err != nil {
		t.Fatal(err)
	}

	poll := func() (*oauth2.TokenResponse, error) {
		req, err := provider.ParseTokenRequest(ctx, url.Values{
			"grant_type": {oauth2.GrantDeviceCode}, "client_id": {"tv"}, "device_code": {resp.DeviceCode},
		}, "")
		if err != nil {
			return nil, err
		}
		return provider.DeviceToken(ctx, req)
	}
	tokens, err := poll()
	if err != nil {
		t.Fatalf("redeem: %v", err)
	}
	if tokens.Sub != "alice" || tokens.RefreshToken == "" || tokens.Authentication.ACR != "mfa" {
		t.Errorf("tokens = %+v", tokens)
	}
	clock.now = clock.now.Add(6 * time.Second)
	if _, err := poll(); !errors.Is(err, oauth2.ErrInvalidGrant) {
		t.Errorf("second redemption: err = %v, want invalid_grant", err)
	}
}

// TestGormGuardsHoldIndividually. Several transitions are guarded twice --
// a spent handle and a non-pending status both stop a second completion;
// the read and the delete in Consume both require approval. Each guard is
// pinned here on its own, so removing one is not hidden by the other.
func TestGormGuardsHoldIndividually(t *testing.T) {
	ctx := context.Background()
	repo := setupRepo(t)
	_ = repo.SaveDeviceAuthorization(ctx, pendingDevice("dc", "BBBBBBBB"), deviceNow)
	_, _ = repo.BeginDeviceVerification(ctx, "BBBBBBBB", "t1", "h", "alice", deviceNow)
	_ = repo.CompleteDeviceAuthorization(ctx, "h", "alice", oauth2.DeviceAuthorizationDenied, oauth2.AuthenticationInfo{}, deviceNow)

	var row gormDeviceAuthorization
	if err := repo.db.First(&row, "device_code = ?", "dc").Error; err != nil {
		t.Fatal(err)
	}
	if row.VerificationHandle != "" {
		t.Error("the handle survived its use")
	}

	// Restore the handle by hand: only the status guard now stands between
	// a decided authorization and a second decision.
	repo.db.Model(&gormDeviceAuthorization{}).Where("device_code = ?", "dc").Update("verification_handle", "h")
	if err := repo.CompleteDeviceAuthorization(ctx, "h", "alice", oauth2.DeviceAuthorizationApproved, oauth2.AuthenticationInfo{}, deviceNow); !errors.Is(err, oauth2.ErrDeviceAuthorizationNotFound) {
		t.Errorf("a denied authorization was approved: err = %v", err)
	}
}
