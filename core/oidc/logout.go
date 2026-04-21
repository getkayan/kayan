package oidc

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/getkayan/kayan/core/oauth2"
	"github.com/golang-jwt/jwt/v5"
)

// LogoutNotifier defines the interface for notifying clients of a logout event.
type LogoutNotifier interface {
	NotifyLogout(sid string, identityID string) error
}

// ClientLister is a consumer-defined interface for listing OAuth2 clients.
// The clientStore is type-asserted to this interface at runtime; if it is
// not implemented, NotifyLogout is a no-op.
type ClientLister interface {
	ListClients(ctx context.Context) ([]*oauth2.Client, error)
}

var ErrClientListingUnavailable = errors.New("oidc: client store does not support client listing")

// BackChannelLogoutOption configures optional notifier behavior.
type BackChannelLogoutOption func(*BackChannelLogoutNotifier)

// WithStrictClientListing makes NotifyLogout fail when the client store does not
// implement ClientLister instead of silently skipping fan-out.
func WithStrictClientListing() BackChannelLogoutOption {
	return func(n *BackChannelLogoutNotifier) {
		n.requireClientListing = true
	}
}

// BackChannelLogoutNotifier implements the OIDC Back-Channel Logout notification.
type BackChannelLogoutNotifier struct {
	issuer               string
	signingKey           any
	keyID                string
	clientStore          oauth2.ClientStore
	httpClient           *http.Client
	requireClientListing bool
}

func NewBackChannelLogoutNotifier(issuer string, signingKey any, keyID string, cs oauth2.ClientStore, opts ...BackChannelLogoutOption) *BackChannelLogoutNotifier {
	n := &BackChannelLogoutNotifier{
		issuer:      issuer,
		signingKey:  signingKey,
		keyID:       keyID,
		clientStore: cs,
		httpClient:  &http.Client{Timeout: 5 * time.Second},
	}
	for _, opt := range opts {
		opt(n)
	}
	return n
}

func (n *BackChannelLogoutNotifier) NotifyLogout(sid string, identityID string) error {
	lister, ok := n.clientStore.(ClientLister)
	if !ok {
		if n.requireClientListing {
			return ErrClientListingUnavailable
		}
		return nil // store does not support listing; no-op
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	clients, err := lister.ListClients(ctx)
	if err != nil {
		return fmt.Errorf("oidc: failed to list clients: %w", err)
	}

	var errs []string
	for _, c := range clients {
		if c.BackChannelLogoutURI == "" {
			continue
		}
		if err := n.NotifyClient(ctx, c.ID, c.BackChannelLogoutURI, sid, identityID); err != nil {
			errs = append(errs, fmt.Sprintf("client %s: %v", c.ID, err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("oidc: backchannel logout errors: %s", strings.Join(errs, "; "))
	}
	return nil
}

func (n *BackChannelLogoutNotifier) NotifyClient(ctx context.Context, clientID string, logoutURI string, sid string, identityID string) error {
	if logoutURI == "" {
		return nil
	}

	// 1. Create Logout Token (JWT)
	now := time.Now()
	claims := jwt.MapClaims{
		"iss": n.issuer,
		"sub": identityID,
		"aud": clientID,
		"iat": now.Unix(),
		"jti": sid + "-" + clientID,
		"sid": sid,
		"events": map[string]any{
			"http://schemas.openid.net/event/backchannel-logout": map[string]any{},
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = n.keyID

	tokenString, err := token.SignedString(n.signingKey)
	if err != nil {
		return err
	}

	// 2. Send POST request
	form := url.Values{}
	form.Add("logout_token", tokenString)

	req, err := http.NewRequestWithContext(ctx, "POST", logoutURI, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := n.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("logout notification failed with status: %d", resp.StatusCode)
	}

	return nil
}
