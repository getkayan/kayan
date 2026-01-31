package oidc

import (
	"context"
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

// BackChannelLogoutNotifier implements the OIDC Back-Channel Logout notification.
type BackChannelLogoutNotifier struct {
	issuer      string
	signingKey  any
	keyID       string
	clientStore oauth2.ClientStore
	httpClient  *http.Client
}

func NewBackChannelLogoutNotifier(issuer string, signingKey any, keyID string, cs oauth2.ClientStore) *BackChannelLogoutNotifier {
	return &BackChannelLogoutNotifier{
		issuer:      issuer,
		signingKey:  signingKey,
		keyID:       keyID,
		clientStore: cs,
		httpClient:  &http.Client{Timeout: 5 * time.Second},
	}
}

func (n *BackChannelLogoutNotifier) NotifyLogout(sid string, identityID string) error {
	// In a headless, flexible system, we don't want to enforce how clients are retrieved.
	// For now, this is a placeholder where a developer can plug in their client logic.
	// In a real Kayan implementation, we would likely have a session-to-client mapping.
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
