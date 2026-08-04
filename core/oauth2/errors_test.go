package oauth2

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"testing"
)

func TestErrorStatusCodes(t *testing.T) {
	tests := []struct {
		err  *Error
		code string
		want int
	}{
		{ErrInvalidRequest, "invalid_request", http.StatusBadRequest},
		{ErrInvalidClient, "invalid_client", http.StatusUnauthorized},
		{ErrInvalidGrant, "invalid_grant", http.StatusBadRequest},
		{ErrUnauthorizedClient, "unauthorized_client", http.StatusBadRequest},
		{ErrUnsupportedGrantType, "unsupported_grant_type", http.StatusBadRequest},
		{ErrUnsupportedResponseType, "unsupported_response_type", http.StatusBadRequest},
		{ErrInvalidScope, "invalid_scope", http.StatusBadRequest},
		{ErrAccessDenied, "access_denied", http.StatusForbidden},
		{ErrServerError, "server_error", http.StatusInternalServerError},
		{ErrTemporarilyUnavailable, "temporarily_unavailable", http.StatusServiceUnavailable},
		{ErrInvalidToken, "invalid_token", http.StatusUnauthorized},
	}

	for _, tc := range tests {
		t.Run(tc.code, func(t *testing.T) {
			if tc.err.Code != tc.code {
				t.Errorf("code = %q, want %q", tc.err.Code, tc.code)
			}
			if got := tc.err.StatusCode(); got != tc.want {
				t.Errorf("status = %d, want %d", got, tc.want)
			}
		})
	}
}

// TestErrorsIsMatchesAcrossCopies proves a derived error still matches its
// sentinel, which is what lets callers branch on the error kind.
func TestErrorsIsMatchesAcrossCopies(t *testing.T) {
	err := ErrInvalidGrant.
		WithDescription("authorization code expired").
		WithCause(errors.New("row not found")).
		WithState("xyz")

	if !errors.Is(err, ErrInvalidGrant) {
		t.Error("derived error does not match its sentinel")
	}
	if errors.Is(err, ErrInvalidClient) {
		t.Error("derived error matches an unrelated sentinel")
	}
}

func TestErrorsAsExtractsProtocolError(t *testing.T) {
	wrapped := fmt.Errorf("exchange failed: %w", ErrInvalidClient.WithDescription("bad secret"))

	var oerr *Error
	if !errors.As(wrapped, &oerr) {
		t.Fatal("errors.As did not extract the protocol error")
	}
	if oerr.Code != "invalid_client" {
		t.Errorf("code = %q, want invalid_client", oerr.Code)
	}
	if oerr.StatusCode() != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", oerr.StatusCode())
	}
}

func TestUnwrapReachesCause(t *testing.T) {
	cause := errors.New("database unavailable")
	err := ErrServerError.WithCause(cause)

	if !errors.Is(err, cause) {
		t.Error("cause is not reachable through errors.Is")
	}
}

// TestSentinelsAreNeverMutated is the core safety property: the With* helpers
// must copy. A mutating implementation would let one request's description
// leak into another's response, and would corrupt the shared sentinel.
func TestSentinelsAreNeverMutated(t *testing.T) {
	original := *ErrInvalidGrant

	_ = ErrInvalidGrant.WithDescription("first")
	_ = ErrInvalidGrant.WithCause(errors.New("boom"))
	_ = ErrInvalidGrant.WithState("state-1")
	_ = ErrInvalidGrant.WithURI("https://example.test/errors")

	if ErrInvalidGrant.Description != original.Description {
		t.Errorf("sentinel description mutated to %q", ErrInvalidGrant.Description)
	}
	if ErrInvalidGrant.State != original.State {
		t.Errorf("sentinel state mutated to %q", ErrInvalidGrant.State)
	}
	if ErrInvalidGrant.URI != original.URI {
		t.Errorf("sentinel URI mutated to %q", ErrInvalidGrant.URI)
	}
	if ErrInvalidGrant.cause != original.cause {
		t.Error("sentinel cause mutated")
	}
	if ErrInvalidGrant.status != original.status {
		t.Error("sentinel status mutated")
	}
}

// TestSentinelsAreRaceFree runs the With* helpers concurrently. Under -race a
// mutating implementation reports a data race on the shared sentinel; without
// -race the assertions still catch cross-contamination between goroutines.
func TestSentinelsAreRaceFree(t *testing.T) {
	const goroutines = 64

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := range goroutines {
		go func(i int) {
			defer wg.Done()

			want := fmt.Sprintf("description-%d", i)
			err := ErrInvalidGrant.WithDescription(want)

			// Each goroutine must observe only its own description.
			if err.Description != want {
				t.Errorf("description = %q, want %q", err.Description, want)
			}
			if err.Code != "invalid_grant" {
				t.Errorf("code = %q, want invalid_grant", err.Code)
			}
			if !errors.Is(err, ErrInvalidGrant) {
				t.Error("copy no longer matches its sentinel")
			}
		}(i)
	}

	wg.Wait()

	if ErrInvalidGrant.Description != "" {
		t.Errorf("sentinel description = %q after concurrent use, want empty", ErrInvalidGrant.Description)
	}
}

// TestWireFormat pins the JSON shape RFC 6749 section 5.2 requires.
func TestWireFormat(t *testing.T) {
	err := ErrInvalidGrant.
		WithDescription("authorization code expired").
		WithState("xyz").
		WithCause(errors.New("internal detail that must not ship"))

	encoded, marshalErr := json.Marshal(err)
	if marshalErr != nil {
		t.Fatalf("marshal: %v", marshalErr)
	}

	var decoded map[string]any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded["error"] != "invalid_grant" {
		t.Errorf("error = %v, want invalid_grant", decoded["error"])
	}
	if decoded["error_description"] != "authorization code expired" {
		t.Errorf("error_description = %v", decoded["error_description"])
	}
	if decoded["state"] != "xyz" {
		t.Errorf("state = %v, want xyz", decoded["state"])
	}

	// The cause is for server-side diagnosis and must never reach the client.
	if body := string(encoded); containsSubstring(body, "internal detail") {
		t.Fatalf("cause leaked into the wire format: %s", body)
	}
}

// TestWireFormatOmitsEmptyMembers proves a bare error does not emit empty
// strings for optional members.
func TestWireFormatOmitsEmptyMembers(t *testing.T) {
	encoded, err := json.Marshal(ErrServerError)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if len(decoded) != 1 {
		t.Errorf("payload = %v, want only the error member", decoded)
	}
	if decoded["error"] != "server_error" {
		t.Errorf("error = %v, want server_error", decoded["error"])
	}
}

func TestWithDescriptionFormatting(t *testing.T) {
	// WithDescription takes the text verbatim, so a literal percent sign is
	// never interpreted as a format verb.
	literal := ErrInvalidRequest.WithDescription("100% invalid")
	if literal.Description != "100% invalid" {
		t.Errorf("description = %q, want %q", literal.Description, "100% invalid")
	}

	formatted := ErrInvalidRequest.WithDescriptionf("parameter %q is required", "redirect_uri")
	if formatted.Description != `parameter "redirect_uri" is required` {
		t.Errorf("description = %q", formatted.Description)
	}
}

func containsSubstring(haystack, needle string) bool {
	if needle == "" {
		return false
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
