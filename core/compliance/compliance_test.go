package compliance

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"
)

type testRetentionStore struct {
	auditCount       int64
	sessionCount     int64
	consentCount     int64
	failedLoginCount int64
	deletedUserCount int64
	auditErr         error
	lastCutoffs      map[string]time.Time
}

func (s *testRetentionStore) PurgeAuditLogs(_ context.Context, olderThan time.Time) (int64, error) {
	s.lastCutoffs["audit_logs"] = olderThan
	return s.auditCount, s.auditErr
}

func (s *testRetentionStore) PurgeSessions(_ context.Context, olderThan time.Time) (int64, error) {
	s.lastCutoffs["sessions"] = olderThan
	return s.sessionCount, nil
}

func (s *testRetentionStore) PurgeConsents(_ context.Context, olderThan time.Time) (int64, error) {
	s.lastCutoffs["consents"] = olderThan
	return s.consentCount, nil
}

func (s *testRetentionStore) PurgeFailedLogins(_ context.Context, olderThan time.Time) (int64, error) {
	s.lastCutoffs["failed_logins"] = olderThan
	return s.failedLoginCount, nil
}

func (s *testRetentionStore) PurgeDeletedUsers(_ context.Context, olderThan time.Time) (int64, error) {
	s.lastCutoffs["deleted_users"] = olderThan
	return s.deletedUserCount, nil
}

func TestRetentionManagerRunCleanupAndHooks(t *testing.T) {
	store := &testRetentionStore{
		auditCount:       3,
		sessionCount:     2,
		consentCount:     1,
		failedLoginCount: 4,
		deletedUserCount: 5,
		auditErr:         errors.New("audit purge failed"),
		lastCutoffs:      map[string]time.Time{},
	}

	manager := NewRetentionManager(store, &RetentionPolicy{
		AuditLogDays:       365,
		SessionHistoryDays: 90,
		ConsentRecordDays:  30,
		FailedLoginDays:    10,
		DeletedUserDays:    7,
	})

	var before []string
	var after []string
	var onError []string
	manager.SetHooks(RetentionHooks{
		BeforePurge: func(_ context.Context, dataType string, _ int64) {
			before = append(before, dataType)
		},
		AfterPurge: func(_ context.Context, dataType string, count int64, err error) {
			after = append(after, dataType)
			if dataType == "audit_logs" && count != 3 {
				t.Errorf("expected audit purge count 3, got %d", count)
			}
			if dataType == "audit_logs" && err == nil {
				t.Fatal("expected audit purge error")
			}
		},
		OnError: func(_ context.Context, dataType string, err error) {
			onError = append(onError, dataType+":"+err.Error())
		},
	})

	report, err := manager.RunCleanup(context.Background())
	if err != nil {
		t.Fatalf("run cleanup: %v", err)
	}

	if report.AuditLogsDeleted != 3 || report.SessionsDeleted != 2 || report.ConsentsDeleted != 1 || report.FailedLoginsDeleted != 4 || report.DeletedUsersRemoved != 5 {
		t.Fatalf("unexpected cleanup report: %+v", report)
	}
	if len(report.Errors) != 1 || report.Errors[0] != "audit_logs: audit purge failed" {
		t.Fatalf("unexpected errors: %#v", report.Errors)
	}
	if len(before) != 5 || len(after) != 5 {
		t.Fatalf("expected hooks for all purge operations, got before=%d after=%d", len(before), len(after))
	}
	if !reflect.DeepEqual(onError, []string{"audit_logs:audit purge failed"}) {
		t.Fatalf("unexpected onError callbacks: %#v", onError)
	}
	if store.lastCutoffs["sessions"].IsZero() {
		t.Fatal("expected session cutoff to be recorded")
	}
}

func TestAESEncryptionRoundTripAndRotate(t *testing.T) {
	key, err := GenerateAESKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	enc, err := NewAESEncryption(key)
	if err != nil {
		t.Fatalf("new encryption: %v", err)
	}

	plaintext := []byte("sensitive-value")
	ciphertext, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if string(ciphertext) == string(plaintext) {
		t.Fatal("expected ciphertext to differ from plaintext")
	}

	decrypted, err := enc.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Fatalf("unexpected plaintext after decrypt: %q", decrypted)
	}

	oldKey := append([]byte(nil), enc.key...)
	if err := enc.RotateKey(context.Background()); err != nil {
		t.Fatalf("rotate key: %v", err)
	}
	if reflect.DeepEqual(oldKey, enc.key) {
		t.Fatal("expected rotated key to change")
	}

	if _, err := NewAESEncryption([]byte("short")); err == nil {
		t.Fatal("expected short key to fail")
	}
	if _, err := enc.Decrypt([]byte("tiny")); err == nil {
		t.Fatal("expected short ciphertext to fail")
	}
}

func TestSecurityHeadersMiddleware(t *testing.T) {
	middleware := SecurityHeadersMiddleware(&SecurityHeadersConfig{
		ContentSecurityPolicy:   "default-src 'none'",
		StrictTransportSecurity: "max-age=1",
		XContentTypeOptions:     "nosniff",
		XFrameOptions:           "DENY",
		XXSSProtection:          "1; mode=block",
		ReferrerPolicy:          "same-origin",
		PermissionsPolicy:       "camera=()",
		CustomHeaders: map[string]string{
			"X-Custom-Security": "enabled",
		},
	})

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	handler.ServeHTTP(recorder, request)

	if got := recorder.Header().Get("Content-Security-Policy"); got != "default-src 'none'" {
		t.Fatalf("unexpected CSP header: %q", got)
	}
	if got := recorder.Header().Get("Strict-Transport-Security"); got != "max-age=1" {
		t.Fatalf("unexpected HSTS header: %q", got)
	}
	if got := recorder.Header().Get("X-Custom-Security"); got != "enabled" {
		t.Fatalf("unexpected custom header: %q", got)
	}
}