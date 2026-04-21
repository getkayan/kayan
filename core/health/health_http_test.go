package health

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLiveHandler(t *testing.T) {
	mgr := NewManager("1.0.0")
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/healthz", nil)

	mgr.LiveHandler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", recorder.Code)
	}
	if contentType := recorder.Header().Get("Content-Type"); contentType != "application/json" {
		t.Fatalf("expected application/json, got %q", contentType)
	}

	var body map[string]string
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if body["status"] != "ok" {
		t.Fatalf("expected status ok, got %q", body["status"])
	}
}

func TestReadyHandler_Ready(t *testing.T) {
	mgr := NewManager("1.0.0")
	mgr.RegisterFunc("cache", func(ctx context.Context) *Check {
		return &Check{Name: "cache", Status: StatusDegraded}
	})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/ready", nil)

	mgr.ReadyHandler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", recorder.Code)
	}
}

func TestReadyHandler_NotReady(t *testing.T) {
	mgr := NewManager("1.0.0")
	mgr.RegisterFunc("db", func(ctx context.Context) *Check {
		return &Check{Name: "db", Status: StatusUnhealthy}
	})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/ready", nil)

	mgr.ReadyHandler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected status 503, got %d", recorder.Code)
	}
}

func TestFullHandler_Healthy(t *testing.T) {
	mgr := NewManager("1.0.0")
	mgr.RegisterFunc("ok", func(ctx context.Context) *Check {
		return &Check{Name: "ok", Status: StatusHealthy}
	})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/health", nil)

	mgr.FullHandler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", recorder.Code)
	}

	var report Report
	if err := json.Unmarshal(recorder.Body.Bytes(), &report); err != nil {
		t.Fatalf("failed to decode report: %v", err)
	}
	if report.Status != StatusHealthy {
		t.Fatalf("expected healthy report, got %s", report.Status)
	}
}

func TestFullHandler_Unhealthy(t *testing.T) {
	mgr := NewManager("1.0.0")
	mgr.RegisterFunc("db", func(ctx context.Context) *Check {
		return &Check{Name: "db", Status: StatusUnhealthy}
	})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/health", nil)

	mgr.FullHandler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected status 503, got %d", recorder.Code)
	}
}
