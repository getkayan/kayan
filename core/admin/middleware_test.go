package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWriteJSON(t *testing.T) {
	w := httptest.NewRecorder()
	writeJSON(w, http.StatusOK, map[string]string{"key": "value"})

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected Content-Type application/json, got %s", ct)
	}

	var body map[string]string
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode JSON body: %v", err)
	}
	if body["key"] != "value" {
		t.Errorf("expected key=value, got key=%s", body["key"])
	}
}

func TestWriteJSON_Struct(t *testing.T) {
	type payload struct {
		Name  string `json:"name"`
		Count int    `json:"count"`
	}
	w := httptest.NewRecorder()
	writeJSON(w, http.StatusCreated, payload{Name: "test", Count: 42})

	if w.Code != http.StatusCreated {
		t.Errorf("expected status 201, got %d", w.Code)
	}

	var body payload
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode JSON body: %v", err)
	}
	if body.Name != "test" || body.Count != 42 {
		t.Errorf("unexpected body: %+v", body)
	}
}

func TestWriteError(t *testing.T) {
	w := httptest.NewRecorder()
	writeError(w, http.StatusForbidden, "insufficient permissions")

	if w.Code != http.StatusForbidden {
		t.Errorf("expected status 403, got %d", w.Code)
	}

	var body map[string]string
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode JSON body: %v", err)
	}
	if body["error"] != "Forbidden" {
		t.Errorf("expected error=Forbidden, got %s", body["error"])
	}
	if body["message"] != "insufficient permissions" {
		t.Errorf("expected message=insufficient permissions, got %s", body["message"])
	}
}

func TestWriteError_SpecialCharacters(t *testing.T) {
	w := httptest.NewRecorder()
	writeError(w, http.StatusBadRequest, `value with "quotes" and <brackets>`)

	var body map[string]string
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("JSON with special characters should be properly escaped: %v", err)
	}
	if body["message"] != `value with "quotes" and <brackets>` {
		t.Errorf("unexpected message: %s", body["message"])
	}
}

type mockAuthenticator struct {
	admin *AdminIdentity
	err   error
}

func (m *mockAuthenticator) Authenticate(r *http.Request) (*AdminIdentity, error) {
	return m.admin, m.err
}

func TestAuthMiddleware_NoAuth(t *testing.T) {
	auth := &mockAuthenticator{admin: nil, err: ErrNoToken}
	middleware := AuthMiddleware(auth)

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called")
	}))

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}

	var body map[string]string
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("response should contain valid JSON: %v", err)
	}
	if body["message"] != "authentication required" {
		t.Errorf("expected message=authentication required, got %s", body["message"])
	}
}

func TestAuthMiddleware_Authenticated(t *testing.T) {
	admin := &AdminIdentity{ID: "1", Email: "admin@test.com", IsSuperAdmin: true}
	auth := &mockAuthenticator{admin: admin, err: nil}
	middleware := AuthMiddleware(auth)

	called := false
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		got := GetAdminFromContext(r.Context())
		if got == nil || got.ID != "1" {
			t.Error("expected admin in context")
		}
	}))

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	handler.ServeHTTP(w, r)

	if !called {
		t.Error("handler should have been called")
	}
}

func TestRequireSuperAdmin_NonSuper(t *testing.T) {
	middleware := RequireSuperAdmin()

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called")
	}))

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	// Inject non-super admin into context
	admin := &AdminIdentity{ID: "2", IsSuperAdmin: false}
	r = r.WithContext(context.WithValue(r.Context(), AdminContextKey{}, admin))

	handler.ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}

	var body map[string]string
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("response should contain valid JSON: %v", err)
	}
	if body["message"] != "super admin access required" {
		t.Errorf("expected message=super admin access required, got %s", body["message"])
	}
}
