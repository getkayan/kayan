package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/getkayan/kayan/core/admin"
	"github.com/getkayan/kayan/core/flow"
	gormstore "github.com/getkayan/kayan/kayan-gorm"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func testApplication(t *testing.T, allowRegistration bool) *application {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("database pool: %v", err)
	}
	sqlDB.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = sqlDB.Close() })
	repo := gormstore.NewRepository(db)
	if err := repo.AutoMigrateDev(); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return newApplication(repo, flow.NewMemoryLockoutStore(), allowRegistration)
}

func request(t *testing.T, handler http.Handler, method, path, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var payload bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&payload).Encode(body); err != nil {
			t.Fatalf("encode request: %v", err)
		}
	}
	req := httptest.NewRequest(method, path, &payload)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	return response
}

func tokenResponse(t *testing.T, response *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	if response.Code != http.StatusOK {
		t.Fatalf("login status = %d, body = %s", response.Code, response.Body.String())
	}
	var tokens map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &tokens); err != nil {
		t.Fatalf("decode tokens: %v", err)
	}
	return tokens
}

func login(t *testing.T, handler http.Handler, email, password string) map[string]any {
	t.Helper()
	return tokenResponse(t, request(t, handler, http.MethodPost, "/api/login", "", map[string]string{
		"Email": email, "Password": password,
	}))
}

func TestProductionPathUsersLoginRolesPermissionsAndLockout(t *testing.T) {
	app := testApplication(t, false)
	if err := app.bootstrap(t.Context(), "admin@example.test", "StrongBootstrapPassword123"); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	handler := app.routes()
	adminTokens := login(t, handler, "admin@example.test", "StrongBootstrapPassword123")
	adminToken := adminTokens["access_token"].(string)

	response := request(t, handler, http.MethodPost, "/api/admin/roles", adminToken, admin.CreateRoleInput{
		Name: "reader", Permissions: []string{"documents:read"},
	})
	if response.Code != http.StatusCreated {
		t.Fatalf("create role status = %d, body = %s", response.Code, response.Body.String())
	}
	response = request(t, handler, http.MethodPost, "/api/admin/users", adminToken, admin.CreateUserInput{
		Email: "reader@example.test", Password: "StrongReaderPassword123", Roles: []string{"reader"},
	})
	if response.Code != http.StatusCreated {
		t.Fatalf("create user status = %d, body = %s", response.Code, response.Body.String())
	}
	var created admin.User
	if err := json.Unmarshal(response.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode user: %v", err)
	}

	readerTokens := login(t, handler, "reader@example.test", "StrongReaderPassword123")
	readerToken := readerTokens["access_token"].(string)
	if response := request(t, handler, http.MethodGet, "/api/documents", readerToken, nil); response.Code != http.StatusOK {
		t.Fatalf("permission check status = %d, body = %s", response.Code, response.Body.String())
	}
	if response := request(t, handler, http.MethodGet, "/api/admin/users", readerToken, nil); response.Code != http.StatusForbidden {
		t.Fatalf("unprivileged admin read status = %d, want 403", response.Code)
	}

	lockPath := fmt.Sprintf("/api/admin/users/%v/lock", created.ID)
	if response := request(t, handler, http.MethodPost, lockPath, adminToken, nil); response.Code != http.StatusNoContent {
		t.Fatalf("lock status = %d, body = %s", response.Code, response.Body.String())
	}
	if response := request(t, handler, http.MethodGet, "/api/documents", readerToken, nil); response.Code != http.StatusUnauthorized {
		t.Fatalf("pre-lock session status = %d, want 401", response.Code)
	}
	if response := request(t, handler, http.MethodPost, "/api/login", "", map[string]string{
		"Email": "reader@example.test", "Password": "StrongReaderPassword123",
	}); response.Code != http.StatusUnauthorized {
		t.Fatalf("locked login status = %d, want 401", response.Code)
	}
}

func TestProductionPathRotatesRefreshAndRevokesLogout(t *testing.T) {
	app := testApplication(t, false)
	if err := app.bootstrap(t.Context(), "admin@example.test", "StrongBootstrapPassword123"); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	handler := app.routes()
	tokens := login(t, handler, "admin@example.test", "StrongBootstrapPassword123")
	oldAccess := tokens["access_token"].(string)
	oldRefresh := tokens["refresh_token"].(string)

	rotated := tokenResponse(t, request(t, handler, http.MethodPost, "/api/refresh", "", map[string]string{
		"refresh_token": oldRefresh,
	}))
	newAccess := rotated["access_token"].(string)
	if newAccess == oldAccess || rotated["refresh_token"] == oldRefresh {
		t.Fatal("refresh did not rotate both tokens")
	}
	if response := request(t, handler, http.MethodPost, "/api/refresh", "", map[string]string{
		"refresh_token": oldRefresh,
	}); response.Code != http.StatusUnauthorized {
		t.Fatalf("replayed refresh status = %d, want 401", response.Code)
	}
	if response := request(t, handler, http.MethodDelete, "/api/logout", newAccess, nil); response.Code != http.StatusNoContent {
		t.Fatalf("logout status = %d, body = %s", response.Code, response.Body.String())
	}
	if response := request(t, handler, http.MethodGet, "/api/me", newAccess, nil); response.Code != http.StatusUnauthorized {
		t.Fatalf("logged-out session status = %d, want 401", response.Code)
	}
}

func TestProductionPathRefusesPublicRegistrationByDefault(t *testing.T) {
	app := testApplication(t, false)
	response := request(t, app.routes(), http.MethodPost, "/api/register", "", map[string]string{
		"Email": "public@example.test", "Password": "StrongPublicPassword123",
	})
	if response.Code != http.StatusNotFound {
		t.Fatalf("registration status = %d, want 404", response.Code)
	}
}
