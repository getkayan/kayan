package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/getkayan/kayan/internal/flow"
	"github.com/getkayan/kayan/internal/persistence"
	"github.com/getkayan/kayan/internal/session"
	"github.com/labstack/echo/v4"
)

func TestAPIIntegration(t *testing.T) {
	// Setup temporary database
	dbPath := "test_kayan.db"
	defer os.Remove(dbPath)

	repo, err := persistence.NewStorage("sqlite", dbPath, nil)
	if err != nil {
		t.Fatalf("failed to setup repo: %v", err)
	}

	regManager := flow.NewRegistrationManager(repo)
	logManager := flow.NewLoginManager(repo)
	sm := session.NewManager(repo)

	pwStrategy := flow.NewPasswordStrategy(repo, flow.NewBcryptHasher(14))
	regManager.RegisterStrategy(pwStrategy)
	logManager.RegisterStrategy(pwStrategy)

	h := NewHandler(regManager, logManager, sm, nil)

	e := echo.New()
	g := e.Group("/api/v1")
	h.RegisterRoutes(g)

	// 1. Test Registration
	regBody := map[string]interface{}{
		"traits":   map[string]string{"email": "test@example.com"},
		"password": "password123",
	}
	body, _ := json.Marshal(regBody)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/registration", bytes.NewBuffer(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("registration failed with code %d: %s", rec.Code, rec.Body.String())
	}

	// 2. Test Login
	loginBody := map[string]string{
		"identifier": `{"email":"test@example.com"}`,
		"password":   "password123",
	}
	body, _ = json.Marshal(loginBody)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/login", bytes.NewBuffer(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec = httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("login failed with code %d: %s", rec.Code, rec.Body.String())
	}

	var loginResponse struct {
		Token string `json:"token"`
	}
	json.Unmarshal(rec.Body.Bytes(), &loginResponse)

	// 3. Test WhoAmI (Protected)
	req = httptest.NewRequest(http.MethodGet, "/api/v1/whoami", nil)
	req.Header.Set("Authorization", loginResponse.Token)
	rec = httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("whoami failed with code %d: %s", rec.Code, rec.Body.String())
	}
}
