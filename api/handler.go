package api

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/getkayan/kayan/domain"
	"github.com/getkayan/kayan/flow"
	"github.com/getkayan/kayan/identity"
	"github.com/getkayan/kayan/session"
	"github.com/labstack/echo/v4"
)

type Handler[T any] struct {
	regManager     *flow.RegistrationManager[T]
	logManager     *flow.LoginManager[T]
	sessionManager *session.Manager[T]
	oidcManager    *flow.OIDCManager[T]
	generator      domain.IDGenerator[T]
}

func NewHandler[T any](reg *flow.RegistrationManager[T], log *flow.LoginManager[T], sm *session.Manager[T], om *flow.OIDCManager[T]) *Handler[T] {
	return &Handler[T]{regManager: reg, logManager: log, sessionManager: sm, oidcManager: om}
}

func (h *Handler[T]) SetIDGenerator(g domain.IDGenerator[T]) {
	h.generator = g
}

func (h *Handler[T]) RegisterRoutes(g *echo.Group) {
	g.POST("/registration", h.HandleRegistration)
	g.POST("/login", h.HandleLogin)

	// OIDC routes
	g.GET("/auth/oidc/:provider", h.HandleOIDCAuth)
	g.GET("/auth/oidc/:provider/callback", h.HandleOIDCCallback)

	// Protected routes
	protected := g.Group("")
	protected.Use(h.AuthMiddleware)
	protected.GET("/whoami", h.HandleWhoAmI)
}

func (h *Handler[T]) HandleRegistration(c echo.Context) error {
	var body struct {
		Traits   map[string]interface{} `json:"traits"`
		Password string                 `json:"password"`
		Method   string                 `json:"method"`
	}

	if err := c.Bind(&body); err != nil {
		return h.Error(c, http.StatusBadRequest, "Invalid request body", err)
	}

	if body.Method == "" {
		body.Method = "password"
	}

	traitsJSON, _ := json.Marshal(body.Traits)
	ident, err := h.regManager.Submit(c.Request().Context(), body.Method, identity.JSON(traitsJSON), body.Password)
	if err != nil {
		return h.Error(c, http.StatusInternalServerError, "Internal server error", err)
	}

	return c.JSON(http.StatusOK, ident)
}

func (h *Handler[T]) HandleLogin(c echo.Context) error {
	var body struct {
		Identifier string `json:"identifier"`
		Password   string `json:"password"`
		Method     string `json:"method"`
	}

	if err := c.Bind(&body); err != nil {
		return h.Error(c, http.StatusBadRequest, "Invalid request body", err)
	}

	if body.Method == "" {
		body.Method = "password"
	}

	ident, err := h.logManager.Authenticate(c.Request().Context(), body.Method, body.Identifier, body.Password)
	if err != nil {
		return h.Error(c, http.StatusUnauthorized, "Unauthorized", err)
	}

	// Use generator if provided
	var sessionID T
	if h.generator != nil {
		sessionID = h.generator()
	}

	s, err := h.sessionManager.Create(sessionID, ident.ID)
	if err != nil {
		return h.Error(c, http.StatusInternalServerError, "Internal server error", err)
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"identity": ident,
		"session":  s,
		"token":    fmt.Sprintf("%v", s.ID),
	})
}

func (h *Handler[T]) AuthMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		token := c.Request().Header.Get("Authorization")
		if token == "" {
			return h.Error(c, http.StatusUnauthorized, "Authorization header required", nil)
		}

		s, err := h.sessionManager.Validate(token)
		if err != nil {
			return h.Error(c, http.StatusUnauthorized, "Unauthorized", err)
		}

		// Store session in context
		c.Set("session", s)
		return next(c)
	}
}

func (h *Handler[T]) HandleWhoAmI(c echo.Context) error {
	s := c.Get("session").(*identity.Session[T])
	return c.JSON(http.StatusOK, map[string]interface{}{
		"status":  "authenticated",
		"session": s,
	})
}

func (h *Handler[T]) HandleOIDCAuth(c echo.Context) error {
	provider := c.Param("provider")
	state := "random-state" // TODO: Use real state management

	url, err := h.oidcManager.GetAuthURL(provider, state)
	if err != nil {
		return h.Error(c, http.StatusBadRequest, "Invalid OIDC configuration", err)
	}

	return c.Redirect(http.StatusFound, url)
}

func (h *Handler[T]) HandleOIDCCallback(c echo.Context) error {
	provider := c.Param("provider")
	code := c.QueryParam("code")

	ident, err := h.oidcManager.HandleCallback(c.Request().Context(), provider, code)
	if err != nil {
		return h.Error(c, http.StatusUnauthorized, "OIDC verification failed", err)
	}

	// Create Session
	var sessionID T
	if h.generator != nil {
		sessionID = h.generator()
	}
	s, err := h.sessionManager.Create(sessionID, ident.ID)
	if err != nil {
		return h.Error(c, http.StatusInternalServerError, "Internal server error", err)
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"identity": ident,
		"session":  s,
		"token":    fmt.Sprintf("%v", s.ID),
	})
}

// Helper for professional errors
func (h *Handler[T]) Error(c echo.Context, code int, message string, err error) error {
	resp := map[string]interface{}{
		"status": message,
		"code":   code,
	}
	if err != nil {
		resp["error"] = err.Error()
	}
	return c.JSON(code, resp)
}
