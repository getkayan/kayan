package api

import (
	"encoding/json"
	"net/http"

	"github.com/getkayan/kayan/internal/flow"
	"github.com/getkayan/kayan/internal/identity"
	"github.com/getkayan/kayan/internal/session"
	"github.com/labstack/echo/v4"
)

type Handler struct {
	regManager     *flow.RegistrationManager
	logManager     *flow.LoginManager
	sessionManager *session.Manager
	oidcManager    *flow.OIDCManager
}

func NewHandler(reg *flow.RegistrationManager, log *flow.LoginManager, sm *session.Manager, om *flow.OIDCManager) *Handler {
	return &Handler{regManager: reg, logManager: log, sessionManager: sm, oidcManager: om}
}

func (h *Handler) RegisterRoutes(g *echo.Group) {
	g.POST("/registration", h.HandleRegistration)
	g.POST("/login", h.HandleLogin)

	// OIDC routes
	g.GET("/auth/oidc/:provider", h.HandleOIDCAuth)
	g.GET("/auth/oidc/:provider/callback", h.HandleOIDCCallback)
	println("XD")

	// Protected routes
	protected := g.Group("")
	protected.Use(h.AuthMiddleware)
	protected.GET("/whoami", h.HandleWhoAmI)
}

func (h *Handler) HandleRegistration(c echo.Context) error {
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

func (h *Handler) HandleLogin(c echo.Context) error {
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

	// Create Session
	s, err := h.sessionManager.Create(ident.ID)
	if err != nil {
		return h.Error(c, http.StatusInternalServerError, "Internal server error", err)
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"identity": ident,
		"session":  s,
		"token":    s.ID.String(),
	})
}

func (h *Handler) AuthMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
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

func (h *Handler) HandleWhoAmI(c echo.Context) error {
	s := c.Get("session").(*identity.Session)
	return c.JSON(http.StatusOK, map[string]interface{}{
		"status":  "authenticated",
		"session": s,
	})
}

func (h *Handler) HandleOIDCAuth(c echo.Context) error {
	provider := c.Param("provider")
	state := "random-state" // TODO: Use real state management

	url, err := h.oidcManager.GetAuthURL(provider, state)
	if err != nil {
		return h.Error(c, http.StatusBadRequest, "Invalid OIDC configuration", err)
	}

	return c.Redirect(http.StatusFound, url)
}

func (h *Handler) HandleOIDCCallback(c echo.Context) error {
	provider := c.Param("provider")
	code := c.QueryParam("code")

	ident, err := h.oidcManager.HandleCallback(c.Request().Context(), provider, code)
	if err != nil {
		return h.Error(c, http.StatusUnauthorized, "OIDC verification failed", err)
	}

	// Create Session
	s, err := h.sessionManager.Create(ident.ID)
	if err != nil {
		return h.Error(c, http.StatusInternalServerError, "Internal server error", err)
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"identity": ident,
		"session":  s,
		"token":    s.ID.String(),
	})
}

// Helper for professional errors
func (h *Handler) Error(c echo.Context, code int, message string, err error) error {
	resp := map[string]interface{}{
		"status": message,
		"code":   code,
	}
	if err != nil {
		resp["error"] = err.Error()
	}
	return c.JSON(code, resp)
}
