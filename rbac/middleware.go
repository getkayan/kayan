package rbac

import (
	"net/http"

	"github.com/getkayan/kayan/session"
	"github.com/labstack/echo/v4"
)

// Middleware provides role-based access control for Echo.
type Middleware struct {
	rbac    *Manager
	session *session.Manager
}

func NewMiddleware(rbac *Manager, session *session.Manager) *Middleware {
	return &Middleware{
		rbac:    rbac,
		session: session,
	}
}

// RequireRole returns an Echo middleware that requires the user to have the specified role.
// It assumes the session ID is in a cookie or header (standard Kayan session flow).
func (m *Middleware) RequireRole(role string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// 1. Get Session (This logic might vary based on how the dev sets up session middleware)
			// For this example, we assume the session is already validated or we validate it here.
			// Ideally, Kayan should have a standard way to retrieve the identity from context.

			// This is a placeholder. In a real app, the session middleware would have already
			// put the IdentityID in the context.
			identityID := c.Get("identity_id")
			if identityID == nil {
				return echo.NewHTTPError(http.StatusUnauthorized, "unauthorized")
			}

			// 2. Check Role
			allowed, err := m.rbac.Authorize(identityID, role)
			if err != nil {
				return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
			}

			if !allowed {
				return echo.NewHTTPError(http.StatusForbidden, "forbidden: missing required role")
			}

			return next(c)
		}
	}
}

// RequirePermission returns an Echo middleware that requires the user to have the specified permission.
func (m *Middleware) RequirePermission(permission string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			identityID := c.Get("identity_id")
			if identityID == nil {
				return echo.NewHTTPError(http.StatusUnauthorized, "unauthorized")
			}

			allowed, err := m.rbac.AuthorizePermission(identityID, permission)
			if err != nil {
				return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
			}

			if !allowed {
				return echo.NewHTTPError(http.StatusForbidden, "forbidden: missing required permission")
			}

			return next(c)
		}
	}
}
