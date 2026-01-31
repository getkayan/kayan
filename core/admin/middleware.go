package admin

import (
	"context"
	"net/http"
	"strings"
)

// AdminContextKey is the context key for admin authentication.
type AdminContextKey struct{}

// AdminIdentity represents the authenticated admin user.
type AdminIdentity struct {
	ID           string   `json:"id"`
	Email        string   `json:"email"`
	Roles        []string `json:"roles"`
	Permissions  []string `json:"permissions"`
	TenantID     string   `json:"tenant_id,omitempty"`
	IsSuperAdmin bool     `json:"is_super_admin"`
}

// Authenticator defines the interface for admin authentication.
type Authenticator interface {
	// Authenticate validates the request and returns the admin identity.
	Authenticate(r *http.Request) (*AdminIdentity, error)
}

// Authorizer defines the interface for admin authorization.
type Authorizer interface {
	// Authorize checks if the admin has the required permission.
	Authorize(ctx context.Context, admin *AdminIdentity, permission string) bool
}

// ---- Middleware ----

// AuthMiddleware creates authentication middleware.
func AuthMiddleware(auth Authenticator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			admin, err := auth.Authenticate(r)
			if err != nil {
				writeError(w, http.StatusUnauthorized, "authentication required")
				return
			}

			ctx := context.WithValue(r.Context(), AdminContextKey{}, admin)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequirePermission creates middleware that requires a specific permission.
func RequirePermission(authz Authorizer, permission string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			admin := GetAdminFromContext(r.Context())
			if admin == nil {
				writeError(w, http.StatusUnauthorized, "authentication required")
				return
			}

			if !authz.Authorize(r.Context(), admin, permission) {
				writeError(w, http.StatusForbidden, "insufficient permissions")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireAnyPermission creates middleware that requires any of the specified permissions.
func RequireAnyPermission(authz Authorizer, permissions ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			admin := GetAdminFromContext(r.Context())
			if admin == nil {
				writeError(w, http.StatusUnauthorized, "authentication required")
				return
			}

			for _, perm := range permissions {
				if authz.Authorize(r.Context(), admin, perm) {
					next.ServeHTTP(w, r)
					return
				}
			}

			writeError(w, http.StatusForbidden, "insufficient permissions")
		})
	}
}

// RequireSuperAdmin creates middleware that requires super admin access.
func RequireSuperAdmin() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			admin := GetAdminFromContext(r.Context())
			if admin == nil {
				writeError(w, http.StatusUnauthorized, "authentication required")
				return
			}

			if !admin.IsSuperAdmin {
				writeError(w, http.StatusForbidden, "super admin access required")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// GetAdminFromContext retrieves the admin identity from context.
func GetAdminFromContext(ctx context.Context) *AdminIdentity {
	if admin, ok := ctx.Value(AdminContextKey{}).(*AdminIdentity); ok {
		return admin
	}
	return nil
}

// ---- Default Implementations ----

// BearerTokenAuthenticator authenticates using Bearer tokens.
type BearerTokenAuthenticator struct {
	ValidateToken func(token string) (*AdminIdentity, error)
}

func (a *BearerTokenAuthenticator) Authenticate(r *http.Request) (*AdminIdentity, error) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return nil, ErrNoToken
	}

	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return nil, ErrInvalidToken
	}

	return a.ValidateToken(parts[1])
}

// RoleBasedAuthorizer authorizes based on roles and permissions.
type RoleBasedAuthorizer struct {
	// RolePermissions maps role names to their permissions.
	RolePermissions map[string][]string
}

func (a *RoleBasedAuthorizer) Authorize(ctx context.Context, admin *AdminIdentity, permission string) bool {
	if admin.IsSuperAdmin {
		return true
	}

	// Check direct permissions
	for _, p := range admin.Permissions {
		if matchPermission(p, permission) {
			return true
		}
	}

	// Check role-based permissions
	for _, role := range admin.Roles {
		if perms, ok := a.RolePermissions[role]; ok {
			for _, p := range perms {
				if matchPermission(p, permission) {
					return true
				}
			}
		}
	}

	return false
}

// matchPermission checks if a permission matches (supports wildcards).
func matchPermission(granted, required string) bool {
	if granted == "*" || granted == required {
		return true
	}

	// Support resource:* patterns
	if strings.HasSuffix(granted, ":*") {
		prefix := strings.TrimSuffix(granted, "*")
		if strings.HasPrefix(required, prefix) {
			return true
		}
	}

	return false
}

// ---- Errors ----

type AdminError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *AdminError) Error() string { return e.Message }

// ---- HTTP Helpers ----

func writeError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write([]byte(`{"error":"` + http.StatusText(status) + `","message":"` + message + `"}`))
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	// Simple encoding - for production use encoding/json
}
