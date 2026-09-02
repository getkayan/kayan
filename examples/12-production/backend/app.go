package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/getkayan/kayan/core/admin"
	"github.com/getkayan/kayan/core/domain"
	"github.com/getkayan/kayan/core/flow"
	"github.com/getkayan/kayan/core/identity"
	"github.com/getkayan/kayan/core/rbac"
	"github.com/getkayan/kayan/core/session"
	gormstore "github.com/getkayan/kayan/kayan-gorm"
	"github.com/google/uuid"
)

const maxRequestBody = 1 << 20

type application struct {
	repo              *gormstore.Repository
	stores            *gormstore.AdminStores
	registration      *flow.RegistrationManager
	login             *flow.LoginManager
	sessions          *session.DatabaseStrategy
	authorization     *rbac.StorageStrategy
	administration    *admin.Manager
	allowRegistration bool
}

func newApplication(repo *gormstore.Repository, lockout flow.LockoutStore, allowRegistration bool) *application {
	stores := gormstore.NewAdminStores(repo.DB())
	factory := func() any { return &identity.Identity{State: string(admin.UserStateActive)} }
	registration, login := flow.PasswordAuth(
		repo, factory, "email",
		flow.WithHasherCost(12),
		flow.WithPasswordPolicy(&flow.PasswordPolicy{
			MinLength: 12, RequireUppercase: true, RequireLowercase: true, RequireDigit: true,
		}),
		flow.WithLockoutStore(lockout),
		flow.WithQuickAudit(repo, func(_ context.Context, err error) {
			log.Printf("audit persistence failed: %v", err)
		}),
	)
	rbacRepo := gormstore.NewRBACRepository(repo.DB())
	return &application{
		repo: repo, stores: stores, registration: registration, login: login,
		sessions:      session.NewDatabaseStrategy(repo),
		authorization: rbac.NewStorageStrategy(rbacRepo, rbacRepo),
		administration: admin.NewManager(
			admin.WithUserStore(stores.Users), admin.WithSessionStore(stores.Sessions),
			admin.WithRoleStore(stores.Roles), admin.WithAuditStore(stores.Audit),
			admin.WithIDGenerator(func() any { return uuid.NewString() }),
		),
		allowRegistration: allowRegistration,
	}
}

func (a *application) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	mux.HandleFunc("POST /api/register", a.handleRegister)
	mux.HandleFunc("POST /api/login", a.handleLogin)
	mux.HandleFunc("POST /api/refresh", a.handleRefresh)
	mux.HandleFunc("DELETE /api/logout", a.handleLogout)
	mux.HandleFunc("GET /api/me", a.handleMe)
	mux.HandleFunc("GET /api/documents", a.requirePermission("documents:read", a.handleDocuments))
	mux.HandleFunc("GET /api/admin/users", a.handleListUsers)
	mux.HandleFunc("POST /api/admin/users", a.handleCreateUser)
	mux.HandleFunc("POST /api/admin/roles", a.handleCreateRole)
	mux.HandleFunc("PUT /api/admin/users/{userID}/roles/{roleID}", a.handleAssignRole)
	mux.HandleFunc("POST /api/admin/users/{userID}/lock", a.handleLockUser)
	return securityHeaders(mux)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("request contains more than one JSON value")
		}
		return err
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func bearerToken(r *http.Request) string {
	scheme, token, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || token == "" {
		return ""
	}
	return token
}

func (a *application) sessionIdentity(r *http.Request) (*identity.Session, error) {
	token := bearerToken(r)
	if token == "" {
		return nil, errors.New("missing bearer token")
	}
	return a.sessions.Validate(r.Context(), token)
}

func (a *application) adminCaller(r *http.Request) (*admin.Caller, error) {
	sess, err := a.sessionIdentity(r)
	if err != nil {
		return nil, err
	}
	return a.administration.ResolveCaller(r.Context(), sess.IdentityID)
}

func (a *application) handleRegister(w http.ResponseWriter, r *http.Request) {
	if !a.allowRegistration {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	var input struct{ Email, Password string }
	if decodeJSON(w, r, &input) != nil || input.Email == "" || input.Password == "" {
		writeError(w, http.StatusBadRequest, "email and password are required")
		return
	}
	traits, _ := json.Marshal(map[string]string{"email": strings.ToLower(strings.TrimSpace(input.Email))})
	created, err := a.registration.Submit(r.Context(), "password", identity.JSON(traits), input.Password)
	if err != nil {
		writeError(w, http.StatusBadRequest, "registration failed")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": created.(identity.FlowIdentity).GetID()})
}

func (a *application) handleLogin(w http.ResponseWriter, r *http.Request) {
	var input struct{ Email, Password string }
	if decodeJSON(w, r, &input) != nil || input.Email == "" || input.Password == "" {
		writeError(w, http.StatusBadRequest, "email and password are required")
		return
	}
	user, err := a.login.Authenticate(r.Context(), "password", strings.ToLower(strings.TrimSpace(input.Email)), input.Password)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	sess, err := a.sessions.Create(r.Context(), uuid.NewString(), user.(identity.FlowIdentity).GetID())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "session creation failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": sess.ID, "refresh_token": sess.RefreshToken,
		"expires_at": sess.ExpiresAt, "refresh_expires_at": sess.RefreshExpiresAt,
	})
}

func (a *application) handleRefresh(w http.ResponseWriter, r *http.Request) {
	var input struct {
		RefreshToken string `json:"refresh_token"`
	}
	if decodeJSON(w, r, &input) != nil || input.RefreshToken == "" {
		writeError(w, http.StatusBadRequest, "refresh_token is required")
		return
	}
	sess, err := a.sessions.Refresh(r.Context(), input.RefreshToken)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid refresh token")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": sess.ID, "refresh_token": sess.RefreshToken,
		"expires_at": sess.ExpiresAt, "refresh_expires_at": sess.RefreshExpiresAt,
	})
}

func (a *application) handleLogout(w http.ResponseWriter, r *http.Request) {
	token := bearerToken(r)
	if token == "" || a.sessions.Delete(r.Context(), token) != nil {
		writeError(w, http.StatusUnauthorized, "invalid session")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *application) handleMe(w http.ResponseWriter, r *http.Request) {
	sess, err := a.sessionIdentity(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid session")
		return
	}
	user, err := a.stores.Users.Get(r.Context(), sess.IdentityID)
	if err != nil || user.State != admin.UserStateActive {
		writeError(w, http.StatusUnauthorized, "invalid session")
		return
	}
	roles, err := a.stores.Roles.GetUserRoles(r.Context(), user.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not resolve roles")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"user": user, "roles": roles})
}

func (a *application) requirePermission(permission string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, err := a.sessionIdentity(r)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid session")
			return
		}
		allowed, err := a.authorization.HasPermission(r.Context(), sess.IdentityID, permission)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "authorization failed")
			return
		}
		if !allowed {
			writeError(w, http.StatusForbidden, "forbidden")
			return
		}
		next(w, r)
	}
}

func (a *application) handleDocuments(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"documents": []string{"enterprise-plan"}})
}

func (a *application) handleListUsers(w http.ResponseWriter, r *http.Request) {
	caller, err := a.adminCaller(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid session")
		return
	}
	result, err := a.administration.ListUsers(r.Context(), caller, admin.ListOptions{})
	if errors.Is(err, admin.ErrForbidden) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list users")
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (a *application) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	caller, err := a.adminCaller(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid session")
		return
	}
	var input admin.CreateUserInput
	if decodeJSON(w, r, &input) != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	user, err := a.administration.CreateUser(r.Context(), caller, input)
	if errors.Is(err, admin.ErrForbidden) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, "could not create user")
		return
	}
	writeJSON(w, http.StatusCreated, user)
}

func (a *application) handleCreateRole(w http.ResponseWriter, r *http.Request) {
	caller, err := a.adminCaller(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid session")
		return
	}
	var input admin.CreateRoleInput
	if decodeJSON(w, r, &input) != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	role, err := a.administration.CreateRole(r.Context(), caller, input)
	if errors.Is(err, admin.ErrForbidden) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, "could not create role")
		return
	}
	writeJSON(w, http.StatusCreated, role)
}

func (a *application) handleAssignRole(w http.ResponseWriter, r *http.Request) {
	caller, err := a.adminCaller(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid session")
		return
	}
	if err := a.administration.AssignRoleToUser(r.Context(), caller, r.PathValue("userID"), r.PathValue("roleID")); err != nil {
		if errors.Is(err, admin.ErrForbidden) {
			writeError(w, http.StatusForbidden, "forbidden")
		} else {
			writeError(w, http.StatusBadRequest, "could not assign role")
		}
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *application) handleLockUser(w http.ResponseWriter, r *http.Request) {
	caller, err := a.adminCaller(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid session")
		return
	}
	if err := a.administration.LockUser(r.Context(), caller, r.PathValue("userID"), "administrative lock"); err != nil {
		if errors.Is(err, admin.ErrForbidden) {
			writeError(w, http.StatusForbidden, "forbidden")
		} else {
			writeError(w, http.StatusBadRequest, "could not lock user")
		}
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *application) bootstrap(ctx context.Context, email, password string) error {
	if email == "" && password == "" {
		return nil
	}
	if email == "" || password == "" {
		return errors.New("both BOOTSTRAP_ADMIN_EMAIL and BOOTSTRAP_ADMIN_PASSWORD are required")
	}
	if _, err := a.stores.Users.GetByEmail(ctx, email); err == nil {
		return nil
	} else if !errors.Is(err, admin.ErrNotFound) && !errors.Is(err, domain.ErrNotFound) {
		return fmt.Errorf("look up bootstrap administrator: %w", err)
	}
	if _, err := a.stores.Roles.Get(ctx, "administrator"); err != nil {
		if err := a.stores.Roles.Create(ctx, &admin.Role{Name: "administrator", Permissions: []string{"*"}}); err != nil {
			return fmt.Errorf("create bootstrap role: %w", err)
		}
	}
	_, err := a.administration.CreateUser(ctx, &admin.Caller{IsSuperAdmin: true}, admin.CreateUserInput{
		Email: strings.ToLower(strings.TrimSpace(email)), Password: password, Roles: []string{"administrator"},
	})
	if err != nil {
		return fmt.Errorf("create bootstrap administrator: %w", err)
	}
	return nil
}
