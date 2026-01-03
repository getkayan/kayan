package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/getkayan/kayan/api"
	"github.com/getkayan/kayan/flow"
	"github.com/getkayan/kayan/identity"
	"github.com/getkayan/kayan/persistence"
	"github.com/getkayan/kayan/rbac"
	"github.com/getkayan/kayan/session"
	"github.com/glebarez/sqlite"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"gorm.io/gorm"
)

func main() {
	// 1. Setup Persistence (SQLite via GORM)
	db, err := gorm.Open(sqlite.Open("combined_example.db"), &gorm.Config{})
	if err != nil {
		log.Fatalf("failed to connect to database: %v", err)
	}

	repo := persistence.NewRepository(db)
	// AutoMigrate will create tables for Identity, Credential, and Session automatically
	if err := repo.AutoMigrate(); err != nil {
		log.Fatalf("failed to migrate database: %v", err)
	}

	// 2. Kayan Core Setup
	factory := func() any { return &identity.Identity{} }
	regManager := flow.NewRegistrationManager(repo, factory)
	logManager := flow.NewLoginManager(repo)

	// Password Strategy
	hasher := flow.NewBcryptHasher(10)
	pwStrategy := flow.NewPasswordStrategy(repo, hasher, "email", factory)
	pwStrategy.SetIDGenerator(func() any { return uuid.New().String() })

	regManager.RegisterStrategy(pwStrategy)
	logManager.RegisterStrategy(pwStrategy)

	// Session Management (Database Strategy)
	sessStrategy := session.NewDatabaseStrategy(repo)
	sessManager := session.NewManager(sessStrategy)

	// RBAC Management (Basic Strategy fetches roles from Identity.Roles field)
	rbacStrategy := rbac.NewBasicStrategy(repo)
	rbacManager := rbac.NewManager(rbacStrategy)

	// 3. API and Middleware Setup
	h := api.NewHandler(regManager, logManager, sessManager, nil)
	h.SetIDGenerator(func() any { return uuid.New().String() })
	// Tell the handler how to parse the token from the Authorization header
	h.SetTokenParser(func(token string) (any, error) {
		return token, nil // For database sessions, the token is the ID itself
	})

	rbacMw := rbac.NewMiddleware(rbacManager, sessManager)

	// 4. Echo Router
	e := echo.New()
	e.HideBanner = true

	// Public Routes
	g := e.Group("/api/v1")
	h.RegisterRoutes(g) // Registers /registration, /login, /whoami (with AuthMiddleware)

	// Custom Protected Routes using built-in AuthMiddleware from Handler
	protected := g.Group("/protected", h.AuthMiddleware)
	protected.GET("/dashboard", func(c echo.Context) error {
		s := c.Get("session").(*identity.Session)
		return c.JSON(http.StatusOK, map[string]any{
			"message": "Welcome to your dashboard!",
			"user_id": s.IdentityID,
		})
	})

	// RBAC Protected Routes
	// Note: We need to ensure "identity_id" is in context for rbac middleware.
	// We can use a small middleware to bridge Kayan's session to RBAC's expected context.
	contextBridge := func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			s, ok := c.Get("session").(*identity.Session)
			if ok {
				c.Set("identity_id", s.IdentityID)
			}
			return next(c)
		}
	}

	adminOnly := g.Group("/admin", h.AuthMiddleware, contextBridge, rbacMw.RequireRole("admin"))
	adminOnly.GET("/stats", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]any{
			"total_users": 100,
			"status":      "all systems nominal",
		})
	})

	fmt.Println("Big Combined Example is running!")
	fmt.Println("1. Register: POST /api/v1/registration")
	fmt.Println("2. Login:    POST /api/v1/login")
	fmt.Println("3. Admin:    GET  /api/v1/admin/stats (Requires 'admin' role)")
	fmt.Println("\nServer starting on :8080...")

	// Start server (commented out for build-check only, but ready to run)
	// if err := e.Start(":8080"); err != nil {
	// 	log.Fatal(err)
	// }
}
