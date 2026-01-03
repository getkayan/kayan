package main

import (
	"encoding/json"
	"fmt"
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

// Define a simple custom schema validator
type MyUserSchema struct{}

func (s *MyUserSchema) Validate(traits identity.JSON) error {
	var data map[string]any
	if err := json.Unmarshal(traits, &data); err != nil {
		return err
	}

	email, ok := data["email"].(string)
	if !ok || email == "" {
		return fmt.Errorf("email is required")
	}

	age, ok := data["age"].(float64) // JSON numbers are float64 in Go
	if ok && age < 18 {
		return fmt.Errorf("user must be at least 18 years old")
	}

	return nil
}

func main() {
	// 1. Setup Persistence
	db, _ := gorm.Open(sqlite.Open("advanced_iam.db"), &gorm.Config{})
	repo := persistence.NewRepository(db)
	_ = repo.AutoMigrate()

	// 2. Kayan Setup
	factory := func() any { return &identity.Identity{} }
	regManager := flow.NewRegistrationManager(repo, factory)

	// Apply Schema Validation (Point 6)
	regManager.SetSchema(&MyUserSchema{})

	logManager := flow.NewLoginManager(repo)

	// Password Strategy
	hasher := flow.NewBcryptHasher(10)
	pwStrategy := flow.NewPasswordStrategy(repo, hasher, "email", factory)
	pwStrategy.SetIDGenerator(func() any { return uuid.New().String() })
	regManager.RegisterStrategy(pwStrategy)
	logManager.RegisterStrategy(pwStrategy)

	// Session & RBAC
	sessStrategy := session.NewDatabaseStrategy(repo)
	sessManager := session.NewManager(sessStrategy)
	rbacStrategy := rbac.NewBasicStrategy(repo)
	rbacManager := rbac.NewManager(rbacStrategy)
	rbacMw := rbac.NewMiddleware(rbacManager, sessManager)

	// 3. API Setup
	h := api.NewHandler(regManager, logManager, sessManager, nil)
	h.SetIDGenerator(func() any { return uuid.New().String() })
	h.SetTokenParser(func(t string) (any, error) { return t, nil })

	// 4. Echo Router
	e := echo.New()
	e.HideBanner = true

	// Bridge for RBAC context
	contextBridge := func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if s, ok := c.Get("session").(*identity.Session); ok {
				c.Set("identity_id", s.IdentityID)
			}
			return next(c)
		}
	}

	g := e.Group("/api/v1")
	h.RegisterRoutes(g)

	// Route protected by specific permission (Point 3)
	// Requires "blog:create" permission
	e.POST("/api/v1/posts", func(c echo.Context) error {
		return c.JSON(http.StatusCreated, map[string]string{"message": "Post created!"})
	}, h.AuthMiddleware, contextBridge, rbacMw.RequirePermission("blog:create"))

	// Route protected by role
	e.GET("/api/v1/admin", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{"message": "Welcome Admin!"})
	}, h.AuthMiddleware, contextBridge, rbacMw.RequireRole("admin"))

	fmt.Println("Advanced IAM Example running on :8080")
	fmt.Println("- Registration now validates 'email' and 'age' >= 18")
	fmt.Println("- POST /api/v1/posts now requires 'blog:create' permission")

	// Example of how you would manually upgrade a user (for demo purposes)
	fmt.Println("\nTo test permissions, you can manually update the database:")
	fmt.Println("UPDATE identities SET permissions = '[\"blog:create\"]' WHERE id = 'YOUR_USER_ID';")

	// e.Start(":8080")
}
