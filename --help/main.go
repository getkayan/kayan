package main

import (
	"log"

	"github.com/getkayan/kayan-echo"
	"github.com/getkayan/kayan/core/flow"
	"github.com/getkayan/kayan/core/session"
	"github.com/getkayan/kayan/kgorm"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func main() {
	// Database
	db, err := gorm.Open(sqlite.Open("app.db"), &gorm.Config{})
	if err != nil {
		log.Fatal("Failed to connect database:", err)
	}

	// Auto-migrate schemas
	if err := kgorm.AutoMigrate(db); err != nil {
		log.Fatal("Migration failed:", err)
	}

	// Repositories
	identityRepo := kgorm.NewIdentityRepository(db, func() any { return &kgorm.DefaultIdentity{} })
	sessionRepo := kgorm.NewSessionRepository(db)

	// Managers
	regManager := flow.NewRegistrationManager(identityRepo, func() any { return &kgorm.DefaultIdentity{} })
	loginManager := flow.NewLoginManager(identityRepo, func() any { return &kgorm.DefaultIdentity{} })
	sessManager := session.NewManager(session.NewDatabaseStrategy(sessionRepo))

	// Password strategy
	hasher := flow.NewBcryptHasher(12)
	pwStrategy := flow.NewPasswordStrategy(identityRepo, hasher, "email", func() any { return &kgorm.DefaultIdentity{} })
	regManager.AddStrategy("password", pwStrategy)
	loginManager.AddStrategy("password", pwStrategy)

	// Echo setup
	e := echo.New()
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.CORS())

	// Kayan handler
	h := kayanecho.NewHandler(regManager, loginManager, sessManager, nil)
	h.SetIDGenerator(func() any { return uuid.New().String() })
	h.SetTokenParser(func(t string) (any, error) { return t, nil })

	// Routes
	api := e.Group("/api/v1")
	h.RegisterRoutes(api)

	// Protected routes example
	api.GET("/me", func(c echo.Context) error {
		return c.JSON(200, map[string]string{"message": "Hello from protected route!"})
	}, h.AuthMiddleware)

	log.Println("Starting server on :8080")
	e.Logger.Fatal(e.Start(":8080"))
}
