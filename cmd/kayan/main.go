package main

import (
	"fmt"
	"log"

	"github.com/getkayan/kayan/api"
	"github.com/getkayan/kayan/config"
	"github.com/getkayan/kayan/flow"
	"github.com/getkayan/kayan/logger"
	"github.com/getkayan/kayan/persistence"
	"github.com/getkayan/kayan/session"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"go.uber.org/zap"
)

func main() {
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("failed to load configuration: %v", err)
	}

	logger.InitLogger(cfg.LogLevel)
	defer logger.Log.Sync()

	logger.Log.Info("Starting Kayan Authentication Service",
		zap.Int("port", cfg.Port),
		zap.String("dsn", cfg.DSN),
	)

	// Initialize Repository
	repo, err := persistence.NewStorage[uuid.UUID](cfg.DBType, cfg.DSN, nil)
	if err != nil {
		logger.Log.Fatal("failed to initialize repository", zap.Error(err))
	}

	// Initialize Managers
	regManager := flow.NewRegistrationManager[uuid.UUID](repo)
	logManager := flow.NewLoginManager[uuid.UUID](repo)
	sessionManager := session.NewManager[uuid.UUID](repo)
	oidcManager, err := flow.NewOIDCManager[uuid.UUID](repo, cfg.OIDCProviders)
	if err != nil {
		logger.Log.Error("failed to initialize OIDC manager", zap.Error(err))
	}

	// Register Strategies
	hasher := flow.NewBcryptHasher(14)
	pwStrategy := flow.NewPasswordStrategy[uuid.UUID](repo, hasher, "email")

	// Set ID generator for UUIDs
	pwStrategy.SetIDGenerator(uuid.New)

	regManager.RegisterStrategy(pwStrategy)
	logManager.RegisterStrategy(pwStrategy)

	// Initialize Handler
	h := api.NewHandler[uuid.UUID](regManager, logManager, sessionManager, oidcManager)
	h.SetIDGenerator(uuid.New)

	// Setup Echo
	e := echo.New()
	e.HideBanner = true

	// Middleware
	e.Use(middleware.RequestLogger())
	e.Use(middleware.Recover())
	e.Use(middleware.CORS())

	// Routes
	g := e.Group("/api/v1")
	h.RegisterRoutes(g)

	logger.Log.Info("Server is starting", zap.Int("port", cfg.Port))
	if err := e.Start(fmt.Sprintf(":%d", cfg.Port)); err != nil {
		logger.Log.Fatal("server failed to start", zap.Error(err))
	}
}
