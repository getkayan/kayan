package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"time"

	gormstore "github.com/getkayan/kayan/kayan-gorm"
	redisstore "github.com/getkayan/kayan/kayan-redis"
	"github.com/redis/go-redis/v9"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func main() {
	databaseURL := requiredEnv("DATABASE_URL")
	redisAddress := requiredEnv("REDIS_ADDR")

	db, err := gorm.Open(postgres.Open(databaseURL), &gorm.Config{})
	if err != nil {
		log.Fatalf("open database: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		log.Fatalf("database pool: %v", err)
	}
	sqlDB.SetMaxOpenConns(25)
	sqlDB.SetMaxIdleConns(10)
	sqlDB.SetConnMaxLifetime(30 * time.Minute)

	redisClient := redis.NewClient(&redis.Options{Addr: redisAddress})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := redisClient.Ping(ctx).Err(); err != nil {
		log.Fatalf("connect to Redis: %v", err)
	}

	repo := gormstore.NewRepository(db)
	app := newApplication(
		repo,
		redisstore.NewRedisLockoutStore(redisClient, "kayan:login:"),
		os.Getenv("ALLOW_REGISTRATION") == "true",
	)
	if err := app.bootstrap(ctx, os.Getenv("BOOTSTRAP_ADMIN_EMAIL"), os.Getenv("BOOTSTRAP_ADMIN_PASSWORD")); err != nil {
		log.Fatalf("bootstrap: %v", err)
	}

	server := &http.Server{
		Addr: ":8080", Handler: app.routes(),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
		WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second,
	}
	log.Printf("production IAM example listening on %s", server.Addr)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

func requiredEnv(name string) string {
	value := os.Getenv(name)
	if value == "" {
		log.Fatalf("%s is required", name)
	}
	return value
}
