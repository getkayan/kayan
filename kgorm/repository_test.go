package kgorm

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/getkayan/kayan/core/audit"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func TestRepository_AuditEventLifecycle(t *testing.T) {
	// Use a PostgreSQL database for testing (requires running local instance)
	dsn := os.Getenv("KAYAN_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("KAYAN_TEST_PG_DSN not set; skipping Postgres integration test")
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	repo := NewRepository(db)
	if err := repo.AutoMigrate(); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	// Save event
	event := &audit.AuditEvent{
		Type:    audit.EventLoginSuccess,
		ActorID: "actor-1",
		Status:  "success",
		Message: "ok",
		CreatedAt: time.Now().Add(-2 * time.Hour),
	}
	if err := repo.SaveEvent(context.Background(), event); err != nil {
		t.Fatalf("save event: %v", err)
	}
	// Query
	results, err := repo.Query(context.Background(), audit.Filter{ActorID: "actor-1"})
	if err != nil || len(results) != 1 {
		t.Fatalf("query: %v, results: %d", err, len(results))
	}
	// Count
	count, err := repo.Count(context.Background(), audit.Filter{ActorID: "actor-1"})
	if err != nil || count != 1 {
		t.Fatalf("count: %v, got %d", err, count)
	}
	// Purge
	purged, err := repo.Purge(context.Background(), time.Now())
	if err != nil || purged != 1 {
		t.Fatalf("purge: %v, got %d", err, purged)
	}
	// Query after purge
	results, err = repo.Query(context.Background(), audit.Filter{ActorID: "actor-1"})
	if err != nil {
		t.Fatalf("query after purge: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("expected 0 events after purge, got %d", len(results))
	}
}
