//go:build integration

package gormstore

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/getkayan/kayan/core/domain"
	"github.com/getkayan/kayan/core/session"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func TestVersionedMigrationChain(t *testing.T) {
	dialect := os.Getenv("KAYAN_TEST_DIALECT")
	dsn := os.Getenv("DATABASE_URL")
	if dialect == "" || dsn == "" {
		t.Skip("KAYAN_TEST_DIALECT and DATABASE_URL are required")
	}

	var dialector gorm.Dialector
	switch dialect {
	case DialectPostgres:
		dialector = postgres.Open(dsn)
	case DialectMySQL:
		dialector = mysql.Open(dsn)
	default:
		t.Fatalf("unsupported integration dialect %q", dialect)
	}
	db, err := gorm.Open(dialector, &gorm.Config{})
	if err != nil {
		t.Fatalf("open database: %v", err)
	}

	migrations, err := Migrations(dialect)
	if err != nil {
		t.Fatalf("Migrations: %v", err)
	}
	entries, err := fs.ReadDir(migrations, ".")
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	var up, down []string
	for _, entry := range entries {
		switch {
		case strings.HasSuffix(entry.Name(), ".up.sql"):
			up = append(up, entry.Name())
		case strings.HasSuffix(entry.Name(), ".down.sql"):
			down = append(down, entry.Name())
		}
	}
	sort.Strings(up)
	sort.Sort(sort.Reverse(sort.StringSlice(down)))
	if len(up) == 0 || len(up) != len(down) {
		t.Fatalf("migration pairs: %d up, %d down", len(up), len(down))
	}

	applySQLFiles(t, db, migrations, up)
	for _, table := range []string{"identities", "sessions", "sso_sessions", "sso_app_sessions"} {
		if !db.Migrator().HasTable(table) {
			t.Errorf("table %s missing after migration up", table)
		}
	}
	proveRealDatabaseAtomicity(t, NewRepository(db))
	applySQLFiles(t, db, migrations, down)
	for _, table := range []string{"identities", "sessions", "sso_sessions", "sso_app_sessions"} {
		if db.Migrator().HasTable(table) {
			t.Errorf("table %s remains after migration down", table)
		}
	}
}

func proveRealDatabaseAtomicity(t *testing.T, repo *Repository) {
	t.Helper()
	ctx := context.Background()
	if err := repo.SaveToken(ctx, &domain.AuthToken{
		Token: "integration-single-use", IdentityID: "u1", Type: "otp", ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("SaveToken: %v", err)
	}
	var tokenWinners atomic.Int32
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := repo.ConsumeToken(ctx, "integration-single-use", "otp"); err == nil {
				tokenWinners.Add(1)
			}
		}()
	}
	wg.Wait()
	if got := tokenWinners.Load(); got != 1 {
		t.Fatalf("successful concurrent token consumes = %d, want 1", got)
	}

	mgr := session.NewSSOManager(repo)
	created, err := mgr.CreateSession(ctx, "integration-user", "app-0")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	for i := 1; i <= 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, err := mgr.JoinSession(ctx, created.ID, fmt.Sprintf("app-%d", i)); err != nil {
				t.Errorf("JoinSession: %v", err)
			}
		}(i)
	}
	wg.Wait()
	got, err := mgr.GetSession(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if len(got.AppSessions) != 17 {
		t.Fatalf("SSO app sessions = %d, want 17", len(got.AppSessions))
	}
}

func applySQLFiles(t *testing.T, db *gorm.DB, migrations fs.FS, names []string) {
	t.Helper()
	for _, name := range names {
		data, err := fs.ReadFile(migrations, name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if err := db.Exec(string(data)).Error; err != nil {
			t.Fatalf("apply %s: %v", name, err)
		}
	}
}
