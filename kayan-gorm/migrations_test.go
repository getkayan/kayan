package gormstore

import (
	"io/fs"
	"strings"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func TestMigrationsAreBundledForEveryDialect(t *testing.T) {
	for _, dialect := range []string{DialectPostgres, DialectMySQL, DialectSQLite} {
		t.Run(dialect, func(t *testing.T) {
			names, err := MigrationNames(dialect)
			if err != nil {
				t.Fatalf("MigrationNames: %v", err)
			}
			if len(names) == 0 {
				t.Fatal("no migrations are bundled")
			}

			// Every up must have a matching down, or a deployment can move
			// forward and not back.
			ups := make(map[string]bool)
			downs := make(map[string]bool)
			for _, name := range names {
				switch {
				case strings.HasSuffix(name, ".up.sql"):
					ups[strings.TrimSuffix(name, ".up.sql")] = true
				case strings.HasSuffix(name, ".down.sql"):
					downs[strings.TrimSuffix(name, ".down.sql")] = true
				default:
					t.Errorf("%s is neither an up nor a down migration", name)
				}
			}
			for version := range ups {
				if !downs[version] {
					t.Errorf("%s has no down migration", version)
				}
			}
		})
	}
}

func TestDialectAliases(t *testing.T) {
	aliases := map[string]string{
		"postgres":   DialectPostgres,
		"postgresql": DialectPostgres,
		"pgx":        DialectPostgres,
		"POSTGRES":   DialectPostgres,
		"mysql":      DialectMySQL,
		"mariadb":    DialectMySQL,
		"sqlite":     DialectSQLite,
		"sqlite3":    DialectSQLite,
		" sqlite ":   DialectSQLite,
	}

	for input, want := range aliases {
		t.Run(input, func(t *testing.T) {
			if got := normalizeDialect(input); got != want {
				t.Errorf("normalizeDialect(%q) = %q, want %q", input, got, want)
			}
		})
	}

	if _, err := Migrations("oracle"); err == nil {
		t.Error("an unbundled dialect was accepted")
	}
}

// TestSQLiteMigrationsApply executes the bundled SQL rather than only reading
// it. A migration that parses but does not run is worse than none: the failure
// surfaces during a deployment, against a live database.
func TestSQLiteMigrationsApply(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}

	applyMigrations(t, db, ".up.sql")

	// Every table the repositories write to must now exist.
	expected := []string{
		"identities", "credentials", "sessions", "auth_tokens", "audit_events",
		"relation_tuples", "mfa_enrollments", "mfa_challenges",
		"mfa_recovery_codes", "devices", "role_assignments",
	}
	for _, table := range expected {
		if !db.Migrator().HasTable(table) {
			t.Errorf("table %q was not created", table)
		}
	}

	// Tenant isolation depends on the column existing everywhere it filters.
	for _, table := range expected {
		if !db.Migrator().HasColumn(table, "tenant_id") {
			t.Errorf("table %q has no tenant_id column; isolation cannot filter it", table)
		}
	}
}

// TestSQLiteMigrationsRollBack proves the down migrations run. Without them a
// failed deployment cannot be reversed.
func TestSQLiteMigrationsRollBack(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}

	applyMigrations(t, db, ".up.sql")
	if !db.Migrator().HasTable("identities") {
		t.Fatal("the up migration did not create identities")
	}

	applyMigrations(t, db, ".down.sql")
	if db.Migrator().HasTable("identities") {
		t.Error("the down migration left identities in place")
	}
}

// TestMigrationsMatchTheModels guards against the SQL and the Go models
// drifting apart. AutoMigrateDev builds the schema from the models; if the
// bundled SQL produces a different one, development and production disagree.
func TestMigrationsMatchTheModels(t *testing.T) {
	fromSQL, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	applyMigrations(t, fromSQL, ".up.sql")

	fromModels, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	repo := NewRepository(fromModels)
	if err := repo.AutoMigrateDev(); err != nil {
		t.Fatalf("AutoMigrateDev: %v", err)
	}
	if err := NewMFARepository(fromModels).AutoMigrate(); err != nil {
		t.Fatalf("MFA AutoMigrate: %v", err)
	}
	if err := NewDeviceRepository(fromModels).AutoMigrate(); err != nil {
		t.Fatalf("device AutoMigrate: %v", err)
	}

	// Compare the columns each path produced for the tables both create.
	for _, table := range []string{
		"identities", "credentials", "sessions", "auth_tokens",
		"mfa_enrollments", "mfa_challenges", "mfa_recovery_codes", "devices",
	} {
		t.Run(table, func(t *testing.T) {
			sqlColumns := columnSet(t, fromSQL, table)
			modelColumns := columnSet(t, fromModels, table)

			for column := range modelColumns {
				if !sqlColumns[column] {
					t.Errorf("the models define %s.%s but the migration does not create it",
						table, column)
				}
			}

			// The reverse direction matters just as much. A column the SQL
			// creates and the model omits is invisible to GORM: it is never
			// selected, never written, and never available as a predicate.
			// That is how tenant_id came to exist on every core table while
			// the models ignored it, leaving queries unscoped.
			for column := range sqlColumns {
				if !modelColumns[column] {
					t.Errorf("the migration creates %s.%s but no model maps it, so GORM will never read or write it",
						table, column)
				}
			}
		})
	}
}

// applyMigrations runs every bundled SQLite migration with the given suffix.
func applyMigrations(t *testing.T, db *gorm.DB, suffix string) {
	t.Helper()

	files, err := Migrations(DialectSQLite)
	if err != nil {
		t.Fatalf("Migrations: %v", err)
	}

	names, err := MigrationNames(DialectSQLite)
	if err != nil {
		t.Fatalf("MigrationNames: %v", err)
	}

	// Down migrations reverse the up order.
	if suffix == ".down.sql" {
		for i, j := 0, len(names)-1; i < j; i, j = i+1, j-1 {
			names[i], names[j] = names[j], names[i]
		}
	}

	applied := 0
	for _, name := range names {
		if !strings.HasSuffix(name, suffix) {
			continue
		}

		content, err := fs.ReadFile(files, name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}

		for _, statement := range splitStatements(string(content)) {
			if err := db.Exec(statement).Error; err != nil {
				t.Fatalf("%s: %v\nstatement: %s", name, err, statement)
			}
		}
		applied++
	}

	if applied == 0 {
		t.Fatalf("no %s migrations were applied", suffix)
	}
}

// splitStatements breaks a migration file into executable statements.
func splitStatements(content string) []string {
	var statements []string
	for _, part := range strings.Split(stripComments(content), ";") {
		statement := strings.TrimSpace(part)
		if statement != "" {
			statements = append(statements, statement)
		}
	}
	return statements
}

// stripComments removes SQL line comments before any splitting happens.
//
// Order matters: a semicolon inside prose — "rolled back during development;
// running it against a production database..." — would otherwise be taken for
// a statement terminator and cut a migration in half.
func stripComments(sql string) string {
	var kept []string
	for _, line := range strings.Split(sql, "\n") {
		if idx := strings.Index(line, "--"); idx >= 0 {
			line = line[:idx]
		}
		if strings.TrimSpace(line) == "" {
			continue
		}
		kept = append(kept, line)
	}
	return strings.Join(kept, "\n")
}

// columnSet returns the columns of a table.
func columnSet(t *testing.T, db *gorm.DB, table string) map[string]bool {
	t.Helper()

	types, err := db.Migrator().ColumnTypes(table)
	if err != nil {
		t.Fatalf("column types for %s: %v", table, err)
	}

	columns := make(map[string]bool, len(types))
	for _, column := range types {
		columns[column.Name()] = true
	}
	return columns
}
