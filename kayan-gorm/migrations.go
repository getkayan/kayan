package gormstore

import (
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strings"
)

//go:embed migrations
var migrationFiles embed.FS

// Dialects with bundled migrations.
const (
	DialectPostgres = "postgres"
	DialectMySQL    = "mysql"
	DialectSQLite   = "sqlite"
)

// Migrations returns the SQL migrations for a dialect.
//
// They are returned as a filesystem rather than applied, so the migration
// runner stays your choice. golang-migrate, Atlas, goose, dbmate, and a shell
// script all read a directory of numbered .sql files:
//
//	files, err := gormstore.Migrations(gormstore.DialectPostgres)
//	if err != nil { /* ... */ }
//
//	source, err := iofs.New(files, ".")
//	m, err := migrate.NewWithSourceInstance("iofs", source, databaseURL)
//	err = m.Up()
//
// Naming follows the convention every one of those tools expects:
// NNNN_description.up.sql and NNNN_description.down.sql.
//
// Prefer these over [Repository.AutoMigrateDev] for anything holding real
// accounts. AutoMigrate cannot drop a column, cannot transform existing rows,
// keeps no record of what ran, and has no way back — so a schema change that
// turns out to be wrong cannot be reversed.
func Migrations(dialect string) (fs.FS, error) {
	dialect = normalizeDialect(dialect)
	if dialect == "" {
		return nil, fmt.Errorf("gormstore: no bundled migrations for that dialect")
	}

	sub, err := fs.Sub(migrationFiles, "migrations/"+dialect)
	if err != nil {
		return nil, fmt.Errorf("gormstore: read %s migrations: %w", dialect, err)
	}
	return sub, nil
}

// MigrationNames lists the migration files for a dialect, in the order they
// must be applied.
//
// Use it to log what a deployment is about to run, or to check the bundled set
// against what a database has already recorded.
func MigrationNames(dialect string) ([]string, error) {
	files, err := Migrations(dialect)
	if err != nil {
		return nil, err
	}

	entries, err := fs.ReadDir(files, ".")
	if err != nil {
		return nil, fmt.Errorf("gormstore: list migrations: %w", err)
	}

	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".sql") {
			names = append(names, entry.Name())
		}
	}
	// Numeric prefixes make lexical order the same as application order.
	sort.Strings(names)
	return names, nil
}

// normalizeDialect maps the names GORM drivers use to a bundled directory.
func normalizeDialect(dialect string) string {
	switch strings.ToLower(strings.TrimSpace(dialect)) {
	case "postgres", "postgresql", "pgx":
		return DialectPostgres
	case "mysql", "mariadb":
		return DialectMySQL
	case "sqlite", "sqlite3":
		return DialectSQLite
	default:
		return ""
	}
}
