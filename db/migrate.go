package db

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// RunMigrations performs full UP (all pending). Used by agent startup.
func RunMigrations(db *sql.DB, dir string) error {
	return MigrateUp(db, dir, 0)
}

// MigrateUp applies up to 'steps' pending migrations. steps=0 means all pending.
// Recognizes both "*.up.sql" and legacy "*.sql" files. Ignores "*.down.sql".
func MigrateUp(db *sql.DB, dir string, steps int) error {
	if err := ensureMigrationsTable(db); err != nil { return err }
	ups, err := listUpFiles(dir)
	if err != nil { return err }
	appliedSet, err := appliedSet(db)
	if err != nil { return err }
	count := 0
	for _, name := range ups {
		if appliedSet[name] { continue }
		if err := applyFile(db, filepath.Join(dir, name)); err != nil {
			return fmt.Errorf("migration %s failed: %w", name, err)
		}
		if err := markApplied(db, name); err != nil { return err }
		count++
		if steps > 0 && count >= steps { break }
	}
	return nil
}

// MigrateDown rolls back 'steps' applied migrations, in reverse order.
// For each applied version, it expects a corresponding down file.
// Rules:
// - If version ends with ".up.sql" -> down is same base with ".down.sql".
// - If version ends with ".sql" (legacy) -> down is base+".down.sql" (base = trimSuffix(".sql")).
func MigrateDown(db *sql.DB, dir string, steps int) error {
	if steps <= 0 { return fmt.Errorf("steps must be > 0 for down") }
	if err := ensureMigrationsTable(db); err != nil { return err }
	appliedList, err := appliedList(db)
	if err != nil { return err }
	if len(appliedList) == 0 { return nil }
	// reverse order (last applied first)
	for i := len(appliedList)-1; i >= 0 && steps > 0; i-- {
		ver := appliedList[i]
		downName := guessDownName(ver)
		downPath := filepath.Join(dir, downName)
		if _, statErr := os.Stat(downPath); statErr != nil {
			return fmt.Errorf("down migration not found for %s (expected %s)", ver, downName)
		}
		if err := applyFile(db, downPath); err != nil {
			return fmt.Errorf("down migration %s failed: %w", downName, err)
		}
		if err := unmarkApplied(db, ver); err != nil { return err }
		steps--
	}
	return nil
}

// MigrateStatus returns applied versions and pending counts.
func MigrateStatus(db *sql.DB, dir string) (applied []string, pending []string, err error) {
	if err = ensureMigrationsTable(db); err != nil { return }
	ups, err2 := listUpFiles(dir)
	if err2 != nil { err = err2; return }
	aset, err2 := appliedSet(db)
	if err2 != nil { err = err2; return }
	for _, v := range orderedApplied(aset) {
		applied = append(applied, v)
	}
	for _, f := range ups {
		if !aset[f] { pending = append(pending, f) }
	}
	return
}

func ensureMigrationsTable(db *sql.DB) error {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		version TEXT PRIMARY KEY
	)`)
	return err
}

func appliedSet(db *sql.DB) (map[string]bool, error) {
	rows, err := db.Query(`SELECT version FROM schema_migrations`)
	if err != nil { return nil, err }
	defer rows.Close()
	m := make(map[string]bool)
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil { return nil, err }
		m[v] = true
	}
	return m, rows.Err()
}

func appliedList(db *sql.DB) ([]string, error) {
	rows, err := db.Query(`SELECT version FROM schema_migrations`)
	if err != nil { return nil, err }
	defer rows.Close()
	var list []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil { return nil, err }
		list = append(list, v)
	}
	sort.Strings(list)
	return list, rows.Err()
}

func orderedApplied(aset map[string]bool) []string {
	var list []string
	for v := range aset { list = append(list, v) }
	sort.Strings(list)
	return list
}

func markApplied(db *sql.DB, v string) error {
	_, err := db.Exec(`INSERT INTO schema_migrations(version) VALUES($1)`, v)
	return err
}

func unmarkApplied(db *sql.DB, v string) error {
	_, err := db.Exec(`DELETE FROM schema_migrations WHERE version=$1`, v)
	return err
}

func listUpFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) { return []string{}, nil }
		return nil, err
	}
	var files []string
	for _, e := range entries {
		if e.IsDir() { continue }
		n := e.Name()
		if strings.HasSuffix(n, ".down.sql") { continue }
		if strings.HasSuffix(n, ".up.sql") || strings.HasSuffix(n, ".sql") {
			files = append(files, n)
		}
	}
	sort.Strings(files)
	return files, nil
}

func guessDownName(up string) string {
	if strings.HasSuffix(up, ".up.sql") {
		return strings.TrimSuffix(up, ".up.sql") + ".down.sql"
	}
	if strings.HasSuffix(up, ".sql") {
		return strings.TrimSuffix(up, ".sql") + ".down.sql"
	}
	return up + ".down.sql"
}

func applyFile(db *sql.DB, path string) error {
	content, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if len(strings.TrimSpace(string(content))) == 0 {
		return nil // skip empty files
	}
	if _, err := db.Exec(string(content)); err != nil {
		return err
	}
	return nil
}
