package db

import (
	"database/sql"
	"fmt"
	"log"
	"os"

	"gopkg.in/ini.v1"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// Config keys (INI)
// [postgres]
// PG_DSN=postgres://user:pass@localhost:5432/dbname?sslmode=disable
// HOST=localhost
// PORT=5432
// USER=postgres
// PASSWORD=postgres
// DBNAME=go_thing
// SSLMODE=disable
// MIGRATIONS_DIR=./migrations

type PGConfig struct {
	DSN           string
	Host          string
	Port          string
	User          string
	Password      string
	DBName        string
	SSLMode       string
	MigrationsDir string
}

var globalDB *sql.DB

func Get() *sql.DB { return globalDB }

// Init opens the connection using config and assigns globalDB. Safe to call once at startup.
func Init(cfg *ini.File) (*sql.DB, *PGConfig, error) {
	pg := loadPGConfig(cfg)
	if pg.DSN == "" {
		pg.DSN = fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=%s", pg.User, pg.Password, pg.Host, pg.Port, pg.DBName, pg.SSLMode)
	}
	db, err := sql.Open("pgx", pg.DSN)
	if err != nil {
		return nil, nil, err
	}
	// Verify connection
	if err := db.Ping(); err != nil {
		return nil, nil, err
	}
	globalDB = db
	log.Printf("[Postgres] Connected to %s/%s", pg.Host, pg.DBName)
	return db, pg, nil
}

func loadPGConfig(cfg *ini.File) *PGConfig {
	// Primary section is [postgres], fallback to [default] to support single-section configs.
	secPG := cfg.Section("postgres")
	secDef := cfg.Section("default")

	pg := &PGConfig{
		DSN:           firstNonEmpty(secPG.Key("PG_DSN").String(), secDef.Key("PG_DSN").String(), os.Getenv("PG_DSN")),
		Host:          keyOrEnv2(secPG, secDef, "HOST", "PGHOST", "localhost"),
		Port:          keyOrEnv2(secPG, secDef, "PORT", "PGPORT", "5432"),
		User:          keyOrEnv2(secPG, secDef, "USER", "PGUSER", "postgres"),
		Password:      keyOrEnv2(secPG, secDef, "PASSWORD", "PGPASSWORD", ""),
		DBName:        keyOrEnv2(secPG, secDef, "DBNAME", "PGDATABASE", "postgres"),
		SSLMode:       firstNonEmpty(secPG.Key("SSLMODE").String(), secDef.Key("SSLMODE").String(), "disable"),
		MigrationsDir: firstNonEmpty(secPG.Key("MIGRATIONS_DIR").String(), secDef.Key("MIGRATIONS_DIR").String(), "./migrations"),
	}
	return pg
}

func keyOrEnv2(primary, fallbackSec *ini.Section, key, env, def string) string {
	if v := primary.Key(key).String(); v != "" { return v }
	if v := fallbackSec.Key(key).String(); v != "" { return v }
	if v := os.Getenv(env); v != "" { return v }
	return def
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" { return v }
	}
	return ""
}

func keyOrEnv(sec *ini.Section, key, env, fallback string) string {
	if v := sec.Key(key).String(); v != "" { return v }
	if v := os.Getenv(env); v != "" { return v }
	return fallback
}
