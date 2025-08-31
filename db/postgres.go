package db

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"net/url"

	"gopkg.in/ini.v1"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// Config keys (INI)
// [postgres]
// Preferred (DB_-prefixed):
// DB_DSN=postgres://user:pass@localhost:5432/dbname?sslmode=disable  # optional
// DB_HOST=localhost
// DB_PORT=5432
// DB_USER=postgres
// DB_PASSWORD=postgres
// DB_NAME=go_thing
// DB_SSLMODE=disable
// DB_MIGRATIONS_DIR=./migrations
// 
// Backward-compatibility: the legacy keys without DB_ prefix are still supported
// (PG_DSN, HOST, PORT, USER, PASSWORD, DBNAME, SSLMODE, MIGRATIONS_DIR) and
// standard env vars are honored (e.g., PG_DSN, PGHOST, PGPORT, PGUSER, PGPASSWORD, PGDATABASE).

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
		pg.DSN = fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=%s", pg.User, url.QueryEscape(pg.Password), pg.Host, pg.Port, pg.DBName, pg.SSLMode)
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
		// DSN: prefer DB_DSN, then legacy PG_DSN, then env PG_DSN
		DSN: firstNonEmpty(
			secPG.Key("DB_DSN").String(), secDef.Key("DB_DSN").String(),
			secPG.Key("PG_DSN").String(), secDef.Key("PG_DSN").String(),
			os.Getenv("PG_DSN"),
		),
		// Host: DB_HOST -> HOST -> PGHOST -> default
		Host: firstNonEmpty(
			secPG.Key("DB_HOST").String(), secDef.Key("DB_HOST").String(),
			secPG.Key("HOST").String(), secDef.Key("HOST").String(),
			os.Getenv("PGHOST"),
			"localhost",
		),
		// Port: DB_PORT -> PORT -> PGPORT -> default
		Port: firstNonEmpty(
			secPG.Key("DB_PORT").String(), secDef.Key("DB_PORT").String(),
			secPG.Key("PORT").String(), secDef.Key("PORT").String(),
			os.Getenv("PGPORT"),
			"5432",
		),
		// User: DB_USER -> USER -> PGUSER -> default
		User: firstNonEmpty(
			secPG.Key("DB_USER").String(), secDef.Key("DB_USER").String(),
			secPG.Key("USER").String(), secDef.Key("USER").String(),
			os.Getenv("PGUSER"),
			"postgres",
		),
		// Password: DB_PASSWORD -> PASSWORD -> PGPASSWORD -> default empty
		Password: firstNonEmpty(
			secPG.Key("DB_PASSWORD").String(), secDef.Key("DB_PASSWORD").String(),
			secPG.Key("PASSWORD").String(), secDef.Key("PASSWORD").String(),
			os.Getenv("PGPASSWORD"),
			"",
		),
		// DBName: DB_NAME -> DBNAME -> PGDATABASE -> default postgres
		DBName: firstNonEmpty(
			secPG.Key("DB_NAME").String(), secDef.Key("DB_NAME").String(),
			secPG.Key("DBNAME").String(), secDef.Key("DBNAME").String(),
			os.Getenv("PGDATABASE"),
			"postgres",
		),
		// SSLMode: DB_SSLMODE -> SSLMODE -> default disable
		SSLMode: firstNonEmpty(
			secPG.Key("DB_SSLMODE").String(), secDef.Key("DB_SSLMODE").String(),
			secPG.Key("SSLMODE").String(), secDef.Key("SSLMODE").String(),
			"disable",
		),
		// Migrations dir: DB_MIGRATIONS_DIR -> MIGRATIONS_DIR -> default ./migrations
		MigrationsDir: firstNonEmpty(
			secPG.Key("DB_MIGRATIONS_DIR").String(), secDef.Key("DB_MIGRATIONS_DIR").String(),
			secPG.Key("MIGRATIONS_DIR").String(), secDef.Key("MIGRATIONS_DIR").String(),
			"./migrations",
		),
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
