package utility

import (
	"flag"
	"fmt"
	"os"

	"go-thing/db"
	"go-thing/internal/config"
	"gopkg.in/ini.v1"
)

// RunMigrateCLI handles: migrate up [--step N], migrate down --step N, migrate status
func RunMigrateCLI(args []string) int {
	if len(args) == 0 {
		fmt.Println("Usage:\n  go-thing migrate up [--step N]\n  go-thing migrate down --step N\n  go-thing migrate status")
		return 2
	}
	// Load config and init DB
	cfgPath := os.ExpandEnv(config.ConfigFilePath)
	cfgIni, err := ini.Load(cfgPath)
	if err != nil {
		fmt.Printf("[Postgres] Config not loaded (%v)\n", err)
		return 1
	}
	dbConn, pgcfg, derr := db.Init(cfgIni)
	if derr != nil {
		fmt.Printf("[Postgres] Init failed: %v\n", derr)
		return 1
	}
	defer func() { _ = dbConn.Close() }()

	sub := args[0]
	switch sub {
	case "up":
		fs := flag.NewFlagSet("up", flag.ContinueOnError)
		step := fs.Int("step", 0, "number of up migrations to apply (0=all)")
		if err := fs.Parse(args[1:]); err != nil {
			fmt.Printf("[Migrate] parse error: %v\n", err)
			return 2
		}
		if err := db.MigrateUp(dbConn, pgcfg.MigrationsDir, *step); err != nil {
			fmt.Printf("[Migrate] up error: %v\n", err)
			return 1
		}
		fmt.Println("[Migrate] up completed")
		return 0
	case "down":
		fs := flag.NewFlagSet("down", flag.ContinueOnError)
		step := fs.Int("step", -1, "number of migrations to roll back (required)")
		if err := fs.Parse(args[1:]); err != nil {
			fmt.Printf("[Migrate] parse error: %v\n", err)
			return 2
		}
		if *step <= 0 {
			fmt.Println("[Migrate] down requires --step N (N>0)")
			return 2
		}
		if err := db.MigrateDown(dbConn, pgcfg.MigrationsDir, *step); err != nil {
			fmt.Printf("[Migrate] down error: %v\n", err)
			return 1
		}
		fmt.Println("[Migrate] down completed")
		return 0
	case "status":
		applied, pending, err := db.MigrateStatus(dbConn, pgcfg.MigrationsDir)
		if err != nil {
			fmt.Printf("[Migrate] status error: %v\n", err)
			return 1
		}
		fmt.Println("Applied:")
		for _, v := range applied {
			fmt.Printf("  - %s\n", v)
		}
		fmt.Println("Pending:")
		for _, v := range pending {
			fmt.Printf("  - %s\n", v)
		}
		return 0
	default:
		fmt.Println("Unknown migrate subcommand. Use: up, down, status")
		return 2
	}
}
