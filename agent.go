package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"

	"crypto/rand"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"golang.org/x/time/rate"
	"gopkg.in/ini.v1"

	"go-thing/db"
	"go-thing/internal/config"
	"go-thing/routes"
	logging "go-thing/internal/logging"
	toolsrv "go-thing/tools"
	"go-thing/utility"
)

// isStrongPassword moved to utility/password.go as utility.IsStrongPassword

// requireAuth is a Gin middleware that enforces a valid session and stores userID in context
func requireAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		if uid, ok := utility.ParseSession(c.Request, sessionSecret); ok {
			c.Set("userID", uid)
			c.Next()
			return
		}
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "not logged in"})
	}
}

// ToolResponse represents a response from tool execution
type ToolResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

// Email validation moved to utility/validation.go (utility.EmailRegex / utility.IsValidEmail)

// sessionSecret holds the HMAC key for signing session cookies
var sessionSecret []byte

// sessionDuration defines how long a session is valid
const sessionDuration = 7 * 24 * time.Hour

// loginRateLimiter provides basic IP-based throttling and per-user lockouts for /login
type loginRateLimiter struct {
	mu        sync.Mutex
	ip        map[string]*rate.Limiter
	ipSeen    map[string]time.Time
	userFails map[string]*userFail
}

type userFail struct {
	count     int
	lockUntil time.Time
	last      time.Time
}

var lr = &loginRateLimiter{
	ip:        make(map[string]*rate.Limiter),
	ipSeen:    make(map[string]time.Time),
	userFails: make(map[string]*userFail),
}

// getLimiter returns the IP limiter, creating one if needed.
func (l *loginRateLimiter) getLimiter(ip string) *rate.Limiter {
	l.mu.Lock()
	defer l.mu.Unlock()
	lim, ok := l.ip[ip]
	if !ok {
		// ~10 requests/minute with burst of 5
		lim = rate.NewLimiter(rate.Every(6*time.Second), 5)
		l.ip[ip] = lim
	}
	l.ipSeen[ip] = time.Now()
	return lim
}

// isLocked returns remaining lockout if the user is locked.
func (l *loginRateLimiter) isLocked(user string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if st, ok := l.userFails[strings.ToLower(strings.TrimSpace(user))]; ok {
		if time.Now().Before(st.lockUntil) {
			return true, time.Until(st.lockUntil)
		}
	}
	return false, 0
}

// recordFailure increments failure count and applies lockout on threshold.
func (l *loginRateLimiter) recordFailure(user string) {
	const threshold = 5
	const lockDur = 15 * time.Minute
	u := strings.ToLower(strings.TrimSpace(user))
	l.mu.Lock()
	defer l.mu.Unlock()
	st := l.userFails[u]
	if st == nil {
		st = &userFail{}
		l.userFails[u] = st
	}
	st.count++
	st.last = time.Now()
	if st.count >= threshold {
		st.lockUntil = time.Now().Add(lockDur)
	}
}

// recordSuccess clears failure state on successful login.
func (l *loginRateLimiter) recordSuccess(user string) {
	u := strings.ToLower(strings.TrimSpace(user))
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.userFails, u)
}

// cleanup prunes stale IP and user failure entries to bound memory usage.
func (l *loginRateLimiter) cleanup() {
	const ipExpiry = 24 * time.Hour
	const userFailExpiry = 30 * time.Minute // lockout 15m + 15m grace

	// Perform pruning under a single lock to avoid dropping concurrent updates.
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()

	// Prune stale IP entries
	for ip, seen := range l.ipSeen {
		if now.Sub(seen) > ipExpiry {
			delete(l.ip, ip)
			delete(l.ipSeen, ip)
		}
	}

	// Prune stale user failure entries
	for user, fail := range l.userFails {
		// Delete if not locked and last failure was sufficiently old
		if now.After(fail.lockUntil) && now.Sub(fail.last) > userFailExpiry {
			delete(l.userFails, user)
		}
	}
}

// getOrCreateAnyThread returns the most recently updated thread id if one exists,
// otherwise it creates the first thread and returns its id.
func getOrCreateAnyThread() (int64, error) {
	dbc := db.Get()
	if dbc == nil {
		return 0, fmt.Errorf("db not initialized")
	}
	var id int64
	// Try to get the latest updated thread
	err := dbc.QueryRow(`SELECT id FROM threads ORDER BY updated_at DESC LIMIT 1`).Scan(&id)
	if err == nil {
		return id, nil
	}
	if err != sql.ErrNoRows {
		return 0, err
	}
	// No rows, create the first thread
	title := fmt.Sprintf("Default Thread %s", time.Now().Format("2006-01-02"))
	return utility.CreateNewThread(title)
}

// runMigrateCLI handles: migrate up [--step N], migrate down --step N, migrate status
func runMigrateCLI(args []string) int {
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

// Tool represents a tool definition
type Tool struct {
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Help        string            `json:"help"`
	Parameters  map[string]string `json:"parameters,omitempty"`
}

// DiskSpaceInfo represents disk space information
type DiskSpaceInfo struct {
	Path         string  `json:"path"`
	TotalBytes   uint64  `json:"total_bytes"`
	FreeBytes    uint64  `json:"free_bytes"`
	UsedBytes    uint64  `json:"used_bytes"`
	TotalGB      float64 `json:"total_gb"`
	FreeGB       float64 `json:"free_gb"`
	UsedGB       float64 `json:"used_gb"`
	UsagePercent float64 `json:"usage_percent"`
}

// Deprecated local tools registry; tools are discovered dynamically from the tool server
var tools = map[string]Tool{}

// (moved) Enhanced Gemini API handler is defined later in this file.
// The earlier partial definition was removed to avoid duplication and syntax errors.
// summarizeToolResponse moved to utility_misc.go
// maskToken moved to utility_misc.go

// Cached allowlist of origins for WebSocket upgrades
var (
	allowedOrigins     map[string]struct{}
	allowedOriginsOnce sync.Once
)

// WebSocket upgrader for shell streaming
// Secure origin check: allow only configured origins or same-origin by default.
var wsUpgrader = websocket.Upgrader{
	CheckOrigin: isAllowedWSOrigin,
}

// isAllowedWSOrigin restricts WebSocket connections to trusted origins to prevent CSWSH.
// Allowed origins can be configured via [default] ALLOWED_ORIGINS in the INI config (comma-separated full origins).
// If not configured, we allow only same-origin based on the request's Host and scheme.
func isAllowedWSOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if strings.TrimSpace(origin) == "" {
		return false
	}
	if u, err := url.Parse(origin); err != nil {
		return false
	} else if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}

	// Parse and cache allowed origins on first run
	allowedOriginsOnce.Do(func() {
		allowedOrigins = make(map[string]struct{})
		if cfg, err := utility.LoadConfig(); err == nil && cfg != nil {
			if raw := strings.TrimSpace(cfg["ALLOWED_ORIGINS"]); raw != "" {
				for _, item := range strings.Split(raw, ",") {
					a := strings.TrimSpace(item)
					if a != "" {
						allowedOrigins[a] = struct{}{}
					}
				}
			}
		} else if err != nil {
			log.Printf("[ShellWS] failed to load config for allowed origins: %v. Falling back to same-origin policy.", err)
		}
	})

	// If an allowlist is configured, use it exclusively.
	if len(allowedOrigins) > 0 {
		_, ok := allowedOrigins[origin]
		return ok
	}

	// Fallback: allow same-origin only
	// Use shared utility.IsSecure(*http.Request) to determine scheme (TLS or proxy-aware).
	scheme := "http"
	if utility.IsSecure(r) {
		scheme = "https"
	}
	sameOrigin := fmt.Sprintf("%s://%s", scheme, r.Host)
	return origin == sameOrigin
}

func main() {
	// Setup logging
	f, err := logging.Setup()
	if err != nil {
		log.Printf("[Startup] Failed to setup logging: %v", err)
	} else if f != nil {
		defer f.Close()
	}
	log.Printf("[Startup] Starting go-thing agent")

	// CLI migrate
	if len(os.Args) > 1 && os.Args[1] == "migrate" {
		os.Exit(runMigrateCLI(os.Args[2:]))
		return
	}

	// Load config and init DB/migrations if possible
	cfgPath := os.ExpandEnv(config.ConfigFilePath)
	cfgIni, iniErr := ini.Load(cfgPath)
	if iniErr == nil {
		if dbConn, pgcfg, derr := db.Init(cfgIni); derr != nil {
			log.Printf("[Postgres] Init failed: %v (continuing without DB)", derr)
		} else {
			defer func() { _ = dbConn.Close() }()
			if merr := db.RunMigrations(dbConn, pgcfg.MigrationsDir); merr != nil {
				log.Printf("[Postgres] Migrations error: %v", merr)
			} else {
				log.Printf("[Postgres] Migrations applied from %s", pgcfg.MigrationsDir)
			}
		}

	} else {
		log.Printf("[Config] Load failed (%v); continuing with defaults", iniErr)
	}

	// Initialize session secret
	if iniErr == nil {
		if v := strings.TrimSpace(cfgIni.Section("default").Key("SESSION_SECRET").String()); v != "" {
			if len(v) < 32 {
				log.Printf("[Auth] WARNING: SESSION_SECRET is %d bytes long, which is less than the recommended 32 bytes for production.", len(v))
			}
			sessionSecret = []byte(v)
		}
	}
	if len(sessionSecret) == 0 {
		// generate ephemeral secret
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			log.Fatalf("[Auth] CRITICAL: failed to generate a random session secret, cannot start: %v", err)
		}
		sessionSecret = b
		log.Printf("[Auth] Using ephemeral session secret; set SESSION_SECRET in config for persistence")
	}

	// Determine addresses
	apiAddr := "0.0.0.0:7866"
	if cfg, err := utility.LoadConfig(); err == nil {
		if v := strings.TrimSpace(cfg["API_ADDR"]); v != "" {
			apiAddr = v
		}
		// DOCKER_AUTO_REMOVE is handled and cached in utility_config.go
	}

	// Start tool server
	toolServer := toolsrv.NewServer(utility.GetToolsAddr())
	go func() {
		log.Printf("[Tools] Starting tool server on %s", utility.GetToolsAddr())
		if err := toolServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[Tools] Tool server error: %v", err)
		}
	}()

	// Periodic cleanup for login rate limiter to bound memory usage
	cleanupStop := make(chan struct{})
	cleanupTicker := time.NewTicker(10 * time.Minute)
	go func() {
		for {
			select {
			case <-cleanupTicker.C:
				lr.cleanup()
			case <-cleanupStop:
				cleanupTicker.Stop()
				return
			}
		}
	}()

	// Gin router and routes
	r := gin.Default()
	r.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok", "service": "go-thing agent API"})
	})
	// CSRF token issuer. Returns {token} and sets csrf_token cookie.
	r.GET("/csrf", func(c *gin.Context) {
		tok, err := utility.NewCSRFToken()
		if err != nil {
			log.Printf("[CSRF] token gen error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed"})
			return
		}
		utility.SetCSRFCookie(c, tok)
		c.JSON(http.StatusOK, gin.H{"token": tok})
	})
	routes.RegisterSignupRoutes(r)

    // Docker SSH key endpoints moved to routes/api_docker_routes.go
    routes.RegisterAPIDockerRoutes(r, requireAuth(), routes.APIDockerDeps{
        EnsureDockerContainer:    toolsrv.EnsureDockerContainer,
        EnsureSSHKeygenAvailable: utility.EnsureSSHKeygenAvailable,
        RunDockerExec:            utility.RunDockerExec,
    })

    // Login endpoint moved to routes/login_routes.go
    routes.RegisterLoginRoutes(r, routes.LoginDeps{
        GetLimiter: func(ip string) bool { return lr.getLimiter(ip).Allow() },
        IsLocked: func(user string) (bool, time.Duration) { return lr.isLocked(user) },
        RecordFailure: lr.recordFailure,
        RecordSuccess: lr.recordSuccess,
        DummyBcryptCompare: utility.DummyBcryptCompare,
        SetSessionCookie: func(c *gin.Context, userID int64) {
            utility.SetSessionCookie(c, userID, sessionSecret, sessionDuration)
        },
    })

	// Logout endpoint (CSRF protected)
	r.POST("/logout", func(c *gin.Context) {
		if !utility.ValidateCSRF(c) {
			c.JSON(http.StatusForbidden, gin.H{"error": "csrf invalid"})
			return
		}
		utility.ClearSessionCookie(c)
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

    // Current user endpoint moved to routes/me_routes.go
    routes.RegisterMeRoutes(r, sessionSecret)

	// Authenticated User Settings routes
	auth := r.Group("/", requireAuth())
	// Settings page is now rendered by the web frontend (#/settings)

	    // Settings APIs moved to routes/api_settings_routes.go
    routes.RegisterAPISettingsRoutes(auth)

    // Generate SSH keys inside the Docker container and return them (moved to routes)
    routes.RegisterAPISSHRoutes(auth, routes.APISSHDeps{
        EnsureDockerContainer:    toolsrv.EnsureDockerContainer,
        EnsureSSHKeygenAvailable: utility.EnsureSSHKeygenAvailable,
        RunDockerExec:            utility.RunDockerExec,
    })

	// GitHub direct API caller moved to routes/github_routes.go

	routes.RegisterGithubRoutes(r)

	routes.RegisterJiraRoutes(r)
    // Shell session management endpoints (moved to routes/shell_routes.go)
    routes.RegisterShellRoutes(r, &wsUpgrader)
	routes.RegisterChatRoutes(r, getOrCreateAnyThread)
    // Slack webhook routes moved to routes/slack_routes.go
    routes.RegisterSlackRoutes(r, getOrCreateAnyThread)
	r.POST("/webhook", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"status": "webhook received"}) })

	// HTTP server with graceful shutdown
	apiServer := &http.Server{Addr: apiAddr, Handler: r}
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		log.Printf("[API] Starting HTTP server on %s", apiAddr)
		if err := apiServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[API] Server error: %v", err)
		}
	}()
	sig := <-quit
	log.Printf("[Shutdown] Signal: %v", sig)
	// Stop background cleanup ticker
	close(cleanupStop)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = apiServer.Shutdown(ctx)
	_ = toolServer.Shutdown(ctx)
	// Close shell sessions gracefully (single lock via CloseAll)
	toolsrv.GetShellBroker().CloseAll()
}
