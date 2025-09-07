package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"

	"crypto/rand"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/jackc/pgx/v5/pgconn"
	"golang.org/x/crypto/bcrypt"
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

// emailRegex caches a simple email validation regex.
var (
	emailRegexOnce     sync.Once
	emailRegexCompiled *regexp.Regexp
)

func emailRegex() *regexp.Regexp {
	emailRegexOnce.Do(func() {
		// Simple pattern: non-space/non-@ local, @, non-space/non-@ domain, dot, tld
		emailRegexCompiled = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)
	})
	return emailRegexCompiled
}

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

// dummyBcryptCompare performs a bcrypt comparison against a dummy hash to
// normalize timing between "user not found" and "wrong password" cases.
// The dummy hash is generated once at runtime to avoid shipping a hardcoded hash.
var (
	dummyHashOnce sync.Once
	dummyHash     []byte
)

func dummyBcryptCompare(password string) {
	dummyHashOnce.Do(func() {
		// Generate a hash once; cost matches default user hashing cost.
		h, err := bcrypt.GenerateFromPassword([]byte("dummy-password-for-timing-only"), bcrypt.DefaultCost)
		if err != nil {
			log.Fatalf("[Auth] CRITICAL: failed to generate dummy bcrypt hash for timing attack mitigation: %v", err)
		}
		dummyHash = h
	})
	// The dummyHash is guaranteed to be non-empty here due to log.Fatalf on error.
	_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(password))
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

// isSecure determines if the request is effectively HTTPS (directly or via proxy header)
func isSecure(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

// runDockerExec runs `docker exec` with the given args inside the specified container.
// Returns stdout/stderr as strings with a timeout.
func runDockerExec(container string, args []string, timeout time.Duration) (string, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	full := append([]string{"exec", container}, args...)
	cmd := exec.CommandContext(ctx, "docker", full...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

// ensureSSHKeygenAvailable ensures ssh-keygen exists in the container; if missing, installs openssh via pacman.
func ensureSSHKeygenAvailable(container string) error {
	if _, _, err := runDockerExec(container, []string{"ssh-keygen", "-V"}, 10*time.Second); err == nil {
		return nil
	}
	// Attempt install on Arch base
	if _, stderr, err := runDockerExec(container, []string{"bash", "-lc", "pacman -Sy --noconfirm && pacman -S --noconfirm openssh"}, 2*time.Minute); err != nil {
		return fmt.Errorf("failed to install openssh in container: %v (stderr: %s)", err, strings.TrimSpace(stderr))
	}
	// Re-check
	if _, _, err := runDockerExec(container, []string{"ssh-keygen", "-V"}, 10*time.Second); err != nil {
		return fmt.Errorf("ssh-keygen still unavailable after install: %v", err)
	}
	return nil
}

// Session helpers moved to utility/session.go: utility.SetSessionCookie, utility.ClearSessionCookie, utility.ParseSession

// isUniqueViolation returns true when err is a Postgres unique constraint violation (SQLSTATE 23505).
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "23505"
	}
	return false
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
	// Use shared isSecure(*http.Request) to determine scheme (TLS or proxy-aware).
	scheme := "http"
	if isSecure(r) {
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

	// Download SSH key from the running container (without hardcoding user). Uses $HOME/.ssh paths.
	// GET /api/docker/ssh-keys/download?which=public|private
	r.GET("/api/docker/ssh-keys/download", requireAuth(), func(c *gin.Context) {
		which := strings.ToLower(strings.TrimSpace(c.Query("which")))
		var rel string
		var fname string
		switch which {
		case "public", "pub":
			rel = "$HOME/.ssh/id_ed25519.pub"
			fname = "id_ed25519.pub"
		case "private", "priv":
			rel = "$HOME/.ssh/id_ed25519"
			fname = "id_ed25519"
		default:
			c.JSON(http.StatusBadRequest, gin.H{"error": "which must be 'public' or 'private'"})
			return
		}

		containerName, err := toolsrv.EnsureDockerContainer()
		if err != nil {
			log.Printf("[DockerSSHDownload] ensure container error: %v", err)
			c.JSON(http.StatusBadGateway, gin.H{"error": "failed to start container"})
			return
		}
		cmd := fmt.Sprintf("cat %s", rel)
		out, stderr, err := runDockerExec(containerName, []string{"bash", "-lc", cmd}, 5*time.Second)
		if err != nil {
			log.Printf("[DockerSSHDownload] read error: %v (stderr: %s)", err, strings.TrimSpace(stderr))
			c.JSON(http.StatusNotFound, gin.H{"error": "key not found"})
			return
		}
		// Stream as attachment
		c.Header("Content-Type", "text/plain; charset=utf-8")
		c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", fname))
		c.String(http.StatusOK, out)
	})

	// Generate an ed25519 SSH key inside the Docker container and return the public key
	r.POST("/api/docker/ssh-key", requireAuth(), func(c *gin.Context) {
		if !utility.ValidateCSRF(c) {
			c.JSON(http.StatusForbidden, gin.H{"error": "csrf invalid"})
			return
		}
		// Ensure docker container is running
		containerName, err := toolsrv.EnsureDockerContainer()
		if err != nil {
			log.Printf("[DockerSSHKey] ensure container error: %v", err)
			c.JSON(http.StatusBadGateway, gin.H{"error": "failed to start container"})
			return
		}
		if err := ensureSSHKeygenAvailable(containerName); err != nil {
			log.Printf("[DockerSSHKey] ensure ssh-keygen error: %v", err)
			c.JSON(http.StatusBadGateway, gin.H{"error": "failed to prepare ssh-keygen in container"})
			return
		}
		// Create ~/.ssh, remove existing keys, and generate a new one
		cmd := "set -e; mkdir -p ~/.ssh; chmod 700 ~/.ssh; rm -f ~/.ssh/id_ed25519 ~/.ssh/id_ed25519.pub; ssh-keygen -t ed25519 -C 'developer@container.local' -N '' -f ~/.ssh/id_ed25519 -q; chmod 600 ~/.ssh/id_ed25519; chmod 644 ~/.ssh/id_ed25519.pub"
		if _, stderr, err := runDockerExec(containerName, []string{"bash", "-lc", cmd}, 20*time.Second); err != nil {
			log.Printf("[DockerSSHKey] ssh-keygen error: %v (stderr: %s)", err, strings.TrimSpace(stderr))
			c.JSON(http.StatusBadGateway, gin.H{"error": "ssh-keygen failed"})
			return
		}
		// Read public key
		pub, perr, err := runDockerExec(containerName, []string{"bash", "-lc", "cat ~/.ssh/id_ed25519.pub"}, 5*time.Second)
		if err != nil {
			log.Printf("[DockerSSHKey] read public key error: %v (stderr: %s)", err, strings.TrimSpace(perr))
			c.JSON(http.StatusBadGateway, gin.H{"error": "failed reading public key"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"ok": true, "public_key": strings.TrimSpace(pub)})
	})

    // Login endpoint moved to routes/login_routes.go
    routes.RegisterLoginRoutes(r, routes.LoginDeps{
        GetLimiter: func(ip string) bool { return lr.getLimiter(ip).Allow() },
        IsLocked: func(user string) (bool, time.Duration) { return lr.isLocked(user) },
        RecordFailure: lr.recordFailure,
        RecordSuccess: lr.recordSuccess,
        DummyBcryptCompare: dummyBcryptCompare,
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

	// Current user endpoint
	r.GET("/me", func(c *gin.Context) {
		uid, ok := utility.ParseSession(c.Request, sessionSecret)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "not logged in"})
			return
		}
		dbc := db.Get()
		if dbc == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database not initialized"})
			return
		}
		var username, name string
		if err := dbc.QueryRow(`SELECT username, name FROM users WHERE id=$1`, uid).Scan(&username, &name); err != nil {
			if err == sql.ErrNoRows {
				log.Printf("[Me] WARN: valid session for non-existent user ID %d", uid)
				utility.ClearSessionCookie(c)
				c.JSON(http.StatusUnauthorized, gin.H{"error": "not logged in"})
				return
			}
			log.Printf("[Me] query error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"id": uid, "username": username, "name": name})
	})

	// Authenticated User Settings routes
	auth := r.Group("/", requireAuth())
	// Settings page is now rendered by the web frontend (#/settings)

	// Read current settings
	auth.GET("/api/settings", func(c *gin.Context) {
		v, ok := c.Get("userID")
		if !ok {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "user ID not found in context"})
			return
		}
		uid, ok := v.(int64)
		if !ok {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid user ID type in context"})
			return
		}
		dbc := db.Get()
		if dbc == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database not initialized"})
			return
		}
		var username, name string
		if err := dbc.QueryRow(`SELECT username, name FROM users WHERE id=$1`, uid).Scan(&username, &name); err != nil {
			if err == sql.ErrNoRows {
				utility.ClearSessionCookie(c)
				c.JSON(http.StatusUnauthorized, gin.H{"error": "not logged in"})
				return
			}
			log.Printf("[Settings] query error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"username": username, "name": name})
	})

	// Update profile (name)
	auth.POST("/api/settings", func(c *gin.Context) {
		if !utility.ValidateCSRF(c) {
			c.JSON(http.StatusForbidden, gin.H{"error": "csrf invalid"})
			return
		}
		var req struct {
			Name string `json:"name"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}
		name := strings.TrimSpace(req.Name)
		if name == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "name is required"})
			return
		}
		v, ok := c.Get("userID")
		if !ok {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "user ID not found in context"})
			return
		}
		uid, ok := v.(int64)
		if !ok {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid user ID type in context"})
			return
		}
		dbc := db.Get()
		if dbc == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database not initialized"})
			return
		}
		if _, err := dbc.Exec(`UPDATE users SET name=$1, updated_at=now() WHERE id=$2`, name, uid); err != nil {
			log.Printf("[Settings] update name error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	// Change password
	auth.POST("/api/settings/password", func(c *gin.Context) {
		if !utility.ValidateCSRF(c) {
			c.JSON(http.StatusForbidden, gin.H{"error": "csrf invalid"})
			return
		}
		var req struct {
			Current string `json:"current_password"`
			New     string `json:"new_password"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}
		if len(req.New) < 8 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "new password must be at least 8 characters"})
			return
		}
		if !utility.IsStrongPassword(req.New) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "password must be 12+ chars and include upper, lower, digit, and special character"})
			return
		}
		v, ok := c.Get("userID")
		if !ok {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "user ID not found in context"})
			return
		}
		uid, ok := v.(int64)
		if !ok {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid user ID type in context"})
			return
		}
		dbc := db.Get()
		if dbc == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database not initialized"})
			return
		}
		var hash string
		if err := dbc.QueryRow(`SELECT password_hash FROM users WHERE id=$1`, uid).Scan(&hash); err != nil {
			if err == sql.ErrNoRows {
				utility.ClearSessionCookie(c)
				c.JSON(http.StatusUnauthorized, gin.H{"error": "not logged in"})
				return
			}
			log.Printf("[Settings] query pass error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed"})
			return
		}
		if bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Current)) != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "current password is incorrect"})
			return
		}
		newHash, err := bcrypt.GenerateFromPassword([]byte(req.New), bcrypt.DefaultCost)
		if err != nil {
			log.Printf("[Settings] bcrypt error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed"})
			return
		}
		if _, err := dbc.Exec(`UPDATE users SET password_hash=$1, updated_at=now() WHERE id=$2`, string(newHash), uid); err != nil {
			log.Printf("[Settings] update pass error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	// Docker settings: GET current and POST to update
	auth.GET("/api/settings/docker", func(c *gin.Context) {
		v, ok := c.Get("userID")
		if !ok {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "user ID not found in context"})
			return
		}
		uid, ok := v.(int64)
		if !ok {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid user ID type in context"})
			return
		}
		dbc := db.Get()
		if dbc == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database not initialized"})
			return
		}
		var settingsRaw sql.NullString
		if err := dbc.QueryRow(`SELECT settings::text FROM users WHERE id=$1`, uid).Scan(&settingsRaw); err != nil {
			if err == sql.ErrNoRows {
				utility.ClearSessionCookie(c)
				c.JSON(http.StatusUnauthorized, gin.H{"error": "not logged in"})
				return
			}
			log.Printf("[DockerSettings] select err: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed"})
			return
		}
		var settings map[string]interface{}
		if settingsRaw.Valid && strings.TrimSpace(settingsRaw.String) != "" {
			_ = json.Unmarshal([]byte(settingsRaw.String), &settings)
		}
		if settings == nil {
			settings = map[string]interface{}{}
		}
		dockerVal, _ := settings["docker"].(map[string]interface{})
		if dockerVal == nil {
			dockerVal = map[string]interface{}{}
		}
		c.JSON(http.StatusOK, gin.H{"docker": dockerVal})
	})

	auth.POST("/api/settings/docker", func(c *gin.Context) {
		if !utility.ValidateCSRF(c) {
			c.JSON(http.StatusForbidden, gin.H{"error": "csrf invalid"})
			return
		}
		v, ok := c.Get("userID")
		if !ok {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "user ID not found in context"})
			return
		}
		uid, ok := v.(int64)
		if !ok {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid user ID type in context"})
			return
		}
		var req struct {
			Container  string `json:"container"`
			Image      string `json:"image"`
			Args       string `json:"args"`
			Dockerfile string `json:"dockerfile"`
			AutoRemove *bool  `json:"auto_remove"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}
		// minimal validation/normalization
		container := strings.TrimSpace(req.Container)
		image := strings.TrimSpace(req.Image)
		args := strings.TrimSpace(req.Args)
		dockerfile := req.Dockerfile // allow multi-line, do not trim internally to preserve intended formatting
		autoRemove := true
		if req.AutoRemove != nil {
			autoRemove = *req.AutoRemove
		}
		dockerObj := map[string]interface{}{
			"container":   container,
			"image":       image,
			"args":        args,
			"dockerfile":  dockerfile,
			"auto_remove": autoRemove,
		}
		dbc := db.Get()
		if dbc == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database not initialized"})
			return
		}
		// Update docker key within JSONB using jsonb_set for atomic update
		const upd = `UPDATE users SET settings = jsonb_set(COALESCE(settings, '{}'::jsonb), '{docker}', to_jsonb($1::json), true), updated_at=now() WHERE id=$2`
		b, _ := json.Marshal(dockerObj)
		if _, err := dbc.Exec(upd, string(b), uid); err != nil {
			log.Printf("[DockerSettings] update err: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

    // Generate SSH keys inside the Docker container and return them (moved to routes)
    routes.RegisterAPISSHRoutes(auth, routes.APISSHDeps{
        EnsureDockerContainer:    toolsrv.EnsureDockerContainer,
        EnsureSSHKeygenAvailable: ensureSSHKeygenAvailable,
        RunDockerExec:            runDockerExec,
    })

	// GitHub direct API caller (CSRF protected)
	r.POST("/github/call", func(c *gin.Context) {
		if !utility.ValidateCSRF(c) {
			c.JSON(http.StatusForbidden, gin.H{"error": "csrf invalid"})
			return
		}
		// limit body to 1MB
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 1<<20)
		var req struct {
			Method string                 `json:"method"`
			Path   string                 `json:"path"`
			Query  map[string]interface{} `json:"query"`
			Body   interface{}            `json:"body"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}
		m := strings.ToUpper(strings.TrimSpace(req.Method))
		if m == "" {
			m = "GET"
		}
		p := strings.TrimSpace(req.Path)
		if p == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "path is required"})
			return
		}
		q := url.Values{}
		for k, v := range req.Query {
			key := strings.TrimSpace(k)
			if key == "" {
				continue
			}
			switch tv := v.(type) {
			case string:
				if tv != "" {
					q.Set(key, tv)
				}
			case float64:
				q.Set(key, strconv.FormatInt(int64(tv), 10))
			case bool:
				q.Set(key, strconv.FormatBool(tv))
			case []interface{}:
				// join as comma list
				parts := make([]string, 0, len(tv))
				for _, iv := range tv {
					parts = append(parts, fmt.Sprint(iv))
				}
				if len(parts) > 0 {
					q.Set(key, strings.Join(parts, ","))
				}
			default:
				// fallback to fmt.Sprint
				s := fmt.Sprint(tv)
				if strings.TrimSpace(s) != "" {
					q.Set(key, s)
				}
			}
		}
		status, body, hdrs, err := utility.GitHubDo(m, p, q, req.Body)
		if err != nil {
			c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
			return
		}
		// Try JSON parse
		var obj interface{}
		if len(body) > 0 && json.Unmarshal(body, &obj) == nil {
			c.JSON(status, gin.H{"ok": status >= 200 && status < 300, "data": obj, "headers": hdrs})
			return
		}
		c.JSON(status, gin.H{"ok": status >= 200 && status < 300, "data": string(body), "headers": hdrs})
	})

	routes.RegisterGithubRoutes(r)

	routes.RegisterJiraRoutes(r)
	// Shell session management endpoints
	r.GET("/shell/sessions", func(c *gin.Context) {
		ids := toolsrv.GetShellBroker().List()
		c.JSON(http.StatusOK, gin.H{"sessions": ids})
	})
	r.POST("/shell/sessions", func(c *gin.Context) {
		var req struct {
			ID     string `json:"id" binding:"required"`
			Subdir string `json:"subdir"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}
		if strings.TrimSpace(req.ID) == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "session id cannot be empty"})
			return
		}
		if _, err := toolsrv.GetShellBroker().CreateOrGet(req.ID, req.Subdir); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"ok": true, "id": req.ID})
	})
	r.DELETE("/shell/sessions/:id", func(c *gin.Context) {
		id := c.Param("id")
		if err := toolsrv.GetShellBroker().Close(id); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
	r.GET("/shell/ws/:id", func(c *gin.Context) {
		id := c.Param("id")
		// Create if missing with default workdir
		sess, err := toolsrv.GetShellBroker().CreateOrGet(id, "")
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		conn, err := wsUpgrader.Upgrade(c.Writer, c.Request, nil)
		if err != nil {
			log.Printf("[ShellWS] upgrade error: %v", err)
			return
		}
		defer conn.Close()

		// Subscribe to output
		outCh := sess.Subscribe()
		defer sess.Unsubscribe(outCh)

		// Writer goroutine
		done := make(chan struct{})
		var once sync.Once
		closeDone := func() { once.Do(func() { close(done) }) }
		var writeMu sync.Mutex
		go func() {
			for {
				select {
				case data, ok := <-outCh:
					if !ok {
						// Serialize WebSocket writes with a shared mutex to avoid concurrent writer issues.
						writeMu.Lock()
						_ = conn.WriteMessage(websocket.TextMessage, []byte("[session closed]\n"))
						writeMu.Unlock()
						_ = conn.Close()
						closeDone()
						return
					}
					writeMu.Lock()
					err := conn.WriteMessage(websocket.BinaryMessage, data)
					writeMu.Unlock()
					if err != nil {
						log.Printf("[ShellWS %s] write error: %v", id, err)
						_ = conn.Close()
						closeDone()
						return
					}
				case <-done:
					return
				}
			}
		}()

		// Read loop -> enqueue to shell with heartbeat and backpressure handling
		const pongWait = 60 * time.Second
		conn.SetReadDeadline(time.Now().Add(pongWait))
		conn.SetPongHandler(func(string) error {
			conn.SetReadDeadline(time.Now().Add(pongWait))
			return nil
		})

	ReadLoop:
		for {
			mt, msg, err := conn.ReadMessage()
			if err != nil {
				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
					log.Printf("[ShellWS %s] read error: %v", id, err)
				}
				break
			}
			if mt == websocket.TextMessage || mt == websocket.BinaryMessage {
				if !sess.Enqueue(msg) {
					log.Printf("[ShellWS %s] input queue is full, closing connection.", id)
					writeMu.Lock()
					_ = conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.ClosePolicyViolation, "Input queue full"))
					writeMu.Unlock()
					break ReadLoop
				}
			}
		}
		closeDone()
	})
	r.POST("/chat", func(c *gin.Context) {
		var req struct {
			Message string `json:"message" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
			return
		}
		threadID, err := getOrCreateAnyThread()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to ensure thread"})
			return
		}
		if err := utility.StoreMessage(threadID, "user", req.Message, map[string]interface{}{"source": "http"}); err != nil {
			log.Printf("[DB] Failed to store user message: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to persist user message"})
			return
		}
		// Load last persisted context for this thread
		initialCtx, err := utility.GetLastContextForThread(threadID)
		if err != nil {
			log.Printf("[Context] load error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load conversation context"})
			return
		}
		log.Printf("[Context] Using initial current_context for HTTP: %v", initialCtx)
		resp, updatedCtx, err := utility.GeminiAPIHandler(c.Request.Context(), req.Message, initialCtx)
		if err != nil {
			log.Printf("[Chat] gemini error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process message. Please try again later."})
			return
		}
		if strings.TrimSpace(resp) == "" {
			resp = "**No response available. Please try again.**"
		}
		log.Printf("[Context] Persisting updated current_context (HTTP): %v", updatedCtx)
		if err := utility.StoreMessage(threadID, "assistant", resp, map[string]interface{}{"source": "http", "current_context": updatedCtx}); err != nil {
			log.Printf("[DB] Failed to store assistant message: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to persist assistant message"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"response": resp, "thread_id": threadID})
	})
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
