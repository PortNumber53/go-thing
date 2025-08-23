package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sync"
	"strings"
	"syscall"
	"time"
	"regexp"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/rand"
	"encoding/hex"
	"strconv"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/slack-go/slack"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/google/go-github/v66/github"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/time/rate"
	"gopkg.in/ini.v1"

	toolsrv "go-thing/tools"
	logging "go-thing/internal/logging"
	"go-thing/db"
	"go-thing/internal/config"
	"go-thing/utility"

)


// slackViewInfo contains information about a Slack view, such as its hash.
type slackViewInfo struct {
    Hash string `json:"hash"`
}

// slackAppHomeOpenedEvent represents the structure of a Slack app_home_opened event.
type slackAppHomeOpenedEvent struct {
    User string        `json:"user"`
    Tab  string        `json:"tab"`
    View *slackViewInfo `json:"view"`
}

// ToolResponse represents a response from tool execution
type ToolResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

// newCSRFToken generates a random token (hex) for CSRF protection
func newCSRFToken() (string, error) {
    b := make([]byte, 32)
    if _, err := rand.Read(b); err != nil {
        return "", err
    }
    return hex.EncodeToString(b), nil
}

// setCSRFCookie sets the CSRF cookie. We also return the token to the client via JSON from /csrf
func setCSRFCookie(c *gin.Context, token string) {
    ck := &http.Cookie{
        Name:     "csrf_token",
        Value:    token,
        Path:     "/",
        // HttpOnly true is acceptable because clients obtain the token from GET /csrf response body
        HttpOnly: true,
        SameSite: http.SameSiteStrictMode,
        // Session cookie is fine; rotate by calling /csrf as needed
    }
    if isSecureRequest(c) { ck.Secure = true }
    http.SetCookie(c.Writer, ck)
}

// validateCSRF verifies the Origin/Referer (if present) and double-submit cookie/header token
func validateCSRF(c *gin.Context) bool {
    // --- Origin allowlist or same-origin check ---
    origin := strings.TrimSpace(c.Request.Header.Get("Origin"))
    if origin != "" {
        // Lazy-load ALLOWED_ORIGINS from config once
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
                log.Printf("[CSRF] failed to load config for allowed origins: %v. Falling back to same-origin policy.", err)
            }
        })
        if len(allowedOrigins) > 0 {
            if _, ok := allowedOrigins[origin]; !ok {
                log.Printf("[CSRF] reject: origin not in allowlist: origin=%q", origin)
                return false
            }
            log.Printf("[CSRF] origin allowed via allowlist: %s", origin)
        } else {
            scheme := "http"
            if isSecureRequest(c) {
                scheme = "https"
            }
            sameOrigin := fmt.Sprintf("%s://%s", scheme, c.Request.Host)
            if !strings.EqualFold(origin, sameOrigin) {
                log.Printf("[CSRF] reject: origin mismatch: origin=%q sameOrigin=%q", origin, sameOrigin)
                return false
            }
            log.Printf("[CSRF] origin allowed via same-origin: %s", origin)
        }
    }

    // --- Double submit: header must equal cookie ---
    headerTok := strings.TrimSpace(c.Request.Header.Get("X-CSRF-Token"))
    if headerTok == "" {
        log.Printf("[CSRF] reject: missing X-CSRF-Token header")
        return false
    }
    ck, err := c.Request.Cookie("csrf_token")
    if err != nil || ck == nil || strings.TrimSpace(ck.Value) == "" {
        log.Printf("[CSRF] reject: missing csrf_token cookie (err=%v)", err)
        return false
    }
    if !hmac.Equal([]byte(headerTok), []byte(strings.TrimSpace(ck.Value))) {
        log.Printf("[CSRF] reject: token mismatch (header vs cookie)")
        return false
    }
    log.Printf("[CSRF] passed: origin and token validated")
    return true
}

// hmacSha256 computes the GitHub signature header value for the given secret and body.
// Returns the string in the format "sha256=<hex>" to compare against X-Hub-Signature-256.
func hmacSha256(secret string, body []byte) string {
    mac := hmac.New(sha256.New, []byte(secret))
    mac.Write(body)
    sum := mac.Sum(nil)
    return "sha256=" + hex.EncodeToString(sum)
}

// hmacEqual performs a constant-time comparison between the received signature header
// and the expected value. Comparison is case-insensitive for hex digits.
func hmacEqual(gotHeader, expected string) bool {
    // Normalize to lowercase and trim spaces
    g := strings.ToLower(strings.TrimSpace(gotHeader))
    e := strings.ToLower(strings.TrimSpace(expected))
    return hmac.Equal([]byte(g), []byte(e))
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

// isSecureRequest determines if the request is effectively HTTPS (directly or via proxy header)
func isSecureRequest(c *gin.Context) bool {
    return isSecure(c.Request)
}

// setSessionCookie sets an HttpOnly cookie with a signed token for the user id.
func setSessionCookie(c *gin.Context, userID int64) {
    // session expiry
    exp := time.Now().Add(sessionDuration)
    base := fmt.Sprintf("%d.%d", userID, exp.Unix())
    mac := hmac.New(sha256.New, sessionSecret)
    mac.Write([]byte(base))
    sig := hex.EncodeToString(mac.Sum(nil))
    token := base + "." + sig
    cookie := &http.Cookie{
        Name:     "session",
        Value:    token,
        Path:     "/",
        HttpOnly: true,
        SameSite: http.SameSiteLaxMode,
        Expires:  exp,
    }
    // If request came over HTTPS (directly or via proxy header), set Secure
    if isSecureRequest(c) { cookie.Secure = true }
    http.SetCookie(c.Writer, cookie)
}

// clearSessionCookie expires the session cookie
func clearSessionCookie(c *gin.Context) {
    cookie := &http.Cookie{
        Name:     "session",
        Value:    "",
        Path:     "/",
        Expires:  time.Unix(0, 0),
        MaxAge:   -1,
        HttpOnly: true,
        SameSite: http.SameSiteLaxMode,
    }
    // If request came over HTTPS (directly or via proxy header), set Secure
    if isSecureRequest(c) { cookie.Secure = true }
    http.SetCookie(c.Writer, cookie)
}

// parseSession verifies the cookie and returns userID if valid
func parseSession(r *http.Request) (int64, bool) {
    ck, err := r.Cookie("session")
    if err != nil || ck == nil || strings.TrimSpace(ck.Value) == "" {
        return 0, false
    }
    parts := strings.Split(ck.Value, ".")
    if len(parts) != 3 {
        return 0, false
    }
    userStr, expStr, sig := parts[0], parts[1], parts[2]
    base := userStr + "." + expStr
    mac := hmac.New(sha256.New, sessionSecret)
    mac.Write([]byte(base))
    expectedMAC := mac.Sum(nil)
    sigBytes, err := hex.DecodeString(sig)
    if err != nil {
        return 0, false
    }
    if !hmac.Equal(sigBytes, expectedMAC) {
        return 0, false
    }
    // Check expiry
    expUnix, err := strconv.ParseInt(expStr, 10, 64)
    if err != nil || time.Now().After(time.Unix(expUnix, 0)) {
        return 0, false
    }
    uid, err := strconv.ParseInt(userStr, 10, 64)
    if err != nil {
        return 0, false
    }
    return uid, true
}

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
        tok, err := newCSRFToken()
        if err != nil {
            log.Printf("[CSRF] token gen error: %v", err)
            c.JSON(http.StatusInternalServerError, gin.H{"error": "failed"})
            return
        }
        setCSRFCookie(c, tok)
        c.JSON(http.StatusOK, gin.H{"token": tok})
    })
    // Sign up endpoint (CSRF protected)
    r.POST("/signup", func(c *gin.Context) {
        if !validateCSRF(c) {
            c.JSON(http.StatusForbidden, gin.H{"error": "csrf invalid"})
            return
        }
        type signupReq struct {
            Username string `json:"username" binding:"required"`
            Name     string `json:"name" binding:"required"`
            Password string `json:"password" binding:"required"`
        }
        var req signupReq
        if err := c.ShouldBindJSON(&req); err != nil {
            c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
            return
        }
        u := strings.ToLower(strings.TrimSpace(req.Username))
        n := strings.TrimSpace(req.Name)
        p := req.Password
        if u == "" || n == "" || p == "" {
            c.JSON(http.StatusBadRequest, gin.H{"error": "all fields are required"})
            return
        }
        // simple email regex: local@domain.tld
        if !emailRegex().MatchString(u) {
            c.JSON(http.StatusBadRequest, gin.H{"error": "username must be a valid email"})
            return
        }
        if len(p) < 8 {
            c.JSON(http.StatusBadRequest, gin.H{"error": "password must be at least 8 characters"})
            return
        }
        hash, err := bcrypt.GenerateFromPassword([]byte(p), bcrypt.DefaultCost)
        if err != nil {
            log.Printf("[Signup] bcrypt error: %v", err)
            c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to process password"})
            return
        }
        dbc := db.Get()
        if dbc == nil {
            c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database not initialized"})
            return
        }
        // insert user
        const q = `INSERT INTO users (username, name, password_hash) VALUES ($1, $2, $3)`
        if _, err := dbc.Exec(q, u, n, string(hash)); err != nil {
            // Robust duplicate detection: SQLSTATE 23505 unique_violation
            if isUniqueViolation(err) {
                c.JSON(http.StatusConflict, gin.H{"error": "user already exists"})
                return
            }
            // Fallback string check
            le := strings.ToLower(err.Error())
            if strings.Contains(le, "unique") || strings.Contains(le, "duplicate") || strings.Contains(le, "23505") {
                c.JSON(http.StatusConflict, gin.H{"error": "user already exists"})
                return
            }
            log.Printf("[Signup] insert error: %v", err)
            c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create user"})
            return
        }
        c.JSON(http.StatusOK, gin.H{"ok": true})
    })

    // Login endpoint with basic rate limiting and lockouts (CSRF protected)
    r.POST("/login", func(c *gin.Context) {
        if !validateCSRF(c) {
            c.JSON(http.StatusForbidden, gin.H{"error": "csrf invalid"})
            return
        }
        type loginReq struct {
            Username string `json:"username" binding:"required"`
            Password string `json:"password" binding:"required"`
        }
        var req loginReq
        if err := c.ShouldBindJSON(&req); err != nil {
            c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
            return
        }
        // IP-based throttling
        ip := c.ClientIP()
        if !lr.getLimiter(ip).Allow() {
            // Avoid leaking whether the user exists; generic message
            c.Header("Retry-After", "30")
            c.JSON(http.StatusTooManyRequests, gin.H{"error": "too many requests, slow down"})
            return
        }
        u := strings.ToLower(strings.TrimSpace(req.Username))
        p := req.Password
        // Per-user temporary lockout on repeated failures
        if locked, rem := lr.isLocked(u); locked {
            c.Header("Retry-After", fmt.Sprintf("%d", int(rem.Seconds())))
            c.JSON(http.StatusTooManyRequests, gin.H{"error": "account temporarily locked due to failed attempts"})
            return
        }
        dbc := db.Get()
        if dbc == nil {
            c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database not initialized"})
            return
        }
        var id int64
        var username, name, hash string
        const q = `SELECT id, username, name, password_hash FROM users WHERE username = $1`
        err := dbc.QueryRow(q, u).Scan(&id, &username, &name, &hash)
        if err != nil {
            if err == sql.ErrNoRows {
                // To mitigate timing attacks that attempt to enumerate valid usernames,
                // perform a dummy bcrypt comparison even when the user does not exist.
                // This makes the response time similar to the case of an existing user
                // with an incorrect password. See dummyBcryptCompare for details.
                dummyBcryptCompare(p)
                lr.recordFailure(u)
                c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid username or password"})
                return
            }
            log.Printf("[Login] query error: %v", err)
            c.JSON(http.StatusInternalServerError, gin.H{"error": "login failed"})
            return
        }
        if bcrypt.CompareHashAndPassword([]byte(hash), []byte(p)) != nil {
            lr.recordFailure(u)
            c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid username or password"})
            return
        }
        // Success: clear failure state
        lr.recordSuccess(u)
        setSessionCookie(c, id)
        c.JSON(http.StatusOK, gin.H{"ok": true, "user": gin.H{"id": id, "username": username, "name": name}})
    })

    // Logout endpoint (CSRF protected)
    r.POST("/logout", func(c *gin.Context) {
        if !validateCSRF(c) {
            c.JSON(http.StatusForbidden, gin.H{"error": "csrf invalid"})
            return
        }
        clearSessionCookie(c)
        c.JSON(http.StatusOK, gin.H{"ok": true})
    })

    // Current user endpoint
    r.GET("/me", func(c *gin.Context) {
        uid, ok := parseSession(c.Request)
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
                clearSessionCookie(c)
                c.JSON(http.StatusUnauthorized, gin.H{"error": "not logged in"})
                return
            }
            log.Printf("[Me] query error: %v", err)
            c.JSON(http.StatusInternalServerError, gin.H{"error": "failed"})
            return
        }
        c.JSON(http.StatusOK, gin.H{"id": uid, "username": username, "name": name})
    })

    // GitHub direct API caller (CSRF protected)
    r.POST("/github/call", func(c *gin.Context) {
        if !validateCSRF(c) {
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
        if m == "" { m = "GET" }
        p := strings.TrimSpace(req.Path)
        if p == "" {
            c.JSON(http.StatusBadRequest, gin.H{"error": "path is required"})
            return
        }
        q := url.Values{}
        for k, v := range req.Query {
            key := strings.TrimSpace(k)
            if key == "" { continue }
            switch tv := v.(type) {
            case string:
                if tv != "" { q.Set(key, tv) }
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
                if len(parts) > 0 { q.Set(key, strings.Join(parts, ",")) }
            default:
                // fallback to fmt.Sprint
                s := fmt.Sprint(tv)
                if strings.TrimSpace(s) != "" { q.Set(key, s) }
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

    // GitHub webhook endpoint (HMAC-validated)
    r.POST("/webhook/github", func(c *gin.Context) {
        // Read body with a reasonable limit
        c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 1<<20) // 1MB
        body, err := io.ReadAll(c.Request.Body)
        if err != nil {
            log.Printf("[GitHubWebhook] read error: %v", err)
            c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
            return
        }
        // Log basic request metadata (no secrets)
        evt := strings.TrimSpace(c.Request.Header.Get("X-GitHub-Event"))
        delivery := strings.TrimSpace(c.Request.Header.Get("X-GitHub-Delivery"))
        ua := strings.TrimSpace(c.Request.Header.Get("User-Agent"))
        ctype := strings.TrimSpace(c.Request.Header.Get("Content-Type"))
        sigPresent := c.Request.Header.Get("X-Hub-Signature-256") != ""
        clientIP := c.ClientIP()
        qstr := c.Request.URL.RawQuery
        log.Printf("[GitHubWebhook] headers event=%q delivery=%q ua=%q content_type=%q sig256_present=%t ip=%q body_len=%d query=%q", evt, delivery, ua, ctype, sigPresent, clientIP, len(body), qstr)
        // Log the raw body for debugging/analysis (body already limited to 1MB above)
        log.Printf("[GitHubWebhook] raw body: %s", string(body))

        // Try to parse JSON for structured logging (generic map for common fields)
        var payload map[string]interface{}
        if err := json.Unmarshal(body, &payload); err != nil {
            // If not JSON, just log raw (truncated)
            raw := string(body)
            if len(raw) > 512 {
                raw = raw[:512] + "…"
            }
            log.Printf("[GitHubWebhook] non-JSON payload: %s", raw)
            c.JSON(http.StatusOK, gin.H{"ok": true})
            return
        }

        // Validate HMAC signature
        // Prefer INI config [default] GITHUB_WEBHOOK_SECRET; fallback to environment.
        secret := ""
        if cfg, err := utility.LoadConfig(); err == nil && cfg != nil {
            secret = strings.TrimSpace(cfg["GITHUB_WEBHOOK_SECRET"])
        }
        if secret == "" {
            secret = os.Getenv("GITHUB_WEBHOOK_SECRET")
        }
        if secret == "" {
            log.Printf("[GitHubWebhook] reject: missing GITHUB_WEBHOOK_SECRET")
            c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
            return
        }
        signature := c.Request.Header.Get("X-Hub-Signature-256")
        if signature == "" {
            log.Printf("[GitHubWebhook] reject: missing X-Hub-Signature-256")
            c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
            return
        }
        expected := hmacSha256(secret, body)
        if !hmacEqual(signature, expected) {
            log.Printf("[GitHubWebhook] reject: invalid X-Hub-Signature-256")
            c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
            return
        }

        // Extract common fields for visibility
        action := ""
        if v, ok := payload["action"].(string); ok { action = v }
        var repoName, repoFull, repoID string
        if r, ok := payload["repository"].(map[string]interface{}); ok {
            if n, ok := r["name"].(string); ok { repoName = n }
            if fn, ok := r["full_name"].(string); ok { repoFull = fn }
            switch idv := r["id"].(type) {
            case float64:
                repoID = strconv.FormatInt(int64(idv), 10)
            case json.Number:
                repoID = idv.String()
            case string:
                repoID = idv
            }
        }
        sender := ""
        if s, ok := payload["sender"].(map[string]interface{}); ok {
            if lg, ok := s["login"].(string); ok { sender = lg }
        }
        installation := ""
        if ins, ok := payload["installation"].(map[string]interface{}); ok {
            switch idv := ins["id"].(type) {
            case float64:
                installation = strconv.FormatInt(int64(idv), 10)
            case json.Number:
                installation = idv.String()
            case string:
                installation = idv
            }
        }
        ref := ""
        if v, ok := payload["ref"].(string); ok { ref = v }
        before := ""
        if v, ok := payload["before"].(string); ok { before = v }
        after := ""
        if v, ok := payload["after"].(string); ok { after = v }
        pusher := ""
        if p, ok := payload["pusher"].(map[string]interface{}); ok {
            if nm, ok := p["name"].(string); ok { pusher = nm }
        }
        log.Printf("[GitHubWebhook] parsed action=%q repo=%q full=%q id=%q sender=%q installation=%q ref=%q before=%q after=%q pusher=%q", action, repoName, repoFull, repoID, sender, installation, ref, before, after, pusher)

        // Build a concise summary depending on event type (log-only)
        eventHeader := strings.TrimSpace(c.Request.Header.Get("X-GitHub-Event"))
        deliveryID := strings.TrimSpace(c.Request.Header.Get("X-GitHub-Delivery"))
        summary := eventHeader + ": " + action
        // Parse typed webhook once for safer access to event-specific fields
        parsedEvt, parseErr := github.ParseWebHook(eventHeader, body)
        if parseErr != nil {
            log.Printf("[GitHubWebhook] ParseWebHook error for type=%q: %v", eventHeader, parseErr)
        }
        // Issues-specific enrichment
        if eventHeader == "issues" {
            if iss, ok := payload["issue"].(map[string]interface{}); ok {
                num := ""
                switch nv := iss["number"].(type) {
                case float64:
                    num = strconv.FormatInt(int64(nv), 10)
                case json.Number:
                    num = nv.String()
                case string:
                    num = nv
                }
                issueTitle := ""
                if t, ok := iss["title"].(string); ok { issueTitle = t }
                issueBody := ""
                if b, ok := iss["body"].(string); ok { issueBody = b }
                // Truncate description for logging to avoid huge lines
                issueBodyLogged := issueBody
                if len(issueBodyLogged) > 512 {
                    issueBodyLogged = issueBodyLogged[:512] + "…"
                }
                issueTimeline := ""
                if tl, ok := iss["timeline_url"].(string); ok { issueTimeline = tl }
                issueUser := ""
                if u, ok := iss["user"].(map[string]interface{}); ok {
                    if lg, ok := u["login"].(string); ok { issueUser = lg }
                    if nm, ok := u["name"].(string); ok && issueUser == "" { issueUser = nm }
                }
                issueState := ""
                if st, ok := iss["state"].(string); ok { issueState = st }
                // Labels extraction
                var labelNames []string
                if lbs, ok := iss["labels"].([]interface{}); ok {
                    for _, lv := range lbs {
                        if lm, ok := lv.(map[string]interface{}); ok {
                            if ln, ok := lm["name"].(string); ok && strings.TrimSpace(ln) != "" {
                                labelNames = append(labelNames, ln)
                            }
                        }
                    }
                }
                reactionsTotal := 0
                // Optional per-reaction counts (if present)
                var rxPlus1, rxMinus1, rxLaugh, rxHooray, rxConfused, rxHeart, rxRocket, rxEyes int
                if rx, ok := iss["reactions"].(map[string]interface{}); ok {
                    switch tv := rx["total_count"].(type) {
                    case float64:
                        reactionsTotal = int(tv)
                    case json.Number:
                        if iv, err := strconv.Atoi(tv.String()); err == nil { reactionsTotal = iv }
                    case string:
                        if iv, err := strconv.Atoi(tv); err == nil { reactionsTotal = iv }
                    }
                    // Read individual counts if present via map to reduce repetition
                    reactionMap := map[string]*int{
                        "+1":       &rxPlus1,
                        "-1":       &rxMinus1,
                        "laugh":    &rxLaugh,
                        "hooray":   &rxHooray,
                        "confused": &rxConfused,
                        "heart":    &rxHeart,
                        "rocket":   &rxRocket,
                        "eyes":     &rxEyes,
                    }
                    for name, ptr := range reactionMap {
                        if v, ok := rx[name].(float64); ok {
                            *ptr = int(v)
                        }
                    }
                }
                html := ""
                if h, ok := iss["html_url"].(string); ok { html = h }
                if repoFull != "" && num != "" {
                    summary = "issue #" + num + " " + action + " — " + repoFull + ": " + issueTitle
                    if html != "" { summary += " (" + html + ")" }
                }
                // Log extracted issue fields succinctly
                log.Printf("[GitHubWebhook] issue fields action=%q repo=%q number=%q title=%q description=%q state=%q labels=%q reactions_total=%d (+1=%d,-1=%d,laugh=%d,hooray=%d,confused=%d,heart=%d,rocket=%d,eyes=%d) timeline_url=%q user=%q", action, repoFull, num, issueTitle, issueBodyLogged, issueState, strings.Join(labelNames, ","), reactionsTotal, rxPlus1, rxMinus1, rxLaugh, rxHooray, rxConfused, rxHeart, rxRocket, rxEyes, issueTimeline, issueUser)
            }
        }
        // Pull Request-specific enrichment (typed)
        if eventHeader == "pull_request" {
            if prEvt, ok := parsedEvt.(*github.PullRequestEvent); ok && prEvt != nil {
                pr := prEvt.GetPullRequest()
                number := pr.GetNumber()
                title := pr.GetTitle()
                body := pr.GetBody()
                if len(body) > 512 { body = body[:512] + "…" }
                state := pr.GetState()
                draft := pr.GetDraft()
                user := ""
                if pr.User != nil { user = pr.User.GetLogin() }
                htmlURL := pr.GetHTMLURL()
                headRef, headSHA := "", ""
                if pr.Head != nil { headRef = pr.Head.GetRef(); headSHA = pr.Head.GetSHA() }
                baseRef := ""
                if pr.Base != nil { baseRef = pr.Base.GetRef() }
                commits := pr.GetCommits()
                additions := pr.GetAdditions()
                deletions := pr.GetDeletions()
                changed := pr.GetChangedFiles()
                merged := pr.GetMerged()
                mergeableState := pr.GetMergeableState()
                mergeCommitSHA := pr.GetMergeCommitSHA()
                log.Printf("[GitHubWebhook] pr fields action=%q repo=%q number=%d title=%q state=%q draft=%t user=%q url=%q head_ref=%q head_sha=%q base_ref=%q merged=%t mergeable_state=%q merge_commit_sha=%q", action, repoFull, number, title, state, draft, user, htmlURL, headRef, headSHA, baseRef, merged, mergeableState, mergeCommitSHA)
                log.Printf("[GitHubWebhook] pr stats commits=%d additions=%d deletions=%d changed_files=%d body=%q", commits, additions, deletions, changed, body)
            }
        }
        // Push-specific enrichment (typed): detect newly added files
        if eventHeader == "push" {
            if pushEvt, ok := parsedEvt.(*github.PushEvent); ok && pushEvt != nil {
                createdFlag := false
                if pushEvt.Created != nil { createdFlag = *pushEvt.Created }
                // Aggregate added files across commits
                totalAdded := 0
                var addedSamples []string
                for _, cm := range pushEvt.Commits {
                    for _, f := range cm.Added {
                        totalAdded++
                        if len(addedSamples) < 10 { addedSamples = append(addedSamples, f) }
                    }
                }
                // Head commit details
                headID, headMsg, headAuthor := "", "", ""
                if pushEvt.HeadCommit != nil {
                    if pushEvt.HeadCommit.ID != nil { headID = *pushEvt.HeadCommit.ID }
                    if pushEvt.HeadCommit.Message != nil { headMsg = *pushEvt.HeadCommit.Message }
                    if pushEvt.HeadCommit.Author != nil && pushEvt.HeadCommit.Author.Name != nil {
                        headAuthor = *pushEvt.HeadCommit.Author.Name
                    }
                    for _, f := range pushEvt.HeadCommit.Added {
                        totalAdded++
                        if len(addedSamples) < 10 { addedSamples = append(addedSamples, f) }
                    }
                }
                // Truncate message for log safety
                if len(headMsg) > 200 { headMsg = headMsg[:200] + "…" }
                // Prefer typed ref if available
                refVal := ref
                if pushEvt.Ref != nil { refVal = pushEvt.GetRef() }
                log.Printf("[GitHubWebhook] push files created=%t branch=%q total_added=%d head_commit=%q author=%q msg=%q", createdFlag, refVal, totalAdded, headID, headAuthor, headMsg)
                if totalAdded > 0 {
                    log.Printf("[GitHubWebhook] push added samples (%d of %d): %q", len(addedSamples), totalAdded, strings.Join(addedSamples, ","))
                }
            }
        }
        // Log final summary of extracted data (no persistence)
        log.Printf("[GitHubWebhook] summary delivery=%q event=%q action=%q repo_full=%q repo_id=%q sender=%q issue_ref=%q before=%q after=%q", deliveryID, eventHeader, action, repoFull, repoID, sender, ref, before, after)

        // AI follow-up loop: handle PR reviews/comments authored by gemini-code-assist bot
        if (eventHeader == "pull_request_review" || eventHeader == "pull_request_review_comment") && strings.EqualFold(sender, "gemini-code-assist[bot]") {
            // Extract PR context
            prNumber := ""
            headRef, headSHA := "", ""
            if pr, ok := payload["pull_request"].(map[string]interface{}); ok {
                switch v := pr["number"].(type) {
                case float64:
                    prNumber = strconv.FormatInt(int64(v), 10)
                case json.Number:
                    prNumber = v.String()
                case string:
                    prNumber = v
                }
                if h, ok := pr["head"].(map[string]interface{}); ok {
                    if v, ok := h["ref"].(string); ok { headRef = v }
                    if v, ok := h["sha"].(string); ok { headSHA = v }
                }
            } else {
                // Fallbacks if structure differs
                switch v := payload["number"].(type) {
                case float64:
                    prNumber = strconv.FormatInt(int64(v), 10)
                case json.Number:
                    prNumber = v.String()
                case string:
                    prNumber = v
                }
            }

            // Extract review/comment text and any inline context
            commentBody := ""
            extraContext := ""
            reviewID := ""
            commentID := ""
            if eventHeader == "pull_request_review" {
                if rv, ok := payload["review"].(map[string]interface{}); ok {
                    if b, ok := rv["body"].(string); ok { commentBody = b }
                    switch v := rv["id"].(type) {
                    case float64:
                        reviewID = strconv.FormatInt(int64(v), 10)
                    case json.Number:
                        reviewID = v.String()
                    case string:
                        reviewID = v
                    }
                }
            } else if eventHeader == "pull_request_review_comment" {
                if cm, ok := payload["comment"].(map[string]interface{}); ok {
                    if b, ok := cm["body"].(string); ok { commentBody = b }
                    switch v := cm["id"].(type) {
                    case float64:
                        commentID = strconv.FormatInt(int64(v), 10)
                    case json.Number:
                        commentID = v.String()
                    case string:
                        commentID = v
                    }
                    // Include file/line and diff hunk when available for better grounding
                    path, _ := cm["path"].(string)
                    side, _ := cm["side"].(string)
                    // line can be number but often float64 in generic JSON
                    lineStr := ""
                    if lv, ok := cm["line"].(float64); ok { lineStr = strconv.FormatInt(int64(lv), 10) }
                    if hv, ok := cm["diff_hunk"].(string); ok {
                        extraContext = fmt.Sprintf("\n\n[Inline Context]\nFile: %s\nSide: %s Line: %s\nDiff Hunk:\n%s\n", path, side, lineStr, hv)
                    } else if path != "" || side != "" || lineStr != "" {
                        extraContext = fmt.Sprintf("\n\n[Inline Context]\nFile: %s\nSide: %s Line: %s\n", path, side, lineStr)
                    }
                }
            }

            // Build the task for the internal agent loop. Instruct it to output ALL_DONE! when no more actionable suggestions remain.
            task := fmt.Sprintf(
                "Automated follow-up for GitHub PR review.\nRepository: %s\nPR #%s\nHead: %s @ %s\nEvent: %s by gemini-code-assist bot.\n\nInstruction: Apply the review suggestions below to the codebase in the least-intrusive way. When you finish and there are no remaining actionable suggestions from gemini-code-assist on this PR, respond with EXACTLY: ALL_DONE!\n\nIf you determine that you CANNOT complete the requested changes (e.g., missing context or files, insufficient permissions, conflicting instructions, external dependency, or repeated failures), STOP and respond with EXACTLY: GIVING UP: <reason> (replace <reason> with a concise, specific explanation).\n\nReview context:\n%s%s",
                repoFull, prNumber, headRef, headSHA, eventHeader, strings.TrimSpace(commentBody), extraContext,
            )

            // Run asynchronously so webhook responds fast. Use background context with timeout to avoid request context cancellation.
            go func(t string) {
                start := time.Now()
                timeout := 3 * time.Minute
                ctx, cancel := context.WithTimeout(context.Background(), timeout)
                defer cancel()
                log.Printf("[GitHubWebhook][AI] start repo=%q pr=%q head_ref=%q head_sha=%q event=%q review_id=%q comment_id=%q task_len=%d comment_len=%d extra_ctx=%t timeout=%s",
                    repoFull, prNumber, headRef, headSHA, eventHeader, reviewID, commentID, len(t), len(strings.TrimSpace(commentBody)), extraContext != "", timeout)

                resp, _, err := utility.GeminiAPIHandler(ctx, t, nil)
                if err != nil {
                    // Highlight common cancellation/timeout causes
                    msg := err.Error()
                    if strings.Contains(msg, "context canceled") {
                        log.Printf("[GitHubWebhook][AI] error: context canceled (likely timeout/cancel) err=%v elapsed=%s", err, time.Since(start))
                    } else if strings.Contains(msg, "deadline exceeded") {
                        log.Printf("[GitHubWebhook][AI] error: deadline exceeded err=%v elapsed=%s", err, time.Since(start))
                    } else {
                        log.Printf("[GitHubWebhook][AI] error: %v elapsed=%s", err, time.Since(start))
                    }
                    return
                }
                // Log only; future: optionally post a PR comment/status with result
                dur := time.Since(start)
                allDone := strings.Contains(resp, "ALL_DONE!")
                if len(resp) > 512 {
                    log.Printf("[GitHubWebhook][AI] success elapsed=%s all_done=%t result: %.512s…", dur, allDone, resp)
                } else {
                    log.Printf("[GitHubWebhook][AI] success elapsed=%s all_done=%t result: %s", dur, allDone, resp)
                }
            }(task)
        }

        c.JSON(http.StatusOK, gin.H{"ok": true})
    })

    // Jira webhook endpoint (no CSRF; external origin). Optional token validation via config JIRA_WEBHOOK_TOKEN.
    r.POST("/webhook/jira", func(c *gin.Context) {
        // Optional shared token check
        var expectedToken string
        if cfg, err := utility.LoadConfig(); err == nil && cfg != nil {
            expectedToken = strings.TrimSpace(cfg["JIRA_WEBHOOK_TOKEN"])
        }
        if expectedToken != "" {
            got := strings.TrimSpace(c.Request.Header.Get("X-Webhook-Token"))
            if got == "" || got != expectedToken {
                log.Printf("[JiraWebhook] reject: missing or invalid X-Webhook-Token")
                c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
                return
            }
        }

        // Read body with a reasonable limit
        c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 1<<20) // 1MB
        body, err := io.ReadAll(c.Request.Body)
        if err != nil {
            log.Printf("[JiraWebhook] read error: %v", err)
            c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
            return
        }
        // Log the raw body for debugging/analysis (body already limited to 1MB above)
        log.Printf("[JiraWebhook] raw body: %s", string(body))

        // Try to parse JSON for structured logging
        var payload map[string]interface{}
        if err := json.Unmarshal(body, &payload); err != nil {
            // If not JSON, just log raw (truncated)
            raw := string(body)
            if len(raw) > 512 {
                raw = raw[:512] + "…"
            }
            log.Printf("[JiraWebhook] non-JSON payload: %s", raw)
            c.JSON(http.StatusOK, gin.H{"ok": true})
            return
        }

        // Extract some common Jira fields for visibility
        event := ""
        if v, ok := payload["webhookEvent"].(string); ok {
            event = v
        } else if v, ok := payload["issue_event_type_name"].(string); ok {
            event = v
        }
        issueKey := ""
        issueID := ""
        fields := map[string]interface{}{}
        if issue, ok := payload["issue"].(map[string]interface{}); ok {
            if k, ok := issue["key"].(string); ok {
                issueKey = k
            }
            switch idv := issue["id"].(type) {
            case string:
                issueID = idv
            case float64:
                issueID = strconv.FormatInt(int64(idv), 10)
            }
            if f, ok := issue["fields"].(map[string]interface{}); ok {
                fields = f
            }
        }
        // Fallback to top-level for Jira payloads that provide fields/id/key at root
        if issueKey == "" {
            if k, ok := payload["key"].(string); ok { issueKey = k }
        }
        if issueID == "" {
            switch idv := payload["id"].(type) {
            case string:
                issueID = idv
            case float64:
                issueID = strconv.FormatInt(int64(idv), 10)
            case json.Number:
                if iv, err := idv.Int64(); err == nil { issueID = strconv.FormatInt(iv, 10) }
            }
        }
        if len(fields) == 0 {
            if f, ok := payload["fields"].(map[string]interface{}); ok {
                fields = f
            }
        }
        log.Printf("[JiraWebhook] event=%q issue=%q id=%q", event, issueKey, issueID)

        // Build system prompt for AI Agent using requested fields
        projectKey := ""
        if p, ok := fields["project"].(map[string]interface{}); ok {
            if k, ok := p["key"].(string); ok { projectKey = k }
        }
        if projectKey == "" {
            if p, ok := payload["project"].(map[string]interface{}); ok {
                if k, ok := p["key"].(string); ok { projectKey = k }
            }
        }
        var labels []string
        if la, ok := fields["labels"].([]interface{}); ok {
            for _, lv := range la {
                if s, ok := lv.(string); ok && s != "" {
                    // Normalize strings that look like serialized arrays e.g., "['test']"
                    trimmed := strings.TrimSpace(s)
                    if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
                        inner := strings.Trim(trimmed, "[]")
                        parts := strings.Split(inner, ",")
                        for _, p := range parts {
                            v := strings.TrimSpace(p)
                            v = strings.Trim(v, "'\"")
                            if v != "" { labels = append(labels, v) }
                        }
                        continue
                    }
                    labels = append(labels, trimmed)
                }
            }
        }
        statusName := ""
        if st, ok := fields["status"].(map[string]interface{}); ok {
            if n, ok := st["name"].(string); ok { statusName = n }
        }
        if statusName == "" {
            if st, ok := payload["status"].(map[string]interface{}); ok {
                if n, ok := st["name"].(string); ok { statusName = n }
            } else if s, ok := payload["status"].(string); ok { statusName = s }
        }
        summary := ""
        if s, ok := fields["summary"].(string); ok { summary = s }
        // Some webhooks may not include fields.summary; try top-level fallback if present
        if summary == "" {
            if s, ok := payload["summary"].(string); ok { summary = s }
        }
        // Optional description, if available; included as extra context
        description := ""
        if s, ok := fields["description"].(string); ok { description = s }
        if description == "" {
            if s, ok := payload["description"].(string); ok { description = s }
        }
        // comments
        var comments []string
        if cmt, ok := fields["comment"].(map[string]interface{}); ok {
            if arr, ok := cmt["comments"].([]interface{}); ok {
                for _, cv := range arr {
                    if cm, ok := cv.(map[string]interface{}); ok {
                        // Jira v2/v3 comment body may be string or structured; try common keys
                        if b, ok := cm["body"].(string); ok && b != "" {
                            comments = append(comments, b)
                        } else if cbody, ok := cm["renderedBody"].(string); ok && cbody != "" {
                            comments = append(comments, cbody)
                        }
                    }
                }
            }
        }
        // Fallback for comment events which place the comment at the top-level
        if len(comments) == 0 {
            if cm, ok := payload["comment"].(map[string]interface{}); ok {
                if b, ok := cm["body"].(string); ok && b != "" { comments = append(comments, b) }
                if rb, ok := cm["renderedBody"].(string); ok && rb != "" { comments = append(comments, rb) }
            }
        }
        // Fallback labels at top-level if fields missing
        if len(labels) == 0 {
            if la, ok := payload["labels"].([]interface{}); ok {
                for _, lv := range la {
                    if s, ok := lv.(string); ok && s != "" { labels = append(labels, s) }
                }
            }
        }

        // Compose system prompt
        prompt := strings.Builder{}
        prompt.WriteString("You are an AI project assistant that evaluates Jira issues for clarity and completeness, and plans execution.\n")
        prompt.WriteString("Input fields (from Jira webhook):\n")
        prompt.WriteString(fmt.Sprintf("- project_key: %s\n", projectKey))
        prompt.WriteString(fmt.Sprintf("- issue_key: %s\n", issueKey))
        prompt.WriteString(fmt.Sprintf("- issue_id: %s\n", issueID))
        prompt.WriteString(fmt.Sprintf("- status: %s\n", statusName))
        if len(labels) > 0 {
            prompt.WriteString(fmt.Sprintf("- labels: %s\n", strings.Join(labels, ", ")))
        } else {
            prompt.WriteString("- labels: (none)\n")
        }
        prompt.WriteString(fmt.Sprintf("- summary: %s\n", summary))
        if strings.TrimSpace(description) != "" {
            prompt.WriteString("- description: |\n")
            for _, line := range strings.Split(description, "\n") {
                prompt.WriteString("  ")
                prompt.WriteString(line)
                prompt.WriteString("\n")
            }
        }
        if len(comments) > 0 {
            prompt.WriteString("- comments:\n")
            for _, cmt := range comments {
                // ensure multi-line comments are indented for readability
                lines := strings.Split(cmt, "\n")
                for _, line := range lines {
                    prompt.WriteString("  - ")
                    prompt.WriteString(line)
                    prompt.WriteString("\n")
                }
            }
        } else {
            prompt.WriteString("- comments: (none)\n")
        }
        prompt.WriteString("\nTask:\n")
        prompt.WriteString("1) Analyze whether the provided information is sufficient to complete the task described by the summary.\n")
        prompt.WriteString("2) If information is missing or unclear, output a list of comments to request EACH missing piece of information (one comment per missing/unclear item).\n")
        prompt.WriteString("3) If the summary is sufficiently clear and complete, output a list of concrete subtasks that, if executed, will complete the task.\n")
        prompt.WriteString("4) Your output must be in Markdown with the following schema: either a '### Missing Information Requests' section with bullet points, OR a '### Subtasks' section with bullet points. Do not include both.\n")
        prompt.WriteString("\n")
        prompt.WriteString("Tooling you can use (call by setting tool and args in your JSON response):\n")
        prompt.WriteString("- jira_add_comment(issueIdOrKey: string, body: string|AtlassianDoc) — add a comment to the Jira issue.\n")
        prompt.WriteString("\n")
        prompt.WriteString("After your analysis, PLAN concrete tool usage so the workflow continues automatically:\n")
        prompt.WriteString("- If you produce Missing Information Requests: set tool=\"jira_add_comment\" with args { issueIdOrKey: '"+issueKey+"', body: the Markdown list of questions } to post the questions to the issue.\n")
        prompt.WriteString("- If you produce Subtasks: set tool=\"jira_add_comment\" with args { issueIdOrKey: '"+issueKey+"', body: the Markdown list under '### Subtasks' } to post the plan to the issue.\n")
        prompt.WriteString("\n")
        prompt.WriteString("Response schema (JSON object as code block) expected by the agent:\n")
        prompt.WriteString("{\n  \"current_context\": [ ... ],\n  \"tool\": \"<optional tool name, e.g., jira_add_comment>\",\n  \"args\": { <tool args if any> },\n  \"final\": \"<concise user-facing summary in Markdown>\"\n}\n")

        systemPrompt := prompt.String()
        log.Printf("[JiraWebhook] system prompt (issue %s):\n%s", issueKey, systemPrompt)

        // Kick off background processing to avoid delaying Jira response
        go func(promptStr, issueKey string) {
            defer func() {
                if r := recover(); r != nil {
                    log.Printf("[JiraWebhook][goroutine] recovered from panic: %v", r)
                }
            }()
            threadID, err := getOrCreateAnyThread()
            if err != nil {
                log.Printf("[JiraWebhook] thread ensure error: %v", err)
                return
            }
            if err := utility.StoreMessage(threadID, "user", promptStr, map[string]interface{}{"source": "jira", "issue_key": issueKey}); err != nil {
                log.Printf("[JiraWebhook][DB] store user message error: %v", err)
                return
            }
            // Temporarily disable current_context while debugging comment tool
            // Use a background context with timeout so it isn't canceled when the HTTP request finishes
            ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
            defer cancel()
            resp, _, err := utility.GeminiAPIHandler(ctx, promptStr, nil)
            if err != nil {
                log.Printf("[JiraWebhook][Gemini] error: %v", err)
                return
            }
            if strings.TrimSpace(resp) == "" {
                resp = "**No response available.**"
            }
            if err := utility.StoreMessage(threadID, "assistant", resp, map[string]interface{}{"source": "jira", "issue_key": issueKey}); err != nil {
                log.Printf("[JiraWebhook][DB] store assistant message error: %v", err)
                return
            }
        }(systemPrompt, issueKey)

        // Respond immediately to Jira with empty 200
        c.Status(http.StatusOK)
    })
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
	r.POST("/webhook/slack", func(c *gin.Context) {
		body, err := io.ReadAll(c.Request.Body)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to read body"})
			return
		}
		var ev slack.Event
		if err := json.Unmarshal(body, &ev); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid event"})
			return
		}
		if ev.Type == "url_verification" {
			var ch struct {
				Challenge string `json:"challenge"`
			}
			if err := json.Unmarshal(body, &ch); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid challenge"})
				return
			}
			c.JSON(http.StatusOK, gin.H{"challenge": ch.Challenge})
			return
		}
		if ev.Type == "event_callback" {
			// Envelope contains the inner event as raw JSON so we can branch by type
			var envelope struct {
				Event json.RawMessage `json:"event"`
			}
			if err := json.Unmarshal(body, &envelope); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid callback"})
				return
			}
			// Detect inner event type
			var meta struct{ Type string `json:"type"` }
			if err := json.Unmarshal(envelope.Event, &meta); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid inner event"})
				return
			}
			switch meta.Type {
			case "message":
				var msg slack.MessageEvent
				if err := json.Unmarshal(envelope.Event, &msg); err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid message event"})
					return
				}
				utility.HandleSlackMessage(c, &msg, getOrCreateAnyThread, utility.GeminiAPIHandler)
				return
			case "app_home_opened":
				var ah slackAppHomeOpenedEvent
				if err := json.Unmarshal(envelope.Event, &ah); err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid app_home_opened event"})
					return
				}
				if strings.TrimSpace(ah.User) == "" {
					c.JSON(http.StatusBadRequest, gin.H{"error": "Missing user in app_home_opened"})
					return
				}
				hash := ""
				if ah.View != nil {
					hash = strings.TrimSpace(ah.View.Hash)
				}
				if err := utility.PublishSlackHomeTab(c.Request.Context(), ah.User, hash); err != nil {
					log.Printf("[Slack Home] publish failed: %v", err)
				}
				c.JSON(http.StatusOK, gin.H{"status": "home updated"})
				return
			default:
				// Ignore other inner events for now
				c.JSON(http.StatusOK, gin.H{"status": "event ignored", "event_type": meta.Type})
				return
			}
		}
		c.JSON(http.StatusOK, gin.H{"status": "event received"})
	})
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
