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

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/slack-go/slack"
	"github.com/jackc/pgx/v5/pgconn"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/ini.v1"

	toolsrv "go-thing/tools"
	logging "go-thing/internal/logging"
	"go-thing/db"
	"go-thing/internal/config"
	"go-thing/utility"

)

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
	if err != nil && err != sql.ErrNoRows {
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
	// NOTE: r.TLS indicates whether THIS hop used TLS. When running behind a
	// reverse proxy that terminates TLS, r.TLS will be nil even if the client
	// connected via HTTPS. In that case the Origin header may be "https://…" but
	// the computed sameOrigin below would be "http://…", causing a false
	// mismatch. Consider honoring standard proxy headers (e.g. X-Forwarded-Proto)
	// or configuring Gin trusted proxies so scheme detection is proxy-aware.
	// Example (pseudo):
	//   proto := r.Header.Get("X-Forwarded-Proto")
	//   if proto == "https" { scheme = "https" }
scheme := "http"
if r.Header.Get("X-Forwarded-Proto") == "https" || r.TLS != nil {
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

	// Gin router and routes
	r := gin.Default()
	r.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok", "service": "go-thing agent API"})
	})
    // Sign up endpoint
    r.POST("/signup", func(c *gin.Context) {
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
        u := strings.TrimSpace(req.Username)
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
			var cb struct {
				Event slack.MessageEvent `json:"event"`
			}
			if err := json.Unmarshal(body, &cb); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid callback"})
				return
			}
			utility.HandleSlackMessage(c, &cb.Event, getOrCreateAnyThread, utility.GeminiAPIHandler)
			return
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
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = apiServer.Shutdown(ctx)
	_ = toolServer.Shutdown(ctx)
	// Close shell sessions gracefully (single lock via CloseAll)
	toolsrv.GetShellBroker().CloseAll()
}
