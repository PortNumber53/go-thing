package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"go-thing/db"
	"go-thing/internal/config"

	"github.com/gin-gonic/gin"
	"github.com/slack-go/slack"
	"google.golang.org/genai"
	"gopkg.in/ini.v1"

	toolsrv "go-thing/tools"
)

var (
	configOnce       sync.Once
	configData       map[string]string
	configErr        error
	dockerAutoRemove bool
)

// Precompiled regex to collapse accidental double slashes while avoiding schemes like http://
var doubleSlashRegex = regexp.MustCompile(`([^:])//+`)

// ToolResponse represents a response from tool execution
type ToolResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

// getChrootDir returns the CHROOT_DIR from config if set, else empty string.
func getChrootDir() string {
	cfg, err := loadConfig()
	if err != nil {
		return ""
	}
	return strings.TrimRight(strings.TrimSpace(cfg["CHROOT_DIR"]), "/")
}

// normalizePathInText rewrites host chroot paths to their canonical in-sandbox alias (/app)
func normalizePathInText(s string) string {
	ch := getChrootDir()
	if ch == "" {
		return s
	}
	// Replace any occurrence of the absolute chroot path with /app
	s2 := strings.ReplaceAll(s, ch, "/app")
	// Collapse any accidental double slashes but avoid collapsing after a scheme (e.g., http://)
	s2 = doubleSlashRegex.ReplaceAllString(s2, "$1/")
	return s2
}

// sanitizeContextFacts rewrites host-specific paths to canonical sandbox paths and dedupes.
func sanitizeContextFacts(in []string) []string {
	if len(in) == 0 {
		return in
	}
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, item := range in {
		trimmed := strings.TrimSpace(item)
		if trimmed == "" {
			continue
		}
		norm := normalizePathInText(trimmed)
		if !seen[norm] {
			seen[norm] = true
			out = append(out, norm)
		}
	}
	return out
}

// getLastContextForThread loads the most recent message metadata for a thread and extracts current_context
func getLastContextForThread(threadID int64) ([]string, error) {
	dbc := db.Get()
	if dbc == nil {
		return nil, fmt.Errorf("db not initialized")
	}
	// Fetch the most recent message that actually has a non-empty current_context
	// Using JSONB operators to ensure we don't pick up the latest user message w/o context
	var metaBytes []byte
	err := dbc.QueryRow(
		`SELECT metadata FROM messages
         WHERE thread_id=$1
           AND role = 'assistant'
           AND metadata ? 'current_context'
           AND jsonb_typeof(metadata->'current_context') = 'array'
           AND jsonb_array_length(metadata->'current_context') > 0
         ORDER BY id DESC LIMIT 1`, threadID,
	).Scan(&metaBytes)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	var meta struct {
		CurrentContext []string `json:"current_context"`
	}
	if err := json.Unmarshal(metaBytes, &meta); err != nil {
		return nil, err
	}
	if meta.CurrentContext != nil {
		// The caller will sanitize the context (trim/remove empties) via sanitizeContextFacts().
		return meta.CurrentContext, nil
	}
	return nil, nil
}

// getContextMaxItems reads CURRENT_CONTEXT_MAX_ITEMS from config, defaults to 8, and clamps to [1, 50].
func getContextMaxItems() int {
	const (
		defaultValue = 8
		minValue     = 1
		maxValue     = 50
	)

	cfg, err := loadConfig()
	if err != nil {
		return defaultValue
	}

	v := strings.TrimSpace(cfg["CURRENT_CONTEXT_MAX_ITEMS"])
	if v == "" {
		return defaultValue
	}

	n, err := strconv.Atoi(v)
	if err != nil {
		return defaultValue
	}

	if n < minValue {
		return minValue
	}
	if n > maxValue {
		return maxValue
	}
	return n
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
	return createNewThread(title)
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

// Parse tool command and execute it via tool server
func parseAndExecuteTool(command string) (string, error) {
	// Parse /tool command
	toolRegex := regexp.MustCompile(`^/tool\s+(\w+)(?:\s+(.+))?$`)
	matches := toolRegex.FindStringSubmatch(command)
	if len(matches) < 2 {
		return "", fmt.Errorf("invalid tool command format")
	}

	toolName := matches[1]
	argsString := ""
	if len(matches) > 2 {
		argsString = matches[2]
	}

	// Check for help flag
	if strings.Contains(argsString, "--help") {
		tool, err := getToolHelp(toolName)
		if err != nil {
			return fmt.Sprintf("Error getting help for %s: %v", toolName, err), nil
		}
		return fmt.Sprintf("Help for %s:\n%s", toolName, tool.Help), nil
	}

	// Parse arguments: --key value
	args := make(map[string]interface{})
	if argsString != "" {
		argRegex := regexp.MustCompile(`--(\w+)\s+([^\s]+(?:\s+[^\s]+)*)`)
		argMatches := argRegex.FindAllStringSubmatch(argsString, -1)
		for _, m := range argMatches {
			if len(m) >= 3 {
				key := m[1]
				value := strings.Trim(m[2], `"'`)
				args[key] = value
			}
		}
	}

	// Execute via tool server
	resp, err := executeTool(toolName, args)
	if err != nil {
		return fmt.Sprintf("Error executing tool %s: %v", toolName, err), nil
	}
	if !resp.Success {
		return fmt.Sprintf("Tool %s failed: %s", toolName, resp.Error), nil
	}
	// Pretty print result
	resultBytes, err := json.MarshalIndent(resp.Data, "", "  ")
	if err != nil {
		return fmt.Sprintf("Tool %s executed successfully, but failed to format result", toolName), nil
	}
	return fmt.Sprintf("Tool %s executed successfully:\n```json\n%s\n```", toolName, string(resultBytes)), nil
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

func loadConfig() (map[string]string, error) {
	configOnce.Do(func() {
		path := os.ExpandEnv(config.ConfigFilePath)
		cfg, err := ini.Load(path)
		if err != nil {
			configErr = err
			return
		}

		// Load from [default] section
		defaultSection := cfg.Section("default")
		configData = make(map[string]string)
		for _, key := range defaultSection.Keys() {
			configData[key.Name()] = key.String()
		}
		dockerAutoRemove = strings.EqualFold(cfg.Section("default").Key("DOCKER_AUTO_REMOVE").String(), "true")
	})
	return configData, configErr
}

// getToolsAddr returns the address for the embedded tool server from config or a default
func getToolsAddr() string {
	cfg, err := loadConfig()
	if err != nil {
		return ":8080"
	}
	if v, ok := cfg["TOOLS_ADDR"]; ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return ":8080"
}

// Get available tools from the tool server
func getAvailableTools() ([]Tool, error) {
	addr := getToolsAddr()
	url := "http://127.0.0.1" + addr + "/api/tools"
	log.Printf("[Agent->Tools] GET %s", url)
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("tool server returned %s", resp.Status)
	}
	var tr ToolResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return nil, err
	}
	if !tr.Success {
		return nil, fmt.Errorf("tool server error: %s", tr.Error)
	}
	b, err := json.Marshal(tr.Data)
	if err != nil {
		return nil, err
	}
	var list []Tool
	if err := json.Unmarshal(b, &list); err != nil {
		return nil, err
	}
	return list, nil
}

// Execute a tool by delegating to the tool server
func executeTool(toolName string, args map[string]interface{}) (*ToolResponse, error) {
	addr := getToolsAddr()
	url := "http://127.0.0.1" + addr + "/api/tools"
	payload := map[string]interface{}{"tool": toolName, "args": args}
	body, _ := json.Marshal(payload)
	log.Printf("[Agent->Tools] POST %s body=%s", url, string(body))
	req, err := http.NewRequest("POST", url, strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	rb, _ := ioutil.ReadAll(resp.Body)
	log.Printf("[Agent->Tools] Response %s body=%s", resp.Status, string(rb))
	var tr ToolResponse
	if err := json.Unmarshal(rb, &tr); err != nil {
		return nil, err
	}
	return &tr, nil
}

// Get tool help information directly
func getToolHelp(toolName string) (*Tool, error) {
	list, err := getAvailableTools()
	if err != nil {
		return nil, err
	}
	for _, t := range list {
		if t.Name == toolName {
			// cache into local map for quick lookup later
			tools[t.Name] = t
			return &t, nil
		}
	}
	return nil, fmt.Errorf("Tool not found: %s", toolName)
}

// Parse /tools command to list available tools
func listAvailableTools() (string, error) {
	tools, err := getAvailableTools()
	if err != nil {
		return fmt.Sprintf("Error getting available tools: %v", err), nil
	}

	var result strings.Builder
	result.WriteString("Available tools:\n\n")
	for _, tool := range tools {
		result.WriteString(fmt.Sprintf("**%s** - %s\n", tool.Name, tool.Description))
		if len(tool.Parameters) > 0 {
			result.WriteString("  Parameters:\n")
			for param, desc := range tool.Parameters {
				result.WriteString(fmt.Sprintf("    - %s: %s\n", param, desc))
			}
		}
		result.WriteString("\n")
	}

	return result.String(), nil
}

// (moved) Enhanced Gemini API handler is defined later in this file.
// The earlier partial definition was removed to avoid duplication and syntax errors.
// Helper to summarize tool response concisely
func summarizeToolResponse(resp *ToolResponse) string {
	if resp.Success {
		return fmt.Sprint(resp.Data)
	} else {
		return fmt.Sprintf("Failed: %s", resp.Error)
	}
}

// maskToken masks sensitive values leaving a small prefix/suffix for identification
func maskToken(s string) string {
	if s == "" {
		return ""
	}
	if len(s) <= 8 {
		return "****"
	}
	return s[:4] + "****" + s[len(s)-4:]
}

// createNewThread creates a new thread row and returns its ID.
func createNewThread(title string) (int64, error) {
	dbc := db.Get()
	if dbc == nil {
		return 0, fmt.Errorf("db not initialized")
	}
	var id int64
	err := dbc.QueryRow(`INSERT INTO threads (title) VALUES ($1) RETURNING id`, title).Scan(&id)
	if err != nil {
		return 0, err
	}
	return id, nil
}

// storeMessage inserts a message into the specified thread.
func storeMessage(threadID int64, role, content string, metadata map[string]interface{}) error {
	dbc := db.Get()
	if dbc == nil {
		return fmt.Errorf("storeMessage failed: database not initialized")
	}
	// Marshal metadata to JSONB via string parameter
	var metaJSON string = "{}"
	if metadata != nil {
		b, err := json.Marshal(metadata)
		if err != nil {
			log.Printf("[DB] Failed to marshal metadata: %v", err)
			return fmt.Errorf("failed to marshal metadata: %w", err)
		}
		metaJSON = string(b)
	}
	if _, err := dbc.Exec(`INSERT INTO messages (thread_id, role, content, metadata) VALUES ($1,$2,$3,$4::jsonb)`, threadID, role, content, metaJSON); err != nil {
		log.Printf("[DB] insert message failed: %v", err)
		return err
	}
	return nil
}

// Slack channel -> thread mapping
// Bounded in-memory cache for Slack channel -> thread_id to avoid unbounded growth
type SlackCache struct {
	mu    sync.Mutex
	m     map[string]int64
	order []string
	cap   int
}

func (c *SlackCache) Get(k string) (int64, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		return 0, false
	}
	v, ok := c.m[k]
	if !ok {
		return 0, false
	}
	// move to end (most-recently used)
	for i, key := range c.order {
		if key == k {
			c.order = append(c.order[:i], c.order[i+1:]...)
			break
		}
	}
	c.order = append(c.order, k)
	return v, true
}

func (c *SlackCache) Put(k string, v int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = make(map[string]int64)
	}
	if _, exists := c.m[k]; exists {
		// update and move to end
		c.m[k] = v
		for i, key := range c.order {
			if key == k {
				c.order = append(c.order[:i], c.order[i+1:]...)
				break
			}
		}
		c.order = append(c.order, k)
		return
	}
	// insert new
	c.m[k] = v
	c.order = append(c.order, k)
	// evict if over capacity
	if c.cap > 0 && len(c.order) > c.cap {
		evict := c.order[0]
		c.order = c.order[1:]
		delete(c.m, evict)
		// also remove the per-channel lock for the evicted channel
		removeSlackChannelLock(evict)
	}
}

var slackThreads = &SlackCache{cap: 25}

func ensureSlackThread(channel string) (int64, error) {
	// New logic: use any existing thread (most recently updated),
	// or create the first one if none exists. Channel is ignored.
	return getOrCreateAnyThread()
}

// Per-channel lock registry for Slack thread creation
var slackThreadLockRegistry struct {
	mu sync.Mutex
	m  map[string]*sync.Mutex
}

func getSlackChannelLock(channel string) *sync.Mutex {
	slackThreadLockRegistry.mu.Lock()
	defer slackThreadLockRegistry.mu.Unlock()
	if slackThreadLockRegistry.m == nil {
		slackThreadLockRegistry.m = make(map[string]*sync.Mutex)
	}
	l, ok := slackThreadLockRegistry.m[channel]
	if !ok {
		l = &sync.Mutex{}
		slackThreadLockRegistry.m[channel] = l
	}
	return l
}

// removeSlackChannelLock deletes the per-channel lock when evicting from cache
func removeSlackChannelLock(channel string) {
	slackThreadLockRegistry.mu.Lock()
	defer slackThreadLockRegistry.mu.Unlock()
	if slackThreadLockRegistry.m == nil {
		return
	}
	delete(slackThreadLockRegistry.m, channel)
}

// Handle regular message events
func handleSlackMessage(c *gin.Context, event *slack.MessageEvent) {
	// Ignore bot messages to prevent loops
	if event.BotID != "" {
		log.Printf("[Slack Message] Ignoring bot message from bot ID: %s", event.BotID)
		c.JSON(http.StatusOK, gin.H{"status": "bot message ignored"})
		return
	}

	// Use existing thread if any, otherwise create the first one
	threadID, err := getOrCreateAnyThread()
	if err != nil {
		log.Printf("[Slack Message] ensure thread failed: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to ensure thread"})
		return
	}

	// Persist user message
	if err := storeMessage(threadID, "user", event.Text, map[string]interface{}{
		"source":  "slack",
		"channel": event.Channel,
		"user":    event.User,
		"ts":      event.Timestamp,
	}); err != nil {
		log.Printf("[Slack Message] Failed to persist user message: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to persist user message"})
		return
	}

	// Load last persisted context and run gemini loop to persist updated context on Slack path too
	initialCtx, err := getLastContextForThread(threadID)
	if err != nil {
		log.Printf("[Slack Message] Failed to get last context: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load conversation context"})
		return
	}
	reply, updatedCtx, err := geminiAPIHandler(context.Background(), event.Text, initialCtx)
	if err != nil {
		log.Printf("[Slack Message] Gemini error: %v", err)
		// Notify user of failure and stop processing to avoid persisting an invalid reply
		if serr := sendSlackResponse(event.Channel, "Sorry, I encountered an error. Please try again."); serr != nil {
			log.Printf("[Slack Message] Failed to send error notice to Slack: %v", serr)
		}
		c.JSON(http.StatusOK, gin.H{"status": "error_processed"})
		return
	}
	// Persist assistant message including current_context
	if err := storeMessage(threadID, "assistant", reply, map[string]interface{}{
		"source":          "slack",
		"channel":         event.Channel,
		"current_context": updatedCtx,
	}); err != nil {
		log.Printf("[Slack Message] Failed to persist assistant message: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to persist assistant message"})
		return
	}

	// Try to send response back to Slack
	if err := sendSlackResponse(event.Channel, reply); err != nil {
		log.Printf("[Slack Message] Failed to send response to Slack: %v", err)
	}

	log.Printf("[Slack Message] Channel: %s, User: %s, Text: %s", event.Channel, event.User, event.Text)
	log.Printf("[Slack Message] Response: %s", reply)
	c.JSON(http.StatusOK, gin.H{"status": "message processed", "reply": reply})
}

// Send response back to Slack using bot token
func sendSlackResponse(channel, message string) error {
	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("failed to load config: %v", err)
	}
	botToken := cfg["SLACK_BOT_TOKEN"]
	if strings.TrimSpace(botToken) == "" {
		return fmt.Errorf("SLACK_BOT_TOKEN missing in config")
	}
	api := slack.New(botToken)
	_, _, err = api.PostMessage(
		channel,
		slack.MsgOptionText(message, false),
		slack.MsgOptionAsUser(true),
	)
	if err != nil {
		return fmt.Errorf("failed to post message: %v", err)
	}
	log.Printf("[Slack API] Message sent to channel %s", channel)
	return nil
}

func main() {
	// Setup logging
	f, err := setupLogging()
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
	if cfg, err := loadConfig(); err == nil {
		if v := strings.TrimSpace(cfg["API_ADDR"]); v != "" {
			apiAddr = v
		}
		dockerAutoRemove = strings.EqualFold(cfg["DOCKER_AUTO_REMOVE"], "true")
	}

	// Start tool server
	toolServer := toolsrv.NewServer(getToolsAddr())
	go func() {
		log.Printf("[Tools] Starting tool server on %s", getToolsAddr())
		if err := toolServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[Tools] Tool server error: %v", err)
		}
	}()

	// Gin router and routes
	r := gin.Default()
	r.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok", "service": "go-thing agent API"})
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
		if err := storeMessage(threadID, "user", req.Message, map[string]interface{}{"source": "http"}); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to persist user message"})
			return
		}
		// Load last persisted context for this thread
		initialCtx, err := getLastContextForThread(threadID)
		if err != nil {
			log.Printf("[Context] load error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load conversation context"})
			return
		}
		log.Printf("[Context] Using initial current_context for HTTP: %v", initialCtx)
		resp, updatedCtx, err := geminiAPIHandler(c.Request.Context(), req.Message, initialCtx)
		if err != nil {
			log.Printf("[Chat] gemini error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to process message: %v", err)})
			return
		}
		if strings.TrimSpace(resp) == "" {
			resp = "**No response available. Please try again.**"
		}
		log.Printf("[Context] Persisting updated current_context (HTTP): %v", updatedCtx)
		if err := storeMessage(threadID, "assistant", resp, map[string]interface{}{"source": "http", "current_context": updatedCtx}); err != nil {
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
			handleSlackMessage(c, &cb.Event)
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
}

func setupLogging() (*os.File, error) {
	// Default log file path in current working directory
	logPath := "debug.log"

	// Try to open in append mode, create if not exists
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, err
	}

	// Write to both stdout and file
	mw := io.MultiWriter(os.Stdout, f)
	log.SetOutput(mw)
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	// Route Gin logs to the same writer
	gin.DefaultWriter = mw
	gin.DefaultErrorWriter = mw

	return f, nil
}

func callGeminiAPI(ctx context.Context, client *genai.Client, task string, persistedContext []string) (string, ToolCall, error) {
	// Build Available Tools section dynamically
	available, err := getAvailableTools()
	var toolsSection strings.Builder
	toolsSection.WriteString("**Available Tools:**\n")
	if err == nil {
		for _, t := range available {
			// Build args signature from Parameters map
			var params []string
			for k := range t.Parameters {
				params = append(params, k)
			}
			argSig := ""
			if len(params) > 0 {
				argSig = " Args: " + strings.Join(params, ", ") + "."
			}
			toolsSection.WriteString(fmt.Sprintf("- %s: %s.%s\n", t.Name, t.Description, argSig))
		}
	} else {
		toolsSection.WriteString("- (failed to load tools)\n")
	}

	// Persisted Context Section (emit as JSON so the model can easily ingest)
	var contextSection strings.Builder
	if len(persistedContext) > 0 {
		sanitized := sanitizeContextFacts(persistedContext)
		b, err := json.Marshal(sanitized)
		if err != nil {
			log.Printf("[Gemini API] Failed to marshal persisted context: %v", err)
		} else {
			contextSection.WriteString("## Persisted Context\n")
			contextSection.WriteString(fmt.Sprintf("{\"current_context\": %s}\n\n", string(b)))
		}
	}

	maxItems := getContextMaxItems()
	systemPrompt := fmt.Sprintf(`# Role
You are a helpful assistant that executes tasks by calling tools.

## Instructions
1. Analyze the Request
   - Review the "Original Task" and the "History of actions" to understand what has been done and what is left to do.
2. Maintain and Revise Context (ALWAYS)
   - Always include a current_context array reflecting the most important environment/state/constraint facts for THIS turn.
   - Prioritize remembering high-signal details; prune and deduplicate aggressively.
   - Keep it short (<= %d items). Always revise current_context based on the latest user message and outcomes.
3. Decide the Next Step
   - If the task is not yet complete, determine the next tool to call.
   - If the task is complete, prepare a final, user-facing response.
4. Strict Output Format (ALWAYS JSON)
   - Respond ONLY with a single JSON object, never Markdown or prose.
   - Schema:
     {
       "current_context": ["..."],
       "tool": "tool_name" | "",
       "args": {"arg1": "value1"},
       "final": "Final Markdown response if no tool is needed, else empty string"
     }
   - When a tool call is needed, set "tool" and "args"; set "final" to "".
   - When providing a final response, set "final" and leave "tool" as "".

## Execution Environment (IMPORTANT)
- All commands run inside a running Docker container with a chroot at /app.
- Only paths under /app are valid. Never use host paths (e.g., /home/...); map them to /app equivalents.
- Some state may be ephemeral and NOT persist between separate calls. Do not assume running processes or temporary files exist later.
- If a step depends on prior results, restate the essential facts in current_context and re-create needed state deterministically.
- Treat the working directory as /app unless otherwise noted; prefer relative project paths (e.g., crypto-trading-bot/frontend).
- If a tool reports path/permission issues, adjust to remain within /app and avoid relying on host environment tools.

%s

%s

---

**Current Request:**
%s`, maxItems, toolsSection.String(), contextSection.String(), task)
	log.Printf("[Gemini API] Sending prompt: %s", systemPrompt)
	resp, err := client.Models.GenerateContent(ctx, "gemini-2.5-flash", genai.Text(systemPrompt), nil)
	if err != nil {
		log.Printf("[Gemini API] Error generating content: %v", err)
		return "", ToolCall{}, err
	}
	responseText := resp.Text()
	log.Printf("[Gemini API] Received response: %s", responseText)

	// Clean the response to extract raw JSON if it's in a markdown block
	cleanedResponse := strings.TrimSpace(responseText)
	if strings.HasPrefix(cleanedResponse, "```json") {
		cleanedResponse = strings.TrimPrefix(cleanedResponse, "```json")
		cleanedResponse = strings.TrimSuffix(cleanedResponse, "```")
		cleanedResponse = strings.TrimSpace(cleanedResponse)
	} else if strings.HasPrefix(cleanedResponse, "```") {
		cleanedResponse = strings.TrimPrefix(cleanedResponse, "```")
		cleanedResponse = strings.TrimSuffix(cleanedResponse, "```")
		cleanedResponse = strings.TrimSpace(cleanedResponse)
	}

	// Parse for JSON model response
	var toolCall ToolCall
	err = json.Unmarshal([]byte(cleanedResponse), &toolCall)
	if err == nil {
		// Log parsed context if present
		if len(toolCall.CurrentContext) > 0 || len(toolCall.CurrentContent) > 0 {
			merged := toolCall.GetMergedContext()
			log.Printf("[Gemini API] current_json: current_context=%v current_content=%v merged=%v", toolCall.CurrentContext, toolCall.CurrentContent, merged)
		}
		if toolCall.Tool != "" {
			log.Printf("[Gemini API] Tool call detected: %v", toolCall)
			return "", toolCall, nil
		}
		// Final path: ensure responseText reflects final content
		log.Printf("[Gemini API] Final JSON detected")
		return toolCall.Final, toolCall, nil
	}
	// Fallback: not JSON
	log.Printf("[Gemini API] Non-JSON response, returning raw text")
	return responseText, ToolCall{}, nil
}

type ToolCall struct {
	Tool           string                 `json:"tool"`
	Args           map[string]interface{} `json:"args"`
	CurrentContext []string               `json:"current_context,omitempty"`
	CurrentContent []string               `json:"current_content,omitempty"`
	Final          string                 `json:"final,omitempty"`
}

// GetMergedContext returns a merged context slice from either current_context or current_content
func (tc *ToolCall) GetMergedContext() []string {
	// Prefer current_context, but also merge current_content if present
	var out []string
	if len(tc.CurrentContext) > 0 {
		out = append(out, tc.CurrentContext...)
	}
	if len(tc.CurrentContent) > 0 {
		out = mergeStringSets(out, tc.CurrentContent)
	}
	return out
}

// mergeStringSets merges two string slices, de-duplicating while preserving order (favoring later slice order at the end)
func mergeStringSets(base []string, extra []string) []string {
	seen := make(map[string]bool, len(base)+len(extra))
	var res []string
	for _, v := range base {
		if !seen[v] {
			seen[v] = true
			res = append(res, v)
		}
	}
	for _, v := range extra {
		if !seen[v] {
			seen[v] = true
			res = append(res, v)
		}
	}
	return res
}

// geminiAPIHandler runs the LLM/tool loop. It accepts an initialContext (persisted across turns)
// and returns the final assistant response and the updated current_context slice.
func geminiAPIHandler(ctx context.Context, task string, initialContext []string) (string, []string, error) {
	log.Printf("[Gemini API] Handler invoked for task: %s", task)
	if len(initialContext) > 0 {
		log.Printf("[Context] Loaded initial current_context: %v", initialContext)
	} else {
		log.Printf("[Context] No initial current_context loaded")
	}
	cfg, err := loadConfig()
	if err != nil {
		return "Error loading config", nil, err
	}
	apiKey := cfg["GEMINI_API_KEY"]
	if apiKey == "" {
		return "GEMINI_API_KEY missing", nil, fmt.Errorf("GEMINI_API_KEY missing")
	}
	client, err := genai.NewClient(ctx, &genai.ClientConfig{APIKey: apiKey})
	if err != nil {
		return "Error initializing Gemini client", nil, err
	}

	maxIterations := 30
	originalTask := task
	var history []string
	// Aggregated, rolling context provided by the model via current_context/current_content
	var currentContext []string
	if len(initialContext) > 0 {
		currentContext = mergeStringSets(currentContext, initialContext)
	}

	for i := 0; i < maxIterations; i++ {
		currentPrompt := originalTask
		if len(history) > 0 {
			currentPrompt = fmt.Sprintf("Original Task: %s\n\nHistory of actions:\n%s", originalTask, strings.Join(history, "\n"))
		}

		responseText, toolCall, err := callGeminiAPI(ctx, client, currentPrompt, currentContext)
		if err != nil {
			log.Printf("[Gemini Loop] Error from Gemini: %v", err)
			return "An error occurred while calling the LLM.", currentContext, err
		}
		// Always merge model-provided current_context/current_content, whether tool or final
		if len(toolCall.GetMergedContext()) > 0 {
			log.Printf("[Context] From toolCall: current_context=%v current_content=%v", toolCall.CurrentContext, toolCall.CurrentContent)
			incoming := sanitizeContextFacts(toolCall.GetMergedContext())
			currentContext = mergeStringSets(currentContext, incoming)
			maxItems := getContextMaxItems()
			if len(currentContext) > maxItems {
				currentContext = currentContext[len(currentContext)-maxItems:]
			}
			log.Printf("[Context] Updated current_context: %v", currentContext)
		}

		if toolCall.Tool != "" {
			toolResp, err := executeTool(toolCall.Tool, toolCall.Args)
			if err != nil {
				return fmt.Sprintf("Tool %s failed: %v", toolCall.Tool, err), currentContext, err
			}

			// Add tool call and result to history
			history = append(history, fmt.Sprintf("- Tool call: %s with args %v", toolCall.Tool, toolCall.Args))
			history = append(history, fmt.Sprintf("- Tool result: %s", summarizeToolResponse(toolResp)))
		} else {
			// No tool call, assume this is the final response
			if strings.TrimSpace(responseText) == "" {
				return "**No response from Gemini.**", currentContext, nil
			}
			return responseText, currentContext, nil
		}
	}
	return "**Max iterations reached or no final response.** Please refine your query.", currentContext, nil
}

func processUserMessage(message string) (string, error) {
	// Check for explicit tool commands first
	if strings.HasPrefix(message, "/tools") {
		return listAvailableTools()
	}

	if strings.HasPrefix(message, "/tool ") {
		return parseAndExecuteTool(message)
	}

	// Analyze message for implicit tool requests
	lowerMessage := strings.ToLower(message)

	// Check for disk space related queries
	if strings.Contains(lowerMessage, "disk") ||
		strings.Contains(lowerMessage, "space") ||
		strings.Contains(lowerMessage, "storage") ||
		strings.Contains(lowerMessage, "how much space") ||
		strings.Contains(lowerMessage, "disk usage") ||
		strings.Contains(lowerMessage, "free space") {
		// Execute disk space tool
		result, err := parseAndExecuteTool("/tool disk_space")
		if err != nil {
			return "", err
		}
		return result, nil
	}

	// Check for tool listing requests
	if strings.Contains(lowerMessage, "tools") ||
		strings.Contains(lowerMessage, "what can you do") ||
		strings.Contains(lowerMessage, "capabilities") ||
		strings.Contains(lowerMessage, "available") {
		return listAvailableTools()
	}

	// For other messages, use Gemini with tool awareness
	resp, _, err := geminiAPIHandler(context.Background(), message, nil)
	return resp, err
}
