package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"go-thing/internal/config"

	"github.com/gin-gonic/gin"
	"github.com/slack-go/slack"
	"google.golang.org/genai"
	"gopkg.in/ini.v1"

	toolsrv "go-thing/tools"
)

var (
	configOnce sync.Once
	configData map[string]string
	configErr  error
)

// ToolResponse represents a response from tool execution
type ToolResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
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

// Enhanced Gemini API call with tool awareness
func geminiAPIHandler(ctx context.Context, task string) (string, error) {
	log.Printf("[Gemini API] Handler invoked for task: %s", task)
	cfg, err := loadConfig()
	if err != nil {
		return "Error loading config", nil
	}
	apiKey := cfg["GEMINI_API_KEY"]
	if apiKey == "" {
		return "GEMINI_API_KEY missing", nil
	}
	client, err := genai.NewClient(ctx, &genai.ClientConfig{APIKey: apiKey})
	if err != nil {
		return "Error initializing Gemini client", nil
	}

	maxIterations := 30
	originalTask := task
	var history []string

	for i := 0; i < maxIterations; i++ {
		currentPrompt := originalTask
		if len(history) > 0 {
			currentPrompt = fmt.Sprintf("Original Task: %s\n\nHistory of actions:\n%s", originalTask, strings.Join(history, "\n"))
		}

		responseText, toolCall, err := callGeminiAPI(client, currentPrompt)
		if err != nil {
			log.Printf("[Gemini API] Error in API call: %v", err)
			return "Gemini API error occurred", nil
		}

		if toolCall.Tool != "" {
			toolResp, err := executeTool(toolCall.Tool, toolCall.Args)
			if err != nil {
				return fmt.Sprintf("Tool %s failed: %v", toolCall.Tool, err), nil
			}

			// Add tool call and result to history
			history = append(history, fmt.Sprintf("- Tool call: %s with args %v", toolCall.Tool, toolCall.Args))
			history = append(history, fmt.Sprintf("- Tool result: %s", summarizeToolResponse(toolResp)))
		} else {
			// No tool call, assume this is the final response
			if strings.TrimSpace(responseText) == "" {
				return "**No response from Gemini.**", nil
			}
			return responseText, nil // Return immediately with Gemini's response
		}
	}
	return "**Max iterations reached or no final response.** Please refine your query.", nil
}

// Helper to summarize tool response concisely
func summarizeToolResponse(resp *ToolResponse) string {
	if resp.Success {
		return fmt.Sprint(resp.Data)
	} else {
		return fmt.Sprintf("Failed: %s", resp.Error)
	}
}

// Slack webhook handler
func handleSlackWebhook(c *gin.Context) {
	// Read the request body
	body, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {
		log.Printf("[Slack Webhook] Error reading body: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to read request body"})
		return
	}

	// Parse the Slack event
	var event slack.Event
	if err := json.Unmarshal(body, &event); err != nil {
		log.Printf("[Slack Webhook] Error parsing event: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid event format"})
		return
	}

	// Handle URL verification challenge
	if event.Type == "url_verification" {
		var challenge struct {
			Challenge string `json:"challenge"`
		}
		if err := json.Unmarshal(body, &challenge); err != nil {
			log.Printf("[Slack Webhook] Error parsing challenge: %v", err)
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid challenge format"})
			return
		}
		log.Printf("[Slack Webhook] URL verification challenge received: %s", challenge.Challenge)
		c.JSON(http.StatusOK, gin.H{"challenge": challenge.Challenge})
		return
	}

	// Handle events
	if event.Type == "event_callback" {
		var callback struct {
			Event slack.MessageEvent `json:"event"`
		}
		if err := json.Unmarshal(body, &callback); err != nil {
			log.Printf("[Slack Webhook] Error parsing callback: %v", err)
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid callback format"})
			return
		}

		// Handle message events
		handleSlackMessage(c, &callback.Event)
	} else {
		log.Printf("[Slack Webhook] Unhandled event type: %s", event.Type)
		c.JSON(http.StatusOK, gin.H{"status": "event received"})
	}
}

// Handle regular message events
func handleSlackMessage(c *gin.Context, event *slack.MessageEvent) {
	// Ignore bot messages to prevent loops
	if event.BotID != "" {
		log.Printf("[Slack Message] Ignoring bot message from bot ID: %s", event.BotID)
		c.JSON(http.StatusOK, gin.H{"status": "bot message ignored"})
		return
	}

	// Check if this is a direct message or the bot was mentioned
	// For now, we'll process all messages in direct messages
	// In a real implementation, you'd check the channel type and bot mentions

	// Process the message with Gemini
	reply, err := processUserMessage(event.Text)
	if err != nil {
		log.Printf("[Slack Message] Error processing message: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process message"})
		return
	}

	// Try to send response back to Slack using the Slack API
	if err := sendSlackResponse(event.Channel, reply); err != nil {
		log.Printf("[Slack Message] Failed to send response to Slack: %v", err)
		// Still return success to Slack to avoid retries
	}

	log.Printf("[Slack Message] Channel: %s, User: %s, Text: %s", event.Channel, event.User, event.Text)
	log.Printf("[Slack Message] Response: %s", reply)
	c.JSON(http.StatusOK, gin.H{"status": "message processed", "reply": reply})
}

// Send response back to Slack
func sendSlackResponse(channel, message string) error {
	// Load config to get Slack bot token
	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("failed to load config: %v", err)
	}

	botToken := cfg["SLACK_BOT_TOKEN"]
	if botToken == "" {
		return fmt.Errorf("SLACK_BOT_TOKEN missing in config")
	}

	// Create Slack client
	api := slack.New(botToken)

	// Send message
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
	// Setup logging to both stdout and debug.log
	setupLogFile, err := setupLogging()
	if err != nil {
		log.Printf("[Startup] Failed to set up file logging: %v", err)
	} else if setupLogFile != nil {
		defer setupLogFile.Close()
	}
	log.Printf("[Startup] Starting go-thing agent")
	// Start embedded tool server with graceful shutdown support
	toolsAddr := getToolsAddr()
	toolServer := toolsrv.NewServer(toolsAddr)
	go func() {
		log.Printf("[Tools] Starting tool server on %s", toolsAddr)
		if err := toolServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[Tools] Tool server exited with error: %v", err)
		}
	}()

	r := gin.Default()

	r.GET("/", func(c *gin.Context) {
		// Frontend moved to React/Vite SPA served separately.
		// This endpoint now serves as a simple health/info check.
		c.JSON(http.StatusOK, gin.H{
			"status":  "ok",
			"service": "go-thing agent API",
			"message": "Frontend is now a React/Vite SPA. Use the SPA for UI; this server exposes /chat and webhooks.",
		})
	})

	r.POST("/chat", func(c *gin.Context) {
		var req struct {
			Message string `json:"message"`
		}
		if err := c.BindJSON(&req); err != nil {
			log.Printf("[Chat Handler] Error binding JSON: %v", err)
			c.JSON(400, gin.H{"response": "Invalid request format"})
			return
		}
		log.Printf("[Chat Handler] Received message: %s", req.Message)
		response, err := geminiAPIHandler(c.Request.Context(), req.Message)
		if err != nil {
			log.Printf("[Chat Handler] Error from geminiAPIHandler: %v", err)
			c.JSON(500, gin.H{"response": "Internal server error"})
			return
		}
		if strings.TrimSpace(response) == "" {
			response = "**No response available. Please try again.**"
		}
		log.Printf("[Chat Handler] Sending response: %s", response)
		c.JSON(200, gin.H{"response": response})
	})

	r.POST("/webhook/slack", handleSlackWebhook)

	// Keep the existing generic webhook for backward compatibility
	r.POST("/webhook", func(c *gin.Context) {
		// Placeholder for Slack webhook integration
		c.JSON(http.StatusOK, gin.H{"status": "webhook received"})
	})

	// Run Gin HTTP server with graceful shutdown
	apiAddr := "0.0.0.0:7866"
	apiServer := &http.Server{Addr: apiAddr, Handler: r}

	// OS signal handling (SIGINT/SIGTERM) for Air restarts
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		log.Printf("[API] Starting HTTP server on %s", apiAddr)
		if err := apiServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[API] HTTP server exited with error: %v", err)
		}
	}()

	// Wait for termination signal
	sig := <-quit
	log.Printf("[Shutdown] Caught signal: %v. Shutting down servers...", sig)

	// Graceful shutdown context
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Shutdown API server first to stop accepting new requests
	if err := apiServer.Shutdown(ctx); err != nil {
		log.Printf("[Shutdown] API server shutdown error: %v", err)
	} else {
		log.Printf("[Shutdown] API server stopped")
	}

	// Shutdown tool server
	if err := toolServer.Shutdown(ctx); err != nil {
		log.Printf("[Shutdown] Tool server shutdown error: %v", err)
	} else {
		log.Printf("[Shutdown] Tool server stopped")
	}
	log.Printf("[Shutdown] Done")
}

// setupLogging configures the global logger and Gin to write to both stdout and a debug.log file.
// Returns the opened file so caller can defer Close().
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

func callGeminiAPI(client *genai.Client, task string) (string, ToolCall, error) {
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

	systemPrompt := "You are a helpful assistant that executes tasks by calling tools.\n\n" +
		"**Instructions:**\n" +
		"1. **Analyze the Request:** Review the 'Original Task' and the 'History of actions' to understand what has been done and what is left to do.\n" +
		"2. **Decide the Next Step:**\n    *   If the task is not yet complete, determine the next tool to call. Output a JSON object for the tool call.\n    *   If the task is complete, provide a final, user-facing response in Markdown.\n" +
		"3.  **Strict Output Formatting:**\n    *   For tool calls, output **ONLY** a JSON object like: '{\"tool\": \"tool_name\", \"args\": {\"arg1\": \"value1\"}}'.\n    *   For final answers, output **ONLY** Markdown-formatted text.\n    *   Do not include any other text, explanations, or conversational filler.\n\n" +
		toolsSection.String() +
		"\n---\n\n**Current Request:**\n" + task
	log.Printf("[Gemini API] Sending prompt: %s", systemPrompt)
	resp, err := client.Models.GenerateContent(context.Background(), "gemini-2.5-flash", genai.Text(systemPrompt), nil)
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

	// Parse for JSON tool call
	var toolCall ToolCall
	err = json.Unmarshal([]byte(cleanedResponse), &toolCall)
	if err == nil && toolCall.Tool != "" {
		log.Printf("[Gemini API] Tool call detected: %v", toolCall)
		return responseText, toolCall, nil
	} else {
		log.Printf("[Gemini API] No tool call, assuming final response: %s", responseText)
		return responseText, ToolCall{}, nil
	}
}

type ToolCall struct {
	Tool string                 `json:"tool"`
	Args map[string]interface{} `json:"args"`
}

// Process user message with tool support
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
	return geminiAPIHandler(context.Background(), message)
}
