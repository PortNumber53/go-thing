package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"

	"github.com/gin-gonic/gin"
	"github.com/slack-go/slack"
	genai "google.golang.org/genai"
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

// Available tools registry
var tools = map[string]Tool{
	"disk_space": {
		Name:        "disk_space",
		Description: "Get disk space information for a specified path",
		Help: `Usage: /tool disk_space [--path <path>]

Parameters:
  --path <path>    Path to check disk space for (default: current directory)

Examples:
  /tool disk_space                    # Check current directory
  /tool disk_space --path /home       # Check /home directory
  /tool disk_space --help             # Show this help`,
		Parameters: map[string]string{
			"path": "Path to check disk space for (optional, defaults to current directory)",
		},
	},
	"write_file": {
		Name:        "write_file",
		Description: "Write content to a file in the configured write directory",
		Help: `Usage: /tool write_file --path <filepath> --content <content>

Parameters:
  --path <filepath>    Path to the file to write (must be within configured write_dir)
  --content <content>  Content to write to the file

Examples:
  /tool write_file --path test.txt --content "Hello World"
  /tool write_file --help`,
		Parameters: map[string]string{
			"path":    "Path to the file to write",
			"content": "Content to write to the file",
		},
	},
}

func loadConfig() (map[string]string, error) {
	configOnce.Do(func() {
		path := os.ExpandEnv("$HOME/.config/go-thing/config")
		b, err := ioutil.ReadFile(path)
		if err != nil {
			configErr = err
			return
		}
		err = json.Unmarshal(b, &configData)
		if err != nil {
			configErr = err
		}
	})
	return configData, configErr
}

// Get disk space information
func getDiskSpace(path string) (*DiskSpaceInfo, error) {
	var stat syscall.Statfs_t
	err := syscall.Statfs(path, &stat)
	if err != nil {
		return nil, err
	}

	// Calculate sizes
	totalBytes := stat.Blocks * uint64(stat.Bsize)
	freeBytes := stat.Bfree * uint64(stat.Bsize)
	usedBytes := totalBytes - freeBytes

	// Convert to GB
	totalGB := float64(totalBytes) / (1024 * 1024 * 1024)
	freeGB := float64(freeBytes) / (1024 * 1024 * 1024)
	usedGB := float64(usedBytes) / (1024 * 1024 * 1024)

	// Calculate usage percentage
	usagePercent := 0.0
	if totalBytes > 0 {
		usagePercent = (float64(usedBytes) / float64(totalBytes)) * 100
	}

	return &DiskSpaceInfo{
		Path:         path,
		TotalBytes:   totalBytes,
		FreeBytes:    freeBytes,
		UsedBytes:    usedBytes,
		TotalGB:      totalGB,
		FreeGB:       freeGB,
		UsedGB:       usedGB,
		UsagePercent: usagePercent,
	}, nil
}

// Execute disk space tool
func executeDiskSpaceTool(args map[string]interface{}) (*ToolResponse, error) {
	path := "."
	if pathArg, ok := args["path"].(string); ok && pathArg != "" {
		path = pathArg
	}

	// Resolve absolute path
	absPath, err := filepath.Abs(path)
	if err != nil {
		return &ToolResponse{
			Success: false,
			Error:   fmt.Sprintf("Invalid path: %v", err),
		}, nil
	}

	// Check if path exists
	if _, err := os.Stat(absPath); os.IsNotExist(err) {
		return &ToolResponse{
			Success: false,
			Error:   fmt.Sprintf("Path does not exist: %s", absPath),
		}, nil
	}

	diskInfo, err := getDiskSpace(absPath)
	if err != nil {
		return &ToolResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to get disk space: %v", err),
		}, nil
	}

	return &ToolResponse{
		Success: true,
		Data:    diskInfo,
	}, nil
}

// Execute write file tool
func executeWriteFileTool(args map[string]interface{}) (*ToolResponse, error) {
	path, ok := args["path"].(string)
	if !ok || path == "" {
		return &ToolResponse{
			Success: false,
			Error:   "path parameter is required",
		}, nil
	}

	content, ok := args["content"].(string)
	if !ok {
		return &ToolResponse{
			Success: false,
			Error:   "content parameter is required",
		}, nil
	}

	// Read config
	configData, err := ioutil.ReadFile(os.ExpandEnv("$HOME/.config/go-thing/config"))
	if err != nil {
		return &ToolResponse{
			Success: false,
			Error:   fmt.Sprintf("Config file error: %v", err),
		}, nil
	}

	var config map[string]string
	err = json.Unmarshal(configData, &config)
	if err != nil {
		return &ToolResponse{
			Success: false,
			Error:   fmt.Sprintf("Config parse error: %v", err),
		}, nil
	}

	writeDir, ok := config["write_dir"]
	if !ok {
		return &ToolResponse{
			Success: false,
			Error:   "write_dir not configured",
		}, nil
	}

	// Construct full path relative to write_dir
	fullPath := filepath.Join(writeDir, path)

	// Create directory if it doesn't exist
	dir := filepath.Dir(fullPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return &ToolResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to create directory: %v", err),
		}, nil
	}

	// Write the file
	err = os.WriteFile(fullPath, []byte(content), 0644)
	if err != nil {
		return &ToolResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to write file: %v", err),
		}, nil
	}

	return &ToolResponse{
		Success: true,
		Data: map[string]string{
			"message": "File written successfully",
			"path":    fullPath,
		},
	}, nil
}

// Get available tools directly
func getAvailableTools() ([]Tool, error) {
	toolList := make([]Tool, 0, len(tools))
	for _, tool := range tools {
		toolList = append(toolList, tool)
	}
	return toolList, nil
}

// Execute a tool directly
func executeTool(toolName string, args map[string]interface{}) (*ToolResponse, error) {
	switch toolName {
	case "disk_space":
		return executeDiskSpaceTool(args)
	case "write_file":
		return executeWriteFileTool(args)
	default:
		return &ToolResponse{
			Success: false,
			Error:   fmt.Sprintf("Unknown tool: %s", toolName),
		}, nil
	}
}

// Get tool help information directly
func getToolHelp(toolName string) (*Tool, error) {
	tool, exists := tools[toolName]
	if !exists {
		return nil, fmt.Errorf("Tool not found: %s", toolName)
	}
	return &tool, nil
}

// Parse tool command and execute it
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

	// Parse arguments
	args := make(map[string]interface{})
	if argsString != "" {
		// Simple argument parsing for --key value format
		argRegex := regexp.MustCompile(`--(\w+)\s+([^\s]+(?:\s+[^\s]+)*)`)
		argMatches := argRegex.FindAllStringSubmatch(argsString, -1)
		for _, match := range argMatches {
			if len(match) >= 3 {
				key := match[1]
				value := strings.Trim(match[2], `"'`)
				args[key] = value
			}
		}
	}

	// Execute the tool
	resp, err := executeTool(toolName, args)
	if err != nil {
		return fmt.Sprintf("Error executing tool %s: %v", toolName, err), nil
	}

	if !resp.Success {
		return fmt.Sprintf("Tool %s failed: %s", toolName, resp.Error), nil
	}

	// Format the response
	resultBytes, err := json.MarshalIndent(resp.Data, "", "  ")
	if err != nil {
		return fmt.Sprintf("Tool %s executed successfully, but failed to format result", toolName), nil
	}

	return fmt.Sprintf("Tool %s executed successfully:\n```json\n%s\n```", toolName, string(resultBytes)), nil
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

	maxIterations := 5
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
	log.Printf("[Startup] Starting go-thing agent")
	r := gin.Default()

	r.GET("/", func(c *gin.Context) {
		c.Header("Content-Type", "text/html")
		c.String(http.StatusOK, `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>AI Agent Chat</title>
<style>
body { font-family: sans-serif; margin: 2em; }
#chat { border: 1px solid #ccc; padding: 1em; height: 300px; overflow-y: auto; margin-bottom: 1em; }
#input { width: 80%; }
.agent-msg { background: #f6f8fa; padding: 0.5em; border-radius: 4px; margin: 0.5em 0; }
.user-msg { background: #e6f7ff; padding: 0.5em; border-radius: 4px; margin: 0.5em 0; text-align: right; }
</style>
<!-- Marked.js for Markdown rendering -->
<script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
</head>
<body>
<h2>AI Agent Chat</h2>
<div id="chat"></div>
<input id="input" type="text" placeholder="Type a message..." autofocus />
<button onclick="sendMsg()">Send</button>
<script>
document.addEventListener('DOMContentLoaded', function() {
const chat = document.getElementById('chat');
const input = document.getElementById('input');
function append(msg, who) {
if (!chat) return;
const div = document.createElement('div');
if (who === 'Agent') {
  div.className = 'agent-msg';
  // Render Markdown to HTML with robust error handling
  if (typeof msg === 'string' && msg !== '') {
    try {
      div.innerHTML = marked.parse(msg);
    } catch (e) {
      div.textContent = 'Error rendering response: ' + e.message;
    }
  } else {
    div.textContent = 'No or invalid response from server.';
  }
} else if (who === 'You') {
  div.className = 'user-msg';
  div.textContent = who + ': ' + msg;
} else {
  div.textContent = (who ? who+': ' : '') + msg;
}
chat.appendChild(div);
chat.scrollTop = chat.scrollHeight;
}
function sendMsg() {
if (!input) return;
const msg = input.value.trim();
if (!msg) return;
append(msg, 'You');
input.value = '';
fetch('/chat', {
method: 'POST',
headers: { 'Content-Type': 'application/json' },
body: JSON.stringify({ message: msg })
})
.then(r => {
  if (!r.ok) throw new Error('Network response was not ok');
  return r.json();
})
.then(data => {
  if (data.response !== undefined && typeof data.response === 'string') {
    append(data.response, 'Agent');
  } else {
    append('Error: Invalid or missing response from server.', 'System');
  }
})
.catch(error => {
  append('Error: Failed to communicate with server. ' + error.message, 'System');
});
}
if (input) {
input.addEventListener('keydown', e => { if (e.key === 'Enter') sendMsg(); });
window.sendMsg = sendMsg;
}
});
</script>
</body>
</html>
`)
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

	r.Run("0.0.0.0:7865")
}

func callGeminiAPI(client *genai.Client, task string) (string, ToolCall, error) {
	systemPrompt := `You are a helpful assistant that executes tasks by calling tools.

**Instructions:**
1. **Analyze the Request:** Review the 'Original Task' and the 'History of actions' to understand what has been done and what is left to do.
2. **Decide the Next Step:**
    *   If the task is not yet complete, determine the next tool to call. Output a JSON object for the tool call.
    *   If the task is complete, provide a final, user-facing response in Markdown.
3.  **Strict Output Formatting:**
    *   For tool calls, output **ONLY** a JSON object like: '{"tool": "tool_name", "args": {"arg1": "value1"}}'.
    *   For final answers, output **ONLY** Markdown-formatted text.
    *   Do not include any other text, explanations, or conversational filler.

**Available Tools:**
- disk_space: Get disk space. Args: path (string).
- write_file: Write file. Args: path (string), content (string).

---

**Current Request:**
` + task
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
