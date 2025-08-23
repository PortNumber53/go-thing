package utility

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
	"google.golang.org/api/googleapi"
	"google.golang.org/genai"
)

const (
	// Retry/backoff configuration for Gemini API calls
	maxAttempts     = 3
	baseDelay       = 5 * time.Second
	geminiModelName = "gemini-2.5-flash"
	// Random jitter upper bound for backoff, in milliseconds
	backoffJitterMs = 1000
	// Upper bound to clamp burst size for the rate limiter
	maxBurst = 100
	// Default rate limit for Gemini API calls in requests per minute.
	defaultGeminiRpm = 10
)

// ToolCall describes the model's directive in JSON
// Note: kept unexported; only used internally by this package
type ToolCall struct {
	Tool           string                 `json:"tool"`
	Args           map[string]interface{} `json:"args"`
	CurrentContext []string               `json:"current_context,omitempty"`
	CurrentContent []string               `json:"current_content,omitempty"`
	Final          string                 `json:"final,omitempty"`
}

// GetMergedContext returns a merged context slice from either current_context or current_content
func (tc *ToolCall) GetMergedContext() []string {
	return MergeStringSets(tc.CurrentContext, tc.CurrentContent)
}

// --- Rate limiting and retry/backoff for Gemini API ---
var (
	geminiLimiterOnce sync.Once
	geminiLimiter     *rate.Limiter
)

func getGeminiLimiter() *rate.Limiter {
	geminiLimiterOnce.Do(func() {
		// Default requests per minute if not configured
		rpm := defaultGeminiRpm
		cfg, err := LoadConfig()
		if err != nil {
			slog.Warn("Failed to load config for Gemini rate limiter, using default", "error", err)
		} else {
			rpm = parseRpmFromConfig(cfg, rpm)
		}
		// rate.Every defines minimum time between events
		// Burst set to rpm to allow short spikes up to the per-minute quota
		interval := time.Minute / time.Duration(rpm)
		if interval <= 0 {
			// Prevent infinite rate from pathological large RPM values
			interval = time.Nanosecond
		}
		burst := rpm
		if burst > maxBurst {
			slog.Warn("GEMINI_RPM is very large, clamping burst size to avoid traffic spikes", "rpm", rpm, "max_burst", maxBurst)
			burst = maxBurst
		}
		geminiLimiter = rate.NewLimiter(rate.Every(interval), burst)
		slog.Info("Initialized Gemini limiter", "rpm", rpm, "interval", interval.String(), "burst", burst)
	})
	return geminiLimiter
}

// parseRpmFromConfig extracts and validates the GEMINI_RPM value from config.
// Returns defaultRpm when unset, invalid, or unparseable. Emits warnings on issues.
func parseRpmFromConfig(cfg map[string]string, defaultRpm int) int {
	rpmStr := strings.TrimSpace(cfg["GEMINI_RPM"])
	if rpmStr == "" {
		return defaultRpm
	}
	n, err := strconv.Atoi(rpmStr)
	if err != nil {
		slog.Warn("Could not parse GEMINI_RPM; using default", "value", rpmStr, "error", err)
		return defaultRpm
	}
	if n <= 0 {
		slog.Warn("Invalid GEMINI_RPM (must be > 0); using default", "value", rpmStr)
		return defaultRpm
	}
	return n
}

// shouldRetry429 best-effort detection of quota/rate errors
func shouldRetry429(err error) bool {
	if err == nil {
		return false
	}
	// Prefer structured error type when available
	var gerr *googleapi.Error
	if errors.As(err, &gerr) && gerr.Code == 429 {
		return true
	}
	// Fallback to message inspection for other client libs/providers
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "resource_exhausted") || strings.Contains(msg, "429") || strings.Contains(msg, "quota")
}

// parseRetryDelay tries to extract a retry delay from the error text; falls back to def
func parseRetryDelay(err error, def time.Duration) time.Duration {
	if err == nil {
		return def
	}
	// Example fragment: "RetryInfo retryDelay:25s"
	msg := err.Error()
	idx := strings.Index(msg, "retryDelay:")
	if idx >= 0 {
		// A more robust way to parse the duration value, stopping at the first delimiter.
		valStr := strings.TrimSpace(msg[idx+len("retryDelay:"):])
		if endIdx := strings.IndexAny(valStr, " ,"); endIdx != -1 {
			valStr = valStr[:endIdx]
		}
		if d, e := time.ParseDuration(valStr); e == nil {
			return d
		}
	}
	return def
}

// callGeminiAPI sends the assembled system prompt and returns either a final text or a ToolCall.
func callGeminiAPI(ctx context.Context, client *genai.Client, task string, persistedContext []string, disableContext bool) (string, ToolCall, error) {
	// Build Available Tools section dynamically
	available, err := GetAvailableTools()
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
	if !disableContext && len(persistedContext) > 0 {
		sanitized := SanitizeContextFacts(persistedContext)
		b, err := json.Marshal(sanitized)
		if err != nil {
			slog.Error("Failed to marshal persisted context", "error", err)
			return "", ToolCall{}, fmt.Errorf("failed to marshal persisted context: %w", err)
		}
		contextSection.WriteString("## Persisted Context\n")
		contextSection.WriteString(fmt.Sprintf("{\"current_context\": %s}\n\n", string(b)))
	}

	maxItems := getContextMaxItems()
	var instructions string
	if disableContext {
		instructions = fmt.Sprintf(`# Role
You are a helpful assistant that executes tasks by calling tools.

## Instructions
1. Analyze the Request
   - Review the "Original Task" and the "History of actions" to understand what has been done and what is left to do.
2. Decide the Next Step
   - If the task is not yet complete, determine the next tool to call.
   - If the task is complete, prepare a final, user-facing response.
3. Strict Output Format (ALWAYS JSON)
   - Respond ONLY with a single JSON object, never Markdown or prose.
   - Schema:
     {
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

### Shell Sessions (STATEFUL)
- Use the persistent shell tool shell_session for any shell work that relies on state (e.g., cd, environment setup, long-running processes).
- Pick a single session id (e.g., dev) and keep using it for the entire task. Include a note like "session_id=dev" in current_context so you reuse it on the next turn.
- Do NOT use shell_exec for stateful operations; shell_exec creates a fresh, stateless process each time.

%s

%s

---

**Current Request:**
%s`, toolsSection.String(), "", task)
	} else {
		instructions = fmt.Sprintf(`# Role
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

### Shell Sessions (STATEFUL)
- Use the persistent shell tool shell_session for any shell work that relies on state (e.g., cd, environment setup, long-running processes).
- Pick a single session id (e.g., dev) and keep using it for the entire task. Include a note like "session_id=dev" in current_context so you reuse it on the next turn.
- Do NOT use shell_exec for stateful operations; shell_exec creates a fresh, stateless process each time.

%s

%s

---

**Current Request:**
%s`, maxItems, toolsSection.String(), contextSection.String(), task)
	}
	systemPrompt := instructions
	slog.Info("Sending Gemini prompt", "prompt", systemPrompt)
	// Global rate limit to respect API quotas
	if err := getGeminiLimiter().Wait(ctx); err != nil {
		slog.Error("Rate limiter wait failed", "error", err)
		return "", ToolCall{}, fmt.Errorf("rate limiter wait failed: %w", err)
	}

	var resp *genai.GenerateContentResponse
	// Retry with backoff when hitting quota/rate errors
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		resp, err = client.Models.GenerateContent(ctx, geminiModelName, genai.Text(systemPrompt), nil)
		// Success case: no error and a valid response.
		if err == nil && resp != nil {
			break
		}

		// Failure cases: determine if we should retry.
		var isRetryable bool
		if err != nil {
			isRetryable = shouldRetry429(err)
		} else { // err is nil, but resp is also nil. Treat as a transient error.
			err = errors.New("gemini: API returned empty response without error")
			isRetryable = true
		}

		slog.Warn("Error generating Gemini content", "attempt", attempt, "max_attempts", maxAttempts, "error", err)

		if !isRetryable || attempt == maxAttempts {
			break
		}
		// Honor server-provided retry delay if present; else exponential backoff with jitter
		delay := parseRetryDelay(err, baseDelay*time.Duration(1<<(attempt-1)))
		// Add small random jitter to avoid synchronized retries across instances
		delay += time.Duration(rand.Intn(backoffJitterMs)) * time.Millisecond
		if delay > 0 {
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return "", ToolCall{}, fmt.Errorf("retry delay wait canceled: %w", ctx.Err())
			}
		}
		// Also wait on limiter again before retry to re-schedule within quota
		if err := getGeminiLimiter().Wait(ctx); err != nil {
			return "", ToolCall{}, fmt.Errorf("rate limiter wait before retry failed: %w", err)
		}
	}
	// Guard against nil response to avoid panic if no attempt succeeded
	if resp == nil {
		// This happens if the loop completes without a successful response.
		// The `err` variable will hold the error from the last attempt.
		return "", ToolCall{}, fmt.Errorf("gemini: no response received after %d attempts, last error: %w", maxAttempts, err)
	}
	responseText := resp.Text()
	slog.Info("Received Gemini response", "response", responseText)

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
		// Log parsed context if present and not disabled
		if !disableContext && (len(toolCall.CurrentContext) > 0 || len(toolCall.CurrentContent) > 0) {
			merged := toolCall.GetMergedContext()
			slog.Info("Gemini JSON with context", "current_context", toolCall.CurrentContext, "current_content", toolCall.CurrentContent, "merged", merged)
		}
		if toolCall.Tool != "" {
			slog.Info("Gemini tool call detected", "tool_call", toolCall)
			return "", toolCall, nil
		}
		// Final path: ensure responseText reflects final content
		slog.Info("Final JSON detected")
		return toolCall.Final, toolCall, nil
	}
	// Fallback: not JSON
	slog.Info("Non-JSON response, returning raw text")
	return responseText, ToolCall{}, nil
}

// GeminiAPIHandler runs the LLM/tool loop. It accepts an initialContext (persisted across turns)
// and returns the final assistant response and the updated current_context slice.
func GeminiAPIHandler(ctx context.Context, task string, initialContext []string) (string, []string, error) {
	slog.Info("Gemini handler invoked", "task", task)
	if len(initialContext) > 0 {
		slog.Info("Loaded initial current_context", "current_context", initialContext)
	} else {
		slog.Info("No initial current_context loaded")
	}
	cfg, err := LoadConfig()
	if err != nil {
		return "", nil, err
	}
	disableContext := cfg["DISABLE_CONTEXT"] == "1" || cfg["JIRA_DISABLE_CONTEXT"] == "1"
	apiKey := cfg["GEMINI_API_KEY"]
	if apiKey == "" {
		return "", nil, fmt.Errorf("GEMINI_API_KEY missing")
	}
	client, err := genai.NewClient(ctx, &genai.ClientConfig{APIKey: apiKey})
	if err != nil {
		return "", nil, err
	}

	maxIterations := 30
	originalTask := task
	var history []string
	// Aggregated, rolling context provided by the model via current_context/current_content
	var currentContext []string
	if !disableContext && len(initialContext) > 0 {
		currentContext = MergeStringSets(currentContext, initialContext)
	}

	for i := 0; i < maxIterations; i++ {
		currentPrompt := originalTask
		if len(history) > 0 {
			currentPrompt = fmt.Sprintf("Original Task: %s\n\nHistory of actions:\n%s", originalTask, strings.Join(history, "\n"))
		}

		responseText, toolCall, err := callGeminiAPI(ctx, client, currentPrompt, currentContext, disableContext)
		if err != nil {
			slog.Error("Error from Gemini in loop", "error", err)
			return "", currentContext, err
		}
		// Merge model-provided context only when enabled
		if !disableContext && len(toolCall.GetMergedContext()) > 0 {
			slog.Info("Context from toolCall", "current_context", toolCall.CurrentContext, "current_content", toolCall.CurrentContent)
			incoming := SanitizeContextFacts(toolCall.GetMergedContext())
			currentContext = MergeStringSets(currentContext, incoming)
			maxItems := getContextMaxItems()
			if len(currentContext) > maxItems {
				currentContext = currentContext[len(currentContext)-maxItems:]
			}
			slog.Info("Updated current_context", "current_context", currentContext)
		}

		if toolCall.Tool != "" {
			toolResp, err := ExecuteTool(toolCall.Tool, toolCall.Args)
			if err != nil {
				return "", currentContext, err
			}

			// Add tool call and result to history
			history = append(history, fmt.Sprintf("- Tool call: %s with args %v", toolCall.Tool, toolCall.Args))
			history = append(history, fmt.Sprintf("- Tool result: %s", SummarizeToolResponse(toolResp.Success, toolResp.Data, toolResp.Error)))
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
