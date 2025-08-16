package utility

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"google.golang.org/genai"
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
			log.Printf("[Gemini API] Failed to marshal persisted context: %v", err)
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
		// Log parsed context if present and not disabled
		if !disableContext && (len(toolCall.CurrentContext) > 0 || len(toolCall.CurrentContent) > 0) {
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

// GeminiAPIHandler runs the LLM/tool loop. It accepts an initialContext (persisted across turns)
// and returns the final assistant response and the updated current_context slice.
func GeminiAPIHandler(ctx context.Context, task string, initialContext []string) (string, []string, error) {
	log.Printf("[Gemini API] Handler invoked for task: %s", task)
	if len(initialContext) > 0 {
		log.Printf("[Context] Loaded initial current_context: %v", initialContext)
	} else {
		log.Printf("[Context] No initial current_context loaded")
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
			log.Printf("[Gemini Loop] Error from Gemini: %v", err)
			return "", currentContext, err
		}
		// Merge model-provided context only when enabled
		if !disableContext && len(toolCall.GetMergedContext()) > 0 {
			log.Printf("[Context] From toolCall: current_context=%v current_content=%v", toolCall.CurrentContext, toolCall.CurrentContent)
			incoming := SanitizeContextFacts(toolCall.GetMergedContext())
			currentContext = MergeStringSets(currentContext, incoming)
			maxItems := getContextMaxItems()
			if len(currentContext) > maxItems {
				currentContext = currentContext[len(currentContext)-maxItems:]
			}
			log.Printf("[Context] Updated current_context: %v", currentContext)
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
