package utility

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"regexp"
	"strings"

	tools "go-thing/tools"
)

// ParseAndExecuteTool parses a /tool command and executes it via the tool server.
func ParseAndExecuteTool(command string) (string, error) {
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
	if strings.Contains(argsString, "--help") {
		tool, err := GetToolHelp(toolName)
		if err != nil {
			return fmt.Sprintf("Error getting help for %s: %v", toolName, err), nil
		}
		return fmt.Sprintf("Help for %s:\n%s", toolName, tool.Help), nil
	}
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
	resp, err := ExecuteTool(toolName, args)
	if err != nil {
		return fmt.Sprintf("Error executing tool %s: %v", toolName, err), nil
	}
	if !resp.Success {
		return fmt.Sprintf("Tool %s failed: %s", toolName, resp.Error), nil
	}
	resultBytes, err := json.MarshalIndent(resp.Data, "", "  ")
	if err != nil {
		return fmt.Sprintf("Tool %s executed successfully, but failed to format result", toolName), nil
	}
	return fmt.Sprintf("Tool %s executed successfully:\n```json\n%s\n```", toolName, string(resultBytes)), nil
}

// GetToolsAddr returns the tools server address from config or a default.
func GetToolsAddr() string {
	cfg, err := LoadConfig()
	if err != nil {
		return ":8080"
	}
	if v, ok := cfg["TOOLS_ADDR"]; ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return ":8080"
}

// GetAvailableTools fetches the list of tools from the tool server.
func GetAvailableTools() ([]tools.Tool, error) {
	addr := GetToolsAddr()
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
	var tr tools.ToolResponse
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
	var list []tools.Tool
	if err := json.Unmarshal(b, &list); err != nil {
		return nil, err
	}
	return list, nil
}

// ExecuteTool posts a tool execution request to the tool server.
func ExecuteTool(toolName string, args map[string]interface{}) (*tools.ToolResponse, error) {
	addr := GetToolsAddr()
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
	var tr tools.ToolResponse
	if err := json.Unmarshal(rb, &tr); err != nil {
		return nil, err
	}
	return &tr, nil
}

// GetToolHelp finds a tool definition by name from the live registry via the tool server.
func GetToolHelp(toolName string) (*tools.Tool, error) {
	list, err := GetAvailableTools()
	if err != nil {
		return nil, err
	}
	for _, t := range list {
		if t.Name == toolName {
			return &t, nil
		}
	}
	return nil, fmt.Errorf("Tool not found: %s", toolName)
}

// ListAvailableTools renders a human-readable list of tools and their parameters.
func ListAvailableTools() (string, error) {
	available, err := GetAvailableTools()
	if err != nil {
		return fmt.Sprintf("Error getting available tools: %v", err), nil
	}
	var result strings.Builder
	result.WriteString("Available tools:\n\n")
	for _, tool := range available {
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
