package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
)

// Tool represents a tool definition
type Tool struct {
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Help        string            `json:"help"`
	Parameters  map[string]string `json:"parameters,omitempty"`
}

// ToolRequest represents a request to execute a tool
type ToolRequest struct {
	Tool string                 `json:"tool"`
	Args map[string]interface{} `json:"args,omitempty"`
	Help bool                   `json:"help,omitempty"`
}

// ToolResponse represents a response from a tool execution
type ToolResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

// ToolExecutor is a function that executes a tool by name
type ToolExecutor func(args map[string]interface{}) (*ToolResponse, error)

// Registry mapping tool name to executor implementation
var toolExecutors = map[string]ToolExecutor{}

// Available tools registry
var tools = map[string]Tool{}

func toolHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Handle GET request for tool listing
	if r.Method == "GET" {
		toolList := make([]Tool, 0, len(tools))
		for _, tool := range tools {
			toolList = append(toolList, tool)
		}

		response := ToolResponse{
			Success: true,
			Data:    toolList,
		}

		json.NewEncoder(w).Encode(response)
		return
	}

	// Handle POST request for tool execution
	if r.Method == "POST" {
		var req ToolRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			response := ToolResponse{
				Success: false,
				Error:   fmt.Sprintf("Invalid JSON: %v", err),
			}
			json.NewEncoder(w).Encode(response)
			return
		}

		// Handle help request
		if req.Help {
			tool, exists := tools[req.Tool]
			if !exists {
				response := ToolResponse{
					Success: false,
					Error:   fmt.Sprintf("Tool not found: %s", req.Tool),
				}
				json.NewEncoder(w).Encode(response)
				return
			}

			response := ToolResponse{
				Success: true,
				Data:    tool,
			}
			json.NewEncoder(w).Encode(response)
			return
		}

		// Execute tool via registry dispatcher
		var response *ToolResponse
		var err error

		if exec, ok := toolExecutors[req.Tool]; ok {
			response, err = exec(req.Args)
		} else {
			response = &ToolResponse{
				Success: false,
				Error:   fmt.Sprintf("Unknown tool: %s", req.Tool),
			}
		}

		if err != nil {
			response = &ToolResponse{
				Success: false,
				Error:   fmt.Sprintf("Tool execution error: %v", err),
			}
		}

		json.NewEncoder(w).Encode(response)
		return
	}

	// Handle unsupported methods
	response := ToolResponse{
		Success: false,
		Error:   "Method not allowed",
	}
	w.WriteHeader(http.StatusMethodNotAllowed)
	json.NewEncoder(w).Encode(response)
}

func main() {
	http.HandleFunc("/api/tools", toolHandler)
	log.Println("Starting tool server on :8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal(err)
	}
}
