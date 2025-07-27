package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
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
	configData, err := os.ReadFile(os.ExpandEnv("$HOME/.config/go-thing/config"))
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

	// Check if filePath is within writeDir
	absWriteDir, _ := filepath.Abs(writeDir)
	absFilePath, _ := filepath.Abs(path)
	if !strings.HasPrefix(absFilePath, absWriteDir) {
		return &ToolResponse{
			Success: false,
			Error:   "Write denied: path outside allowed directory",
		}, nil
	}

	// Create directory if it doesn't exist
	dir := filepath.Dir(absFilePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return &ToolResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to create directory: %v", err),
		}, nil
	}

	// Write the file
	err = os.WriteFile(absFilePath, []byte(content), 0644)
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
			"path":    absFilePath,
		},
	}, nil
}

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

		// Execute tool
		var response *ToolResponse
		var err error

		switch req.Tool {
		case "disk_space":
			response, err = executeDiskSpaceTool(req.Args)
		case "write_file":
			response, err = executeWriteFileTool(req.Args)
		default:
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
