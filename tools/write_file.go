package tools

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/ini.v1"

	"go-thing/internal/config"
)

func executeWriteFileTool(args map[string]interface{}) (*ToolResponse, error) {
	path, ok := args["path"].(string)
	if !ok || path == "" {
		return &ToolResponse{Success: false, Error: "path parameter is required"}, nil
	}

	content, ok := args["content"].(string)
	if !ok {
		return &ToolResponse{Success: false, Error: "content parameter is required"}, nil
	}

	// Read config
	cfg, err := ini.Load(os.ExpandEnv(config.ConfigFilePath))
	if err != nil {
		return &ToolResponse{Success: false, Error: fmt.Sprintf("Config file error: %v", err)}, nil
	}

	// Load from [default] section
	defaultSection := cfg.Section("default")
	writeDir := defaultSection.Key("CHROOT_DIR").String()
	if writeDir == "" {
		return &ToolResponse{Success: false, Error: "CHROOT_DIR not configured in [default] section"}, nil
	}

	// Check if filePath is within writeDir
	absWriteDir, _ := filepath.Abs(writeDir)
	absFilePath, _ := filepath.Abs(path)
	if !strings.HasPrefix(absFilePath, absWriteDir) {
		return &ToolResponse{Success: false, Error: "Write denied: path outside allowed directory"}, nil
	}

	// Create directory if it doesn't exist
	dir := filepath.Dir(absFilePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return &ToolResponse{Success: false, Error: fmt.Sprintf("Failed to create directory: %v", err)}, nil
	}

	// Write the file
	if err := os.WriteFile(absFilePath, []byte(content), 0644); err != nil {
		return &ToolResponse{Success: false, Error: fmt.Sprintf("Failed to write file: %v", err)}, nil
	}

	return &ToolResponse{
		Success: true,
		Data: map[string]string{
			"message": "File written successfully",
			"path":    absFilePath,
		},
	}, nil
}

func init() {
	// Register tool metadata
	tools["write_file"] = Tool{
		Name:        "write_file",
		Description: "Write content to a file in the configured chroot directory",
		Help: `Usage: /tool write_file --path <filepath> --content <content>

Parameters:
  --path <filepath>    Path to the file to write (must be within configured CHROOT_DIR)
  --content <content>  Content to write to the file

Examples:
  /tool write_file --path test.txt --content "Hello World"
  /tool write_file --help`,
		Parameters: map[string]string{
			"path":    "Path to the file to write",
			"content": "Content to write to the file",
		},
	}

	// Register executor
	toolExecutors["write_file"] = executeWriteFileTool
}
