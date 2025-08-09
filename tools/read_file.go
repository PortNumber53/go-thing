package tools

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/ini.v1"

	"go-thing/internal/config"
)

func executeReadFileTool(args map[string]interface{}) (*ToolResponse, error) {
	path, ok := args["path"].(string)
	if !ok || path == "" {
		return &ToolResponse{Success: false, Error: "path parameter is required"}, nil
	}

	// Read config
	cfg, err := ini.Load(os.ExpandEnv(config.ConfigFilePath))
	if err != nil {
		return &ToolResponse{Success: false, Error: fmt.Sprintf("Config file error: %v", err)}, nil
	}
	defaultSection := cfg.Section("default")
	chroot := defaultSection.Key("CHROOT_DIR").String()
	if chroot == "" {
		return &ToolResponse{Success: false, Error: "CHROOT_DIR not configured in [default] section"}, nil
	}

absChroot, err := filepath.Abs(chroot)
if err != nil {
	return &ToolResponse{Success: false, Error: fmt.Sprintf("Failed to resolve chroot directory: %v", err)}, nil
}
// Build absolute path anchored in chroot if relative was provided
candidate := path
if !filepath.IsAbs(candidate) {
	candidate = filepath.Join(absChroot, candidate)
}
absPath, err := filepath.Abs(candidate)
if err != nil {
	return &ToolResponse{Success: false, Error: fmt.Sprintf("Failed to resolve file path: %v", err)}, nil
}
absPath = filepath.Clean(absPath)
	// Ensure the target stays within chroot using Rel to avoid prefix tricks
	rel, err := filepath.Rel(absChroot, absPath)
	if err != nil || strings.HasPrefix(rel, "..") || rel == "." && absPath == absChroot {
		return &ToolResponse{Success: false, Error: "Read denied: path outside allowed directory"}, nil
	}

	// Enforce file existence and that it's not a directory
	info, err := os.Stat(absPath)
	if err != nil {
		if os.IsNotExist(err) {
			return &ToolResponse{Success: false, Error: "File does not exist"}, nil
		}
		return &ToolResponse{Success: false, Error: fmt.Sprintf("Failed to stat file: %v", err)}, nil
	}
	if info.IsDir() {
		return &ToolResponse{Success: false, Error: "Path is a directory, not a file"}, nil
	}

	data, err := os.ReadFile(absPath)
	if err != nil {
		return &ToolResponse{Success: false, Error: fmt.Sprintf("Failed to read file: %v", err)}, nil
	}

	return &ToolResponse{
		Success: true,
		Data: map[string]interface{}{
			"path":    absPath,
			"size":    len(data),
			"content": string(data),
		},
	}, nil
}

func init() {
	tools["read_file"] = Tool{
		Name:        "read_file",
		Description: "Read the contents of a file within the configured chroot directory",
		Help: `Usage: /tool read_file --path <filepath>

Parameters:
  --path <filepath>    Path to the file to read (must be within configured CHROOT_DIR)

Examples:
  /tool read_file --path test.txt
  /tool read_file --help`,
		Parameters: map[string]string{
			"path": "Path to the file to read",
		},
	}
	toolExecutors["read_file"] = executeReadFileTool
}
