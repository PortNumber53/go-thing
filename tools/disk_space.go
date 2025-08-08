package tools

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

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

func getDiskSpace(path string) (*DiskSpaceInfo, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
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
		return &ToolResponse{Success: false, Error: fmt.Sprintf("Invalid path: %v", err)}, nil
	}

	// Check if path exists
	if _, err := os.Stat(absPath); os.IsNotExist(err) {
		return &ToolResponse{Success: false, Error: fmt.Sprintf("Path does not exist: %s", absPath)}, nil
	}

	diskInfo, err := getDiskSpace(absPath)
	if err != nil {
		return &ToolResponse{Success: false, Error: fmt.Sprintf("Failed to get disk space: %v", err)}, nil
	}

	return &ToolResponse{Success: true, Data: diskInfo}, nil
}

func init() {
	// Register tool metadata
	tools["disk_space"] = Tool{
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
	}

	// Register executor
	toolExecutors["disk_space"] = executeDiskSpaceTool
}
