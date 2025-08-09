package tools

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/ini.v1"

	"go-thing/internal/config"
)

const (
	// defaultTimeoutSec is the default execution timeout in seconds for shell_exec commands.
	defaultTimeoutSec = 60
	// maxTimeoutSec is the maximum allowed timeout in seconds to prevent runaway executions.
	maxTimeoutSec = 600
)

// executeShellExecTool runs a shell command with the working directory constrained to CHROOT_DIR (or a subdirectory of it)
func executeShellExecTool(args map[string]interface{}) (*ToolResponse, error) {
	cmdStr, ok := args["command"].(string)
	if !ok || strings.TrimSpace(cmdStr) == "" {
		return &ToolResponse{Success: false, Error: "command parameter is required"}, nil
	}

	// Optional working directory relative to CHROOT
	workdirArg, _ := args["workdir"].(string)

	// Optional timeout seconds
	var timeoutSec int = defaultTimeoutSec
	if v, ok := args["timeout_sec"]; ok {
		switch tv := v.(type) {
		case float64:
			// JSON numbers decode to float64
			timeoutSec = int(tv)
		case int:
			timeoutSec = tv
		case string:
			if n, err := strconv.Atoi(strings.TrimSpace(tv)); err == nil {
				timeoutSec = n
			}
		}
	}
	if timeoutSec <= 0 {
		timeoutSec = 1
	} else if timeoutSec > maxTimeoutSec {
		timeoutSec = maxTimeoutSec
	}

	// Read config for chroot
	cfg, err := ini.Load(os.ExpandEnv(config.ConfigFilePath))
	if err != nil {
		return &ToolResponse{Success: false, Error: fmt.Sprintf("Config file error: %v", err)}, nil
	}
	defaultSection := cfg.Section("default")
	chroot := defaultSection.Key("CHROOT_DIR").String()
	if strings.TrimSpace(chroot) == "" {
		return &ToolResponse{Success: false, Error: "CHROOT_DIR not configured in [default] section"}, nil
	}

	absChroot, err := filepath.Abs(chroot)
	if err != nil {
		return &ToolResponse{Success: false, Error: fmt.Sprintf("Could not determine absolute path for CHROOT_DIR: %v", err)}, nil
	}
	absChroot = filepath.Clean(absChroot)

	// Resolve working directory within chroot
	targetDir := absChroot
	if strings.TrimSpace(workdirArg) != "" {
		candidate := workdirArg
		if !filepath.IsAbs(candidate) {
			candidate = filepath.Join(absChroot, candidate)
		}
		absCandidate, err := filepath.Abs(candidate)
		if err != nil {
			return &ToolResponse{Success: false, Error: fmt.Sprintf("Could not determine absolute path for workdir: %v", err)}, nil
		}
		absCandidate = filepath.Clean(absCandidate)
		// Allow CHROOT_DIR itself as a valid working directory. Only deny if outside CHROOT.
		if rel, err := filepath.Rel(absChroot, absCandidate); err != nil || strings.HasPrefix(rel, "..") {
			return &ToolResponse{Success: false, Error: "Execution denied: workdir outside allowed directory"}, nil
		}
		// ensure the resolved working directory exists and is a directory
		if fi, err := os.Stat(absCandidate); err == nil && fi.IsDir() {
			targetDir = absCandidate
		} else if err != nil {
			return &ToolResponse{Success: false, Error: fmt.Sprintf("Invalid workdir: %v", err)}, nil
		} else {
			return &ToolResponse{Success: false, Error: "Invalid workdir: not a directory"}, nil
		}
	}

	// Ensure the Docker container is running and compute container workdir mapping
	containerName, derr := EnsureDockerContainer()
	if derr != nil {
		return &ToolResponse{Success: false, Error: fmt.Sprintf("Container setup error: %v", derr)}, nil
	}

	// Map targetDir within CHROOT to /app path in container
	relPath, _ := filepath.Rel(absChroot, targetDir)
	containerWorkdir := "/app"
	if relPath != "." && strings.TrimSpace(relPath) != "" {
		// Use forward slashes for docker exec path
		containerWorkdir = "/app/" + filepath.ToSlash(relPath)
	}

	// Build docker exec command executing shell inside the container with timeout
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSec)*time.Second)
	defer cancel()

	// We avoid -t to keep non-interactive; use -i for stdin-less execution is fine to omit
	execArgs := []string{"exec", "-w", containerWorkdir, containerName, "/bin/sh", "-lc", cmdStr}
	cmd := exec.CommandContext(ctx, "docker", execArgs...)
	// Clear environment for safety
	cmd.Env = []string{}

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	err = cmd.Run()

	// Check for timeout
	if ctx.Err() == context.DeadlineExceeded {
		return &ToolResponse{Success: false, Error: fmt.Sprintf("Command timed out after %ds", timeoutSec)}, nil
	}

	exitCode := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			// Process exited with non-zero
			exitCode = ee.ExitCode()
		} else {
			// Other error (e.g., binary not found)
			return &ToolResponse{Success: false, Error: fmt.Sprintf("Execution error: %v", err)}, nil
		}
	}

	data := map[string]interface{}{
		"command":   cmdStr,
		"workdir":   targetDir,
		"exit_code": exitCode,
		"stdout":    stdoutBuf.String(),
		"stderr":    stderrBuf.String(),
	}

	// Success is true even for non-zero exit codes; caller can inspect exit_code
	return &ToolResponse{Success: true, Data: data}, nil
}

func init() {
	tools["shell_exec"] = Tool{
		Name:        "shell_exec",
		Description: "Execute a shell command within the configured chroot directory (working dir is CHROOT_DIR unless workdir provided)",
		Help: `Usage: /tool shell_exec --command <shell_command> [--workdir <dir>] [--timeout_sec <n>]

Parameters:
  --command <shell_command>  Command to execute (interpreted by /bin/sh -lc)
  --workdir <dir>            Optional working directory relative to CHROOT_DIR
  --timeout_sec <n>          Optional timeout in seconds (default 60, max 600)

Examples:
  /tool shell_exec --command "ls -la"
  /tool shell_exec --command "grep -R TODO ." --workdir src
  /tool shell_exec --help`,
		Parameters: map[string]string{
			"command":     "Command to execute (interpreted by /bin/sh -lc)",
			"workdir":     "Optional working directory relative to CHROOT_DIR",
			"timeout_sec": "Optional timeout in seconds (default 60, max 600)",
		},
	}
	toolExecutors["shell_exec"] = executeShellExecTool
}
