package tools

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/ini.v1"

	"go-thing/internal/config"
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
	var timeoutSec int = 60
	if v, ok := args["timeout_sec"]; ok {
		switch tv := v.(type) {
		case float64:
			// JSON numbers decode to float64
			timeoutSec = int(tv)
		case int:
			timeoutSec = tv
		case string:
			if s := strings.TrimSpace(tv); s != "" {
				if n, err := fmt.Sscanf(s, "%d", &timeoutSec); n == 1 && err == nil {
					// parsed
				}
			}
		}
	}
	if timeoutSec <= 0 || timeoutSec > 600 {
		// clamp to sane range [1, 600]
		timeoutSec = 60
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

	absChroot, _ := filepath.Abs(chroot)
	absChroot = filepath.Clean(absChroot)

	// Resolve working directory within chroot
	targetDir := absChroot
	if strings.TrimSpace(workdirArg) != "" {
		candidate := workdirArg
		if !filepath.IsAbs(candidate) {
			candidate = filepath.Join(absChroot, candidate)
		}
		absCandidate, _ := filepath.Abs(candidate)
		absCandidate = filepath.Clean(absCandidate)
		if rel, err := filepath.Rel(absChroot, absCandidate); err != nil || strings.HasPrefix(rel, "..") || (rel == "." && absCandidate == absChroot) {
			return &ToolResponse{Success: false, Error: "Execution denied: workdir outside allowed directory"}, nil
		}
		// ensure exists, else use chroot (or we can create); we will ensure it exists and is dir
		if fi, err := os.Stat(absCandidate); err == nil && fi.IsDir() {
			targetDir = absCandidate
		} else if err != nil {
			return &ToolResponse{Success: false, Error: fmt.Sprintf("Invalid workdir: %v", err)}, nil
		} else {
			return &ToolResponse{Success: false, Error: "Invalid workdir: not a directory"}, nil
		}
	}

	// Build command using shell for simplicity of pipelines
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSec)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "/bin/sh", "-lc", cmdStr)
	cmd.Dir = targetDir
	// Inherit environment, but we could restrict if needed
	cmd.Env = os.Environ()

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
