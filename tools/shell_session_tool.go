package tools

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// removeANSI strips common ANSI escape sequences (CSI and OSC) from PTY output.
// This keeps only printable text so we can reliably find sentinel lines.
func removeANSI(s string) string {
	r := []rune(s)
	out := make([]rune, 0, len(r))
	for i := 0; i < len(r); {
		if r[i] != 0x1b { // not ESC
			out = append(out, r[i])
			i++
			continue
		}
		// ESC sequence
		i++
		if i >= len(r) { break }
		switch r[i] {
		case '[': // CSI: ESC [ ... final @-~
			i++
			for i < len(r) {
				if r[i] >= '@' && r[i] <= '~' { i++; break }
				i++
			}
		case ']': // OSC: ESC ] ... (BEL) or ESC \
			i++
			for i < len(r) {
				if r[i] == 0x07 { i++; break } // BEL
				if r[i] == 0x1b && i+1 < len(r) && r[i+1] == '\\' { i += 2; break } // ST
				i++
			}
		default:
			// Skip this short escape
			i++
		}
	}
	return string(out)
}

// extractCwdAndTrim searches for a PWD sentinel line (pwdMark) in seg.
// If found, it sets cwd to the detected path and returns seg with the PWD line removed.
// It handles the sentinel appearing at the start of seg or after a newline.
func extractCwdAndTrim(seg, pwdMark string) (out string, cwd string) {
    lines := strings.Split(seg, "\n")
    foundIdx := -1

    // Find the last occurrence of the PWD sentinel line, matching original LastIndex behavior
    for i := len(lines) - 1; i >= 0; i-- {
        if strings.HasPrefix(lines[i], pwdMark) {
            cwd = strings.TrimPrefix(lines[i], pwdMark)
            foundIdx = i
            break
        }
    }

    if foundIdx == -1 {
        return seg, ""
    }

    // Rebuild the output without the sentinel line using a single slice append
    // for better performance and fewer allocations on large outputs.
    return strings.Join(append(lines[:foundIdx], lines[foundIdx+1:]...), "\n"), cwd
}

// executeShellSessionTool runs a command in a persistent interactive shell session managed by ShellBroker.
// Args:
//   id (string, required): session identifier
//   subdir (string, optional): subdir under CHROOT_DIR to map as workdir for new sessions; ignored if session exists
//   command (string, required): the shell command to send (newline auto-appended if missing)
//   timeout_ms (int, optional): capture timeout, default 5000ms
// Behavior:
//   - Ensures the session exists
//   - Subscribes to output
//   - Sends a wrapped command with start/end sentinels
//   - Captures bytes between sentinels and returns as output
func executeShellSessionTool(args map[string]interface{}) (*ToolResponse, error) {
	idVal, _ := args["id"].(string)
	if strings.TrimSpace(idVal) == "" {
		return &ToolResponse{Success: false, Error: "id parameter is required"}, nil
	}
	subdir, _ := args["subdir"].(string)
	cmdStr, _ := args["command"].(string)
	if strings.TrimSpace(cmdStr) == "" {
		return &ToolResponse{Success: false, Error: "command parameter is required"}, nil
	}
	// timeout
	timeoutMs := 5000
	if v, ok := args["timeout_ms"]; ok {
		switch tv := v.(type) {
		case float64:
			timeoutMs = int(tv)
		case int:
			timeoutMs = tv
		case string:
			if n, err := strconv.Atoi(strings.TrimSpace(tv)); err == nil { timeoutMs = n }
		}
	}
	if timeoutMs < 500 { timeoutMs = 500 }
	if timeoutMs > 60000 { timeoutMs = 60000 }

	sess, err := GetShellBroker().CreateOrGet(idVal, subdir)
	if err != nil {
		return &ToolResponse{Success: false, Error: fmt.Sprintf("session error: %v", err)}, nil
	}

	// Subscribe
	outCh := sess.Subscribe()
	defer sess.Unsubscribe(outCh)

	// Unique sentinel (time-based)
	tag := fmt.Sprintf("T%v", time.Now().UnixNano())
	startMark := "__START__" + tag
	endMark := "__END__" + tag
	pwdMark := "__PWD__" + tag

	// Send wrapped command (must end with newline so the shell executes it). Use printf for predictable output.
	// Also emit a PWD sentinel line that includes the effective cwd after the command runs.
	// We escape %% in the format string so Go doesn't consume it; the shell printf will.
	wrapped := fmt.Sprintf(
		"printf '%s\\n'; { %s ; }; printf '%%s%%s\\n' '%s' \"$(pwd)\"; printf '%s\\n'\n",
		startMark, cmdStr, pwdMark, endMark,
	)
	if !sess.Enqueue([]byte(wrapped)) {
		return &ToolResponse{Success: false, Error: "shell input queue is full; please retry shortly"}, nil
	}

	deadlineTimer := time.NewTimer(time.Duration(timeoutMs) * time.Millisecond)
	defer deadlineTimer.Stop()
	var outBuf bytes.Buffer
	var cwdDetected string
	// Accumulator to handle sentinel split across reads
	var acc strings.Builder
	seenStart := false
	// Helpers: strip ANSI, normalize CRLF/CR to LF
	normalize := func(b []byte) string {
		// Remove ANSI escape sequences
		s := removeANSI(string(b))
		// Normalize newlines
		s = strings.ReplaceAll(s, "\r\n", "\n")
		s = strings.ReplaceAll(s, "\r", "\n")
		return s
	}
ReadLoop:
	for {
		select {
		case data, ok := <-outCh:
			if !ok { break ReadLoop }
			// Append to accumulator and operate on the full buffer
			acc.WriteString(normalize(data))
			cur := acc.String()
			if !seenStart {
				// Find a start marker that appears as a full line (LF-delimited)
				if strings.HasPrefix(cur, startMark+"\n") {
					cur = cur[len(startMark)+1:]
					seenStart = true
					acc.Reset(); acc.WriteString(cur)
				} else if i := strings.Index(cur, "\n"+startMark+"\n"); i >= 0 {
					cut := i + 1 + len(startMark) + 1
					cur = cur[cut:]
					seenStart = true
					acc.Reset(); acc.WriteString(cur)
				} else {
					// Keep acc bounded
					if acc.Len() > 8192 {
						s := acc.String()
						s = s[len(s)-1024:]
						acc.Reset(); acc.WriteString(s)
					}
					continue
				}
			}
			// seenStart == true here
			cur = acc.String()
			// Find end marker; capture content up to it (LF-delimited)
			if i := strings.Index(cur, "\n"+endMark); i >= 0 {
				outSeg := cur[:i]
				outBuf.WriteString(outSeg)
				break ReadLoop
			}
			// Not found yet; keep a small tail for upcoming endMark detection.
			// To avoid losing data for large outputs, write the truncated prefix to outBuf.
			tailKeep := len(endMark) + 512
			if acc.Len() > tailKeep {
				s := acc.String()
				toWrite := s[:len(s)-tailKeep]
				tail := s[len(s)-tailKeep:]
				outBuf.WriteString(toWrite)
				acc.Reset()
				acc.WriteString(tail)
			}
		case <-deadlineTimer.C:
			break ReadLoop
		}
	}
	// Post-loop finalization: combine remaining accumulator and process output
	// Combine the main buffer and the accumulator's remaining content to get the full output.
	outBuf.WriteString(acc.String())
	// Extract cwd from the captured segment, removing the PWD line from output if present.
	seg := outBuf.String()
	seg, cwd := extractCwdAndTrim(seg, pwdMark)
	out := strings.TrimSpace(seg)
	cwdDetected = cwd
	if cwdDetected == "" {
		cwdDetected = sess.Workdir
	}
	return &ToolResponse{Success: true, Data: map[string]interface{}{
		"id":      idVal,
		"workdir": sess.Workdir,
		"cwd":     cwdDetected,
		"output":  out,
	}}, nil
}

func init() {
	tools["shell_session"] = Tool{
		Name:        "shell_session",
		Description: "Run a command inside a named persistent shell session (stateful, shared).",
		Help: `Usage: /tool shell_session --id <name> [--subdir <rel>] --command <cmd> [--timeout_ms <n>]

Examples:
  /tool shell_session --id dev --command "pwd"
  /tool shell_session --id dev --subdir repo --command "npm run dev" --timeout_ms 2000
  /tool shell_session --id logs --subdir repo --command "tail -f logs/app.log"`,
		Parameters: map[string]string{
			"id":         "Session identifier (required)",
			"subdir":     "Optional subdirectory under CHROOT_DIR for initial workdir when creating a session",
			"command":    "Shell command to send (newline auto-appended)",
			"timeout_ms": "Capture timeout in milliseconds (default 5000, min 500, max 60000)",
		},
	}
	toolExecutors["shell_session"] = executeShellSessionTool
}
