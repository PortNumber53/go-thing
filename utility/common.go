package utility

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// RunDockerExec runs `docker exec` with the given args inside the specified container.
// Returns stdout/stderr as strings with a timeout.
func RunDockerExec(container string, args []string, timeout time.Duration) (string, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	full := append([]string{"exec", container}, args...)
	cmd := exec.CommandContext(ctx, "docker", full...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

// EnsureSSHKeygenAvailable ensures ssh-keygen exists in the container; if missing, installs openssh via pacman.
func EnsureSSHKeygenAvailable(container string) error {
	// Check presence using shell built-in to avoid relying on ssh-keygen exit codes
	if out, _, err := RunDockerExec(container, []string{"bash", "-lc", "command -v ssh-keygen"}, 10*time.Second); err == nil && strings.TrimSpace(out) != "" {
		return nil
	}
	// Attempt install on Arch base
	if _, stderr, err := RunDockerExec(container, []string{"bash", "-lc", "pacman -Sy --noconfirm && pacman -S --noconfirm --needed openssh"}, 2*time.Minute); err != nil {
		return fmt.Errorf("failed to install openssh in container: %v (stderr: %s)", err, strings.TrimSpace(stderr))
	}
	// Re-check using command -v again
	if out, _, err := RunDockerExec(container, []string{"bash", "-lc", "command -v ssh-keygen"}, 10*time.Second); err != nil || strings.TrimSpace(out) == "" {
		return fmt.Errorf("ssh-keygen still unavailable after install: %v", err)
	}
	return nil
}

// Dummy bcrypt compare utilities for timing mitigation
var (
	dummyHashOnce sync.Once
	dummyHash     []byte
)

// DummyBcryptCompare performs a bcrypt comparison against a dummy hash to
// normalize timing between "user not found" and "wrong password" cases.
// The dummy hash is generated once at runtime to avoid shipping a hardcoded hash.
func DummyBcryptCompare(password string) {
	dummyHashOnce.Do(func() {
		// Generate a hash once; cost matches default user hashing cost.
		h, err := bcryptGenerateFromPassword([]byte("dummy-password-for-timing-only"))
		if err != nil {
			log.Fatalf("[Auth] CRITICAL: failed to generate dummy bcrypt hash for timing attack mitigation: %v", err)
		}
		dummyHash = h
	})
	// The dummyHash is guaranteed to be non-empty here due to log.Fatalf on error.
	_ = bcryptCompareHashAndPassword(dummyHash, []byte(password))
}

// Small indirection helpers to keep this file decoupled for testing/mocking
var (
	bcryptGenerateFromPassword   = func(pw []byte) ([]byte, error) { return bcrypt.GenerateFromPassword(pw, bcrypt.DefaultCost) }
	bcryptCompareHashAndPassword = func(hash, pw []byte) error { return bcrypt.CompareHashAndPassword(hash, pw) }
)
