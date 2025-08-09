package tools

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"gopkg.in/ini.v1"

	"go-thing/internal/config"
)

// Defaults used if not overridden via config
const (
	defaultDockerName  = "go-thing-arch"
	defaultDockerImage = "archlinux:latest"
	defaultAutoRemove  = true
)

// EnsureDockerContainer ensures an Arch-based container is running with CHROOT_DIR mounted at /app.
// Optional config keys in [default]:
//   DOCKER_CONTAINER_NAME, DOCKER_IMAGE, DOCKER_EXTRA_ARGS, DOCKER_AUTO_REMOVE
func EnsureDockerContainer() (string, error) {
	name, image, extra, absChroot, err := resolveDockerSettings()
	if err != nil {
		return "", err
	}

	// If container exists and running -> OK
	running, exists, err := inspectContainerRunning(name)
	if err != nil {
		return "", err
	}
	if exists {
		if running {
			return name, nil
		}
		if err := dockerStart(name); err != nil {
			return "", fmt.Errorf("failed to start existing container %s: %w", name, err)
		}
		return name, nil
	}

	// Create new container
	if err := dockerRunDetached(name, image, extra, absChroot); err != nil {
		return "", err
	}
	return name, nil
}

// Cached settings to avoid repeated config reads
var (
	settingsOnce              sync.Once
	cachedName                string
	cachedImage               string
	cachedExtra               string
	cachedAbsChroot           string
	cachedSettingsLoadErr     error
)

// resolveDockerSettings reads INI config once and returns (name, image, extraArgs, absChroot)
func resolveDockerSettings() (string, string, string, string, error) {
	settingsOnce.Do(func() {
		cfg, err := ini.Load(os.ExpandEnv(config.ConfigFilePath))
		if err != nil {
			cachedSettingsLoadErr = fmt.Errorf("config file error: %v", err)
			return
		}
		s := cfg.Section("default")
		chroot := strings.TrimSpace(s.Key("CHROOT_DIR").String())
		if chroot == "" {
			cachedSettingsLoadErr = fmt.Errorf("CHROOT_DIR not configured in [default] section")
			return
		}
		absChroot, err := filepath.Abs(chroot)
		if err != nil {
			cachedSettingsLoadErr = fmt.Errorf("could not resolve CHROOT_DIR: %v", err)
			return
		}
		if fi, err := os.Stat(absChroot); err != nil || !fi.IsDir() {
			cachedSettingsLoadErr = fmt.Errorf("CHROOT_DIR does not exist or is not a directory: %s", absChroot)
			return
		}

		name := strings.TrimSpace(s.Key("DOCKER_CONTAINER_NAME").String())
		if name == "" {
			name = defaultDockerName
		}
		image := strings.TrimSpace(s.Key("DOCKER_IMAGE").String())
		if image == "" {
			image = defaultDockerImage
		}
		extra := strings.TrimSpace(s.Key("DOCKER_EXTRA_ARGS").String())

		cachedName = name
		cachedImage = image
		cachedExtra = extra
		cachedAbsChroot = absChroot
	})
	return cachedName, cachedImage, cachedExtra, cachedAbsChroot, cachedSettingsLoadErr
}

func dockerRunDetached(name, image, extra, absChroot string) error {
	// Build docker run args: detached container that stays up, CHROOT_DIR mounted at /app, workdir /app
	args := []string{
		"run", "-d", "--name", name,
		"-v", fmt.Sprintf("%s:/app", absChroot),
		"-w", "/app",
	}
	if extra != "" {
		// Split on whitespace to get individual flags; if advanced quoting is required later,
		// we can swap to a shellwords parser. For now this mitigates injection via /bin/sh -c.
		args = append(args, strings.Fields(extra)...)
	}
	args = append(args, image, "sleep", "infinity")

	var stderr bytes.Buffer
	cmd := exec.Command("docker", args...)
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		errStr := stderr.String()
		if strings.Contains(errStr, "pull access denied") || strings.Contains(errStr, "not found") {
			// Attempt a pull then retry once, surfacing pull error if it fails
			if pullErr := exec.Command("docker", "pull", image).Run(); pullErr != nil {
				return fmt.Errorf("docker pull for %q failed: %w; original run error: %v", image, pullErr, err)
			}
			stderr.Reset()
			cmdRetry := exec.Command("docker", args...)
			cmdRetry.Stderr = &stderr
			if err2 := cmdRetry.Run(); err2 != nil {
				return fmt.Errorf("docker run failed after pull: %v; stderr: %s", err2, strings.TrimSpace(stderr.String()))
			}
		} else {
			return fmt.Errorf("docker run failed: %v; stderr: %s", err, strings.TrimSpace(stderr.String()))
		}
	}
	return nil
}

func dockerStart(name string) error {
	cmd := exec.Command("docker", "start", name)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("docker start failed: %v; stderr: %s", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

func dockerStop(name string) error {
	cmd := exec.Command("docker", "stop", name)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("docker stop failed: %v; stderr: %s", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

func inspectContainerRunning(name string) (running bool, exists bool, err error) {
	// docker inspect -f '{{.State.Running}}' name
	out, ierr := exec.Command("docker", "inspect", "-f", "{{.State.Running}}", name).Output()
	if ierr != nil {
		// If inspect fails, assume not exists
		if ee, ok := ierr.(*exec.ExitError); ok {
			_ = ee // not running / not exists
			return false, false, nil
		}
		return false, false, fmt.Errorf("docker inspect error: %v", ierr)
	}
	val := strings.TrimSpace(string(out))
	if val == "true" {
		return true, true, nil
	}
	// If output is false, container exists but not running
	return false, true, nil
}

func StopDockerContainer() error {
	name, _, _, _, err := resolveDockerSettings()
	if err != nil {
		return err
	}
	// If it doesn't exist, nothing to do
	_, exists, ierr := inspectContainerRunning(name)
	if ierr != nil {
		return ierr
	}
	if !exists {
		return nil
	}
	return dockerStop(name)
}

func RemoveDockerContainer(force bool) error {
	name, _, _, _, err := resolveDockerSettings()
	if err != nil {
		return err
	}
	// If it doesn't exist, nothing to do
	_, exists, ierr := inspectContainerRunning(name)
	if ierr != nil {
		return ierr
	}
	if !exists {
		return nil
	}
	args := []string{"rm"}
	if force {
		args = append(args, "-f")
	}
	args = append(args, name)
	cmd := exec.Command("docker", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("docker rm failed: %v; stderr: %s", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}
