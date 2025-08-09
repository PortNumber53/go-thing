package tools

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

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

// resolveDockerSettings reads INI config and returns (name, image, extraArgs, absChroot)
func resolveDockerSettings() (string, string, string, string, error) {
	cfg, err := ini.Load(os.ExpandEnv(config.ConfigFilePath))
	if err != nil {
		return "", "", "", "", fmt.Errorf("config file error: %v", err)
	}
	s := cfg.Section("default")
	chroot := strings.TrimSpace(s.Key("CHROOT_DIR").String())
	if chroot == "" {
		return "", "", "", "", fmt.Errorf("CHROOT_DIR not configured in [default] section")
	}
	absChroot, err := filepath.Abs(chroot)
	if err != nil {
		return "", "", "", "", fmt.Errorf("could not resolve CHROOT_DIR: %v", err)
	}
	if fi, err := os.Stat(absChroot); err != nil || !fi.IsDir() {
		return "", "", "", "", fmt.Errorf("CHROOT_DIR does not exist or is not a directory: %s", absChroot)
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
	return name, image, extra, absChroot, nil
}

func dockerRunDetached(name, image, extra, absChroot string) error {
	// Build docker run command: detached container that stays up
	// Mount CHROOT_DIR at /app, set workdir to /app
	cmdStr := fmt.Sprintf("docker run -d --name %s -v %q:/app -w /app %s %s sleep infinity", name, absChroot, extra, image)
	var stdout, stderr bytes.Buffer
	cmd := exec.Command("/bin/sh", "-c", cmdStr)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if strings.Contains(stderr.String(), "pull access denied") || strings.Contains(stderr.String(), "not found") {
			// Attempt a pull then retry once
			_ = exec.Command("docker", "pull", image).Run()
			stdout.Reset()
			stderr.Reset()
			cmd = exec.Command("/bin/sh", "-c", cmdStr)
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			if err2 := cmd.Run(); err2 != nil {
				return fmt.Errorf("docker run failed: %v; stderr: %s", err2, strings.TrimSpace(stderr.String()))
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
