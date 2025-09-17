package tools

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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
//
//	DOCKER_CONTAINER_NAME, DOCKER_IMAGE, DOCKER_EXTRA_ARGS, DOCKER_AUTO_REMOVE
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
	settingsOnce          sync.Once
	cachedName            string
	cachedImage           string
	cachedExtra           string
	cachedAbsChroot       string
	cachedSettingsLoadErr error
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

// imageSupportsArm64 returns true if the given image manifest advertises linux/arm64.
// If the manifest cannot be inspected, it returns false with the error.
func imageSupportsArm64(image string) (bool, error) {
	out, err := exec.Command("docker", "manifest", "inspect", image).Output()
	if err != nil {
		return false, err
	}
	s := string(out)
	if strings.Contains(s, "linux/arm64") || strings.Contains(s, "\"architecture\": \"arm64\"") {
		return true, nil
	}
	return false, nil
}

// platformArgsIfNeeded determines whether we should add a --platform flag automatically.
// On Apple Silicon (darwin/arm64), many images (like archlinux) do not have arm64 builds.
// If no platform is already specified via extra args and the image lacks arm64, we force amd64.
func platformArgsIfNeeded(image, extra string) []string {
    if runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" {
        hasPlatform := false
        for _, arg := range strings.Fields(extra) {
            if strings.HasPrefix(arg, "--platform") {
                hasPlatform = true
                break
            }
        }
        if !hasPlatform {
            if ok, _ := imageSupportsArm64(image); !ok {
                return []string{"--platform=linux/amd64"}
            }
        }
    }
    return nil
}

func dockerRunDetached(name, image, extra, absChroot string) error {
	// Build docker run args: detached container that stays up, CHROOT_DIR mounted at /app, workdir /app
	args := []string{
		"run", "-d", "--name", name,
		"-v", fmt.Sprintf("%s:/app", absChroot),
		"-w", "/app",
	}
	// Platform fixups for macOS/arm64 environments when the image doesn't support arm64
	if plat := platformArgsIfNeeded(image, extra); len(plat) > 0 {
		args = append(args, plat...)
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
			// Provide more actionable diagnostics for common macOS issues
			trimmed := strings.TrimSpace(errStr)
			switch {
			case strings.Contains(trimmed, "no matching manifest for linux/arm64") || strings.Contains(trimmed, "requested image's platform"):
				return fmt.Errorf("docker run failed: %v; stderr: %s. Hint: on Apple Silicon, add DOCKER_EXTRA_ARGS=\"--platform=linux/amd64\" or use an arm64-compatible image.", err, trimmed)
			case strings.Contains(trimmed, "Mounts denied") || strings.Contains(trimmed, "is not shared from the host"):
				return fmt.Errorf("docker run failed: %v; stderr: %s. Hint: share the CHROOT_DIR path in Docker Desktop (Settings → Resources → File sharing) or move CHROOT_DIR under $HOME.", err, trimmed)
			case strings.Contains(trimmed, "Cannot connect to the Docker daemon") || strings.Contains(trimmed, "error during connect"):
				return fmt.Errorf("docker run failed: %v; stderr: %s. Hint: ensure Docker Desktop/daemon is running.", err, trimmed)
			default:
				return fmt.Errorf("docker run failed: %v; stderr: %s", err, trimmed)
			}
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
