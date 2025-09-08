package routes

import (
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go-thing/utility"
)

// APIDockerDeps defines required dependencies for Docker SSH key routes
type APIDockerDeps struct {
	EnsureDockerContainer    func() (string, error)
	EnsureSSHKeygenAvailable func(container string) error
	RunDockerExec            func(container string, args []string, timeout time.Duration) (string, string, error)
}

// RegisterAPIDockerRoutes registers Docker SSH key download and generation endpoints.
// It accepts requireAuth middleware and the necessary dependencies.
func RegisterAPIDockerRoutes(r *gin.Engine, requireAuth gin.HandlerFunc, deps APIDockerDeps) {
	// Download SSH key from the running container (without hardcoding user). Uses $HOME/.ssh paths.
	// GET /api/docker/ssh-keys/download?which=public|private
	r.GET("/api/docker/ssh-keys/download", requireAuth, func(c *gin.Context) {
		which := strings.ToLower(strings.TrimSpace(c.Query("which")))
		var rel string
		var fname string
		switch which {
		case "public", "pub":
			rel = "$HOME/.ssh/id_ed25519.pub"
			fname = "id_ed25519.pub"
		case "private", "priv":
			rel = "$HOME/.ssh/id_ed25519"
			fname = "id_ed25519"
		default:
			c.JSON(http.StatusBadRequest, gin.H{"error": "which must be 'public' or 'private'"})
			return
		}

		containerName, err := deps.EnsureDockerContainer()
		if err != nil {
			log.Printf("[DockerSSHDownload] ensure container error: %v", err)
			c.JSON(http.StatusBadGateway, gin.H{"error": "failed to start container"})
			return
		}
		cmd := fmt.Sprintf("cat %s", rel)
		out, stderr, err := deps.RunDockerExec(containerName, []string{"bash", "-lc", cmd}, 5*time.Second)
		if err != nil {
			log.Printf("[DockerSSHDownload] read error: %v (stderr: %s)", err, strings.TrimSpace(stderr))
			c.JSON(http.StatusNotFound, gin.H{"error": "key not found"})
			return
		}
		// Stream as attachment
		c.Header("Content-Type", "text/plain; charset=utf-8")
		c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", fname))
		c.String(http.StatusOK, out)
	})

	// Generate an ed25519 SSH key inside the Docker container and return the public key
	r.POST("/api/docker/ssh-key", requireAuth, func(c *gin.Context) {
		if !utility.ValidateCSRF(c) {
			c.JSON(http.StatusForbidden, gin.H{"error": "csrf invalid"})
			return
		}

		// Ensure docker container is running
		containerName, err := deps.EnsureDockerContainer()
		if err != nil {
			log.Printf("[DockerSSHKey] ensure container error: %v", err)
			c.JSON(http.StatusBadGateway, gin.H{"error": "failed to start container"})
			return
		}
		if err := deps.EnsureSSHKeygenAvailable(containerName); err != nil {
			log.Printf("[DockerSSHKey] ensure ssh-keygen error: %v", err)
			c.JSON(http.StatusBadGateway, gin.H{"error": "failed to prepare ssh-keygen in container"})
			return
		}
		// Create ~/.ssh, remove existing keys, and generate a new one
		cmd := "set -e; mkdir -p ~/.ssh; chmod 700 ~/.ssh; rm -f ~/.ssh/id_ed25519 ~/.ssh/id_ed25519.pub; ssh-keygen -t ed25519 -C 'developer@container.local' -N '' -f ~/.ssh/id_ed25519 -q; chmod 600 ~/.ssh/id_ed25519; chmod 644 ~/.ssh/id_ed25519.pub"
		if _, stderr, err := deps.RunDockerExec(containerName, []string{"bash", "-lc", cmd}, 20*time.Second); err != nil {
			log.Printf("[DockerSSHKey] ssh-keygen error: %v (stderr: %s)", err, strings.TrimSpace(stderr))
			c.JSON(http.StatusBadGateway, gin.H{"error": "ssh-keygen failed"})
			return
		}
		// Read public key
		pub, perr, err := deps.RunDockerExec(containerName, []string{"bash", "-lc", "cat ~/.ssh/id_ed25519.pub"}, 5*time.Second)
		if err != nil {
			log.Printf("[DockerSSHKey] read public key error: %v (stderr: %s)", err, strings.TrimSpace(perr))
			c.JSON(http.StatusBadGateway, gin.H{"error": "failed reading public key"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"ok": true, "public_key": strings.TrimSpace(pub)})
	})
}
