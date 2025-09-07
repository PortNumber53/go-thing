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

// APISSHDeps provides the minimal dependencies needed by the SSH keys route
// so the route can live outside of main while still using helpers from main/tools.
type APISSHDeps struct {
	EnsureDockerContainer    func() (string, error)
	EnsureSSHKeygenAvailable func(container string) error
	RunDockerExec            func(container string, args []string, timeout time.Duration) (string, string, error)
}

// RegisterAPISSHRoutes registers the authenticated CSRF-protected /api/ssh-keys endpoint
func RegisterAPISSHRoutes(auth *gin.RouterGroup, deps APISSHDeps) {
	auth.POST("/api/ssh-keys", func(c *gin.Context) {
		if !utility.ValidateCSRF(c) {
			c.JSON(http.StatusForbidden, gin.H{"error": "csrf invalid"})
			return
		}
		var req struct {
			Type       string `json:"type"`       // "ed25519" (default) or "rsa"
			Bits       int    `json:"bits"`       // for rsa, default 3072
			Comment    string `json:"comment"`    // key comment
			Passphrase string `json:"passphrase"` // optional
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}
		keyType := strings.ToLower(strings.TrimSpace(req.Type))
		if keyType == "" {
			keyType = "ed25519"
		}
		if keyType != "ed25519" && keyType != "rsa" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "type must be ed25519 or rsa"})
			return
		}
		bits := req.Bits
		if keyType == "rsa" {
			if bits == 0 {
				bits = 3072
			}
			if bits < 2048 {
				c.JSON(http.StatusBadRequest, gin.H{"error": "rsa bits must be >= 2048"})
				return
			}
		}
		comment := strings.TrimSpace(req.Comment)
		pass := req.Passphrase

		// Ensure docker container is running
		containerName, err := deps.EnsureDockerContainer()
		if err != nil {
			log.Printf("[SSHKeys] ensure container error: %v", err)
			c.JSON(http.StatusBadGateway, gin.H{"error": "failed to start container"})
			return
		}
		if err := deps.EnsureSSHKeygenAvailable(containerName); err != nil {
			log.Printf("[SSHKeys] ensure ssh-keygen error: %v", err)
			c.JSON(http.StatusBadGateway, gin.H{"error": "failed to prepare ssh-keygen in container"})
			return
		}

		base := fmt.Sprintf("/tmp/sshkey_%d", time.Now().UnixNano())
		args := []string{"ssh-keygen"}
		if keyType == "rsa" {
			args = append(args, "-t", "rsa", "-b", fmt.Sprint(bits))
		} else {
			args = append(args, "-t", "ed25519")
		}
		if comment != "" {
			args = append(args, "-C", comment)
		}
		args = append(args, "-N", pass, "-f", base)

		if _, stderr, err := deps.RunDockerExec(containerName, args, 20*time.Second); err != nil {
			log.Printf("[SSHKeys] ssh-keygen error: %v (stderr: %s)", err, strings.TrimSpace(stderr))
			c.JSON(http.StatusBadGateway, gin.H{"error": "ssh-keygen failed"})
			return
		}
		// Read keys
		priv, perr, err := deps.RunDockerExec(containerName, []string{"bash", "-lc", fmt.Sprintf("cat %s", base)}, 5*time.Second)
		if err != nil {
			log.Printf("[SSHKeys] read private error: %v (stderr: %s)", err, strings.TrimSpace(perr))
			c.JSON(http.StatusBadGateway, gin.H{"error": "failed reading private key"})
			// attempt cleanup
			_, _, _ = deps.RunDockerExec(containerName, []string{"rm", "-f", base, base + ".pub"}, 5*time.Second)
			return
		}
		pub, puberr, err := deps.RunDockerExec(containerName, []string{"bash", "-lc", fmt.Sprintf("cat %s.pub", base)}, 5*time.Second)
		if err != nil {
			log.Printf("[SSHKeys] read public error: %v (stderr: %s)", err, strings.TrimSpace(puberr))
			c.JSON(http.StatusBadGateway, gin.H{"error": "failed reading public key"})
			// attempt cleanup
			_, _, _ = deps.RunDockerExec(containerName, []string{"rm", "-f", base, base + ".pub"}, 5*time.Second)
			return
		}
		// Cleanup generated files in container
		_, _, _ = deps.RunDockerExec(containerName, []string{"rm", "-f", base, base + ".pub"}, 5*time.Second)

		c.JSON(http.StatusOK, gin.H{
			"ok":          true,
			"type":        keyType,
			"bits":        bits,
			"public_key":  strings.TrimSpace(pub),
			"private_key": strings.TrimSpace(priv),
		})
	})
}
