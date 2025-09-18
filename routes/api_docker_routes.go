package routes

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"go-thing/db"
	toolsrv "go-thing/tools"
	"go-thing/utility"

	"github.com/gin-gonic/gin"
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

	// Build Docker image from user's saved Dockerfile and tag as their configured image
	r.POST("/api/docker/build", requireAuth, func(c *gin.Context) {
		if !utility.ValidateCSRF(c) {
			c.JSON(http.StatusForbidden, gin.H{"error": "csrf invalid"})
			return
		}
		// Request body allows { no_cache: boolean }
		var req struct {
			NoCache bool `json:"no_cache"`
		}
		_ = c.ShouldBindJSON(&req)

		// Load user's docker settings from DB
		v, ok := c.Get("userID")
		if !ok {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "user ID not found in context"})
			return
		}
		uid, ok := v.(int64)
		if !ok {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid user ID type in context"})
			return
		}
		dbc := db.Get()
		if dbc == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database not initialized"})
			return
		}
		var settingsRaw sql.NullString
		if err := dbc.QueryRow(`SELECT settings::text FROM users WHERE id=$1`, uid).Scan(&settingsRaw); err != nil {
			if err == sql.ErrNoRows {
				utility.ClearSessionCookie(c)
				c.JSON(http.StatusUnauthorized, gin.H{"error": "not logged in"})
				return
			}
			log.Printf("[DockerBuild] select err: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed"})
			return
		}
		var settings map[string]interface{}
		if settingsRaw.Valid && strings.TrimSpace(settingsRaw.String) != "" {
if err := json.Unmarshal([]byte(settingsRaw.String), &settings); err != nil {
	log.Printf("[DockerBuild] unmarshal settings err: %v", err)
	c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to parse settings"})
	return
}
		}
		dockerVal, _ := settings["docker"].(map[string]interface{})
		if dockerVal == nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "no docker settings configured"})
			return
		}
		image, _ := dockerVal["image"].(string)
		dockerfile, _ := dockerVal["dockerfile"].(string)
		image = strings.TrimSpace(image)
		if image == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "docker image tag is required in settings"})
			return
		}
		if strings.TrimSpace(dockerfile) == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Dockerfile content is empty"})
			return
		}

		// Avoid clobbering official images like "archlinux:latest": if the image has no slash
		// we will prefix with "go-thing-<uid>-" to create a unique local tag and update settings.
		targetTag := image
		if !strings.Contains(image, "/") {
			targetTag = fmt.Sprintf("go-thing-%d-%s", uid, image)
		}

		if err := toolsrv.BuildDockerImageFromDockerfile(targetTag, dockerfile, req.NoCache); err != nil {
			log.Printf("[DockerBuild] error: %v", err)
			c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
			return
		}
		// If we rewrote the tag, persist back into settings so future starts use the built image
		if targetTag != image {
			dockerVal["image"] = targetTag
			b, err := json.Marshal(dockerVal)
			if err != nil {
				log.Printf("[DockerBuild] failed to marshal settings for update: %v", err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to prepare settings for update"})
				return
			}
			const upd = `UPDATE users SET settings = jsonb_set(COALESCE(settings, '{}'::jsonb), '{docker}', to_jsonb($1::json), true), updated_at=now() WHERE id=$2`
			if _, err := dbc.Exec(upd, string(b), uid); err != nil {
				log.Printf("[DockerBuild] update image tag err: %v", err)
			}
		}
		c.JSON(http.StatusOK, gin.H{"ok": true, "image": targetTag})
	})

	// Start (or create) the container using saved settings (name, image, args)
	r.POST("/api/docker/start", requireAuth, func(c *gin.Context) {
		if !utility.ValidateCSRF(c) {
			c.JSON(http.StatusForbidden, gin.H{"error": "csrf invalid"})
			return
		}
		v, ok := c.Get("userID")
		if !ok {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "user ID not found in context"})
			return
		}
		uid, ok := v.(int64)
		if !ok {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid user ID type in context"})
			return
		}
		dbc := db.Get()
		if dbc == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database not initialized"})
			return
		}
		var settingsRaw sql.NullString
		if err := dbc.QueryRow(`SELECT settings::text FROM users WHERE id=$1`, uid).Scan(&settingsRaw); err != nil {
			if err == sql.ErrNoRows {
				utility.ClearSessionCookie(c)
				c.JSON(http.StatusUnauthorized, gin.H{"error": "not logged in"})
				return
			}
			log.Printf("[DockerStart] select err: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed"})
			return
		}
		var settings map[string]interface{}
		if settingsRaw.Valid && strings.TrimSpace(settingsRaw.String) != "" {
			_ = json.Unmarshal([]byte(settingsRaw.String), &settings)
		}
		dockerVal, _ := settings["docker"].(map[string]interface{})
		if dockerVal == nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "no docker settings configured"})
			return
		}
		container, _ := dockerVal["container"].(string)
		image, _ := dockerVal["image"].(string)
		args, _ := dockerVal["args"].(string)
		container = strings.TrimSpace(container)
		image = strings.TrimSpace(image)
		if container == "" || image == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "container name and image are required"})
			return
		}

		name, err := toolsrv.StartContainerWithSettings(container, image, args)
		if err != nil {
			log.Printf("[DockerStart] error: %v", err)
			c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"ok": true, "container": name})
	})

	// Remove the configured image (force=false)
	r.POST("/api/docker/remove-image", requireAuth, func(c *gin.Context) {
		if !utility.ValidateCSRF(c) {
			c.JSON(http.StatusForbidden, gin.H{"error": "csrf invalid"})
			return
		}
		v, ok := c.Get("userID")
		if !ok {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "user ID not found in context"})
			return
		}
		uid, ok := v.(int64)
		if !ok {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid user ID type in context"})
			return
		}
		dbc := db.Get()
		if dbc == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database not initialized"})
			return
		}
		var settingsRaw sql.NullString
		if err := dbc.QueryRow(`SELECT settings::text FROM users WHERE id=$1`, uid).Scan(&settingsRaw); err != nil {
			if err == sql.ErrNoRows {
				utility.ClearSessionCookie(c)
				c.JSON(http.StatusUnauthorized, gin.H{"error": "not logged in"})
				return
			}
			log.Printf("[DockerRemoveImage] select err: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed"})
			return
		}
		var settings map[string]interface{}
		if settingsRaw.Valid && strings.TrimSpace(settingsRaw.String) != "" {
			_ = json.Unmarshal([]byte(settingsRaw.String), &settings)
		}
		dockerVal, _ := settings["docker"].(map[string]interface{})
		if dockerVal == nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "no docker settings configured"})
			return
		}
		image, _ := dockerVal["image"].(string)
		image = strings.TrimSpace(image)
		if image == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "docker image tag is required in settings"})
			return
		}
		if err := toolsrv.RemoveDockerImage(image, false); err != nil {
			log.Printf("[DockerRemoveImage] error: %v", err)
			c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"ok": true, "image": image})
	})

	// Stop the configured container (if exists/running)
	r.POST("/api/docker/stop", requireAuth, func(c *gin.Context) {
		if !utility.ValidateCSRF(c) {
			c.JSON(http.StatusForbidden, gin.H{"error": "csrf invalid"})
			return
		}
		v, ok := c.Get("userID")
		if !ok {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "user ID not found in context"})
			return
		}
		uid, ok := v.(int64)
		if !ok {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid user ID type in context"})
			return
		}
		dbc := db.Get()
		if dbc == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database not initialized"})
			return
		}
		var settingsRaw sql.NullString
		if err := dbc.QueryRow(`SELECT settings::text FROM users WHERE id=$1`, uid).Scan(&settingsRaw); err != nil {
			if err == sql.ErrNoRows {
				utility.ClearSessionCookie(c)
				c.JSON(http.StatusUnauthorized, gin.H{"error": "not logged in"})
				return
			}
			log.Printf("[DockerStop] select err: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed"})
			return
		}
		var settings map[string]interface{}
		if settingsRaw.Valid && strings.TrimSpace(settingsRaw.String) != "" {
			_ = json.Unmarshal([]byte(settingsRaw.String), &settings)
		}
		dockerVal, _ := settings["docker"].(map[string]interface{})
		container, _ := dockerVal["container"].(string)
		if strings.TrimSpace(container) == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "container name missing"})
			return
		}
		if err := toolsrv.StopContainerByName(container); err != nil {
			c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	// Restart the configured container (stop if needed, then start)
	r.POST("/api/docker/restart", requireAuth, func(c *gin.Context) {
		if !utility.ValidateCSRF(c) {
			c.JSON(http.StatusForbidden, gin.H{"error": "csrf invalid"})
			return
		}
		v, ok := c.Get("userID")
		if !ok {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "user ID not found in context"})
			return
		}
		uid, ok := v.(int64)
		if !ok {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid user ID type in context"})
			return
		}
		dbc := db.Get()
		if dbc == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database not initialized"})
			return
		}
		var settingsRaw sql.NullString
		if err := dbc.QueryRow(`SELECT settings::text FROM users WHERE id=$1`, uid).Scan(&settingsRaw); err != nil {
			if err == sql.ErrNoRows {
				utility.ClearSessionCookie(c)
				c.JSON(http.StatusUnauthorized, gin.H{"error": "not logged in"})
				return
			}
			log.Printf("[DockerRestart] select err: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed"})
			return
		}
		var settings map[string]interface{}
		if settingsRaw.Valid && strings.TrimSpace(settingsRaw.String) != "" {
			_ = json.Unmarshal([]byte(settingsRaw.String), &settings)
		}
		dockerVal, _ := settings["docker"].(map[string]interface{})
		container, _ := dockerVal["container"].(string)
		image, _ := dockerVal["image"].(string)
		args, _ := dockerVal["args"].(string)
		if strings.TrimSpace(container) == "" || strings.TrimSpace(image) == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "container/image missing"})
			return
		}
		if err := toolsrv.StopContainerByName(container); err != nil {
			log.Printf("[DockerRestart] failed to stop container before restart (continuing anyway): %v", err)
		}
		if _, err := toolsrv.StartContainerWithSettings(container, image, args); err != nil {
			c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
}
