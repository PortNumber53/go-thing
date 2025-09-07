package routes

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"go-thing/db"
	"go-thing/utility"
)

// RegisterAPISettingsRoutes registers authenticated settings-related endpoints under the provided auth group.
// Expects the group to already include requireAuth() middleware.
func RegisterAPISettingsRoutes(auth *gin.RouterGroup) {
	// Read current settings
	auth.GET("/api/settings", func(c *gin.Context) {
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
		var username, name string
		if err := dbc.QueryRow(`SELECT username, name FROM users WHERE id=$1`, uid).Scan(&username, &name); err != nil {
			if err == sql.ErrNoRows {
				utility.ClearSessionCookie(c)
				c.JSON(http.StatusUnauthorized, gin.H{"error": "not logged in"})
				return
			}
			log.Printf("[Settings] query error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"username": username, "name": name})
	})

	// Update profile (name)
	auth.POST("/api/settings", func(c *gin.Context) {
		if !utility.ValidateCSRF(c) {
			c.JSON(http.StatusForbidden, gin.H{"error": "csrf invalid"})
			return
		}
		var req struct {
			Name string `json:"name"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}
		name := strings.TrimSpace(req.Name)
		if name == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "name is required"})
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
		if _, err := dbc.Exec(`UPDATE users SET name=$1, updated_at=now() WHERE id=$2`, name, uid); err != nil {
			log.Printf("[Settings] update name error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	// Change password
	auth.POST("/api/settings/password", func(c *gin.Context) {
		if !utility.ValidateCSRF(c) {
			c.JSON(http.StatusForbidden, gin.H{"error": "csrf invalid"})
			return
		}
		var req struct {
			Current string `json:"current_password"`
			New     string `json:"new_password"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}
		if len(req.New) < 8 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "new password must be at least 8 characters"})
			return
		}
		if !utility.IsStrongPassword(req.New) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "password must be 12+ chars and include upper, lower, digit, and special character"})
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
		var hash string
		if err := dbc.QueryRow(`SELECT password_hash FROM users WHERE id=$1`, uid).Scan(&hash); err != nil {
			if err == sql.ErrNoRows {
				utility.ClearSessionCookie(c)
				c.JSON(http.StatusUnauthorized, gin.H{"error": "not logged in"})
				return
			}
			log.Printf("[Settings] query pass error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed"})
			return
		}
		if bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Current)) != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "current password is incorrect"})
			return
		}
		newHash, err := bcrypt.GenerateFromPassword([]byte(req.New), bcrypt.DefaultCost)
		if err != nil {
			log.Printf("[Settings] bcrypt error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed"})
			return
		}
		if _, err := dbc.Exec(`UPDATE users SET password_hash=$1, updated_at=now() WHERE id=$2`, string(newHash), uid); err != nil {
			log.Printf("[Settings] update pass error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	// Docker settings: GET current and POST to update
	auth.GET("/api/settings/docker", func(c *gin.Context) {
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
			log.Printf("[DockerSettings] select err: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed"})
			return
		}
		var settings map[string]interface{}
		if settingsRaw.Valid && strings.TrimSpace(settingsRaw.String) != "" {
			_ = json.Unmarshal([]byte(settingsRaw.String), &settings)
		}
		if settings == nil {
			settings = map[string]interface{}{}
		}
		dockerVal, _ := settings["docker"].(map[string]interface{})
		if dockerVal == nil {
			dockerVal = map[string]interface{}{}
		}
		c.JSON(http.StatusOK, gin.H{"docker": dockerVal})
	})

	auth.POST("/api/settings/docker", func(c *gin.Context) {
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
		var req struct {
			Container  string `json:"container"`
			Image      string `json:"image"`
			Args       string `json:"args"`
			Dockerfile string `json:"dockerfile"`
			AutoRemove *bool  `json:"auto_remove"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}
		// minimal validation/normalization
		container := strings.TrimSpace(req.Container)
		image := strings.TrimSpace(req.Image)
		args := strings.TrimSpace(req.Args)
		dockerfile := req.Dockerfile // keep formatting
		autoRemove := true
		if req.AutoRemove != nil {
			autoRemove = *req.AutoRemove
		}
		dockerObj := map[string]interface{}{
			"container":   container,
			"image":       image,
			"args":        args,
			"dockerfile":  dockerfile,
			"auto_remove": autoRemove,
		}
		dbc := db.Get()
		if dbc == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database not initialized"})
			return
		}
		// Update docker key within JSONB using jsonb_set for atomic update
		const upd = `UPDATE users SET settings = jsonb_set(COALESCE(settings, '{}'::jsonb), '{docker}', to_jsonb($1::json), true), updated_at=now() WHERE id=$2`
		b, _ := json.Marshal(dockerObj)
		if _, err := dbc.Exec(upd, string(b), uid); err != nil {
			log.Printf("[DockerSettings] update err: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
}
