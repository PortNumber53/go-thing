package routes

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"

	"go-thing/db"
	"go-thing/utility"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
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

	// System Prompts CRUD
	// List prompts for current user
	auth.GET("/api/settings/prompts", func(c *gin.Context) {
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
		rows, err := dbc.Query(`SELECT id, name, content, COALESCE(to_json(preferred_llms)::text,'[]') AS preferred_json, active, is_default, created_at, updated_at FROM system_prompts WHERE user_id=$1 ORDER BY updated_at DESC`, uid)
		if err != nil {
			log.Printf("[Prompts] list err: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed"})
			return
		}
		defer rows.Close()
		type Prompt struct {
			ID            int64    `json:"id"`
			Name          string   `json:"name"`
			Content       string   `json:"content"`
			PreferredLLMs []string `json:"preferred_llms"`
			Active        bool     `json:"active"`
			IsDefault     bool     `json:"default"`
			CreatedAt     string   `json:"created_at"`
			UpdatedAt     string   `json:"updated_at"`
		}
		prompts := []Prompt{}
		for rows.Next() {
			var p Prompt
			var prefJSON string
			if err := rows.Scan(&p.ID, &p.Name, &p.Content, &prefJSON, &p.Active, &p.IsDefault, &p.CreatedAt, &p.UpdatedAt); err != nil {
				log.Printf("[Prompts] scan err: %v", err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed"})
				return
			}
			var arr []string
			_ = json.Unmarshal([]byte(prefJSON), &arr)
			p.PreferredLLMs = arr
			prompts = append(prompts, p)
		}
		c.JSON(http.StatusOK, gin.H{"prompts": prompts})
	})

	// Create prompt
	auth.POST("/api/settings/prompts", func(c *gin.Context) {
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
			Name          string   `json:"name"`
			Content       string   `json:"content"`
			PreferredLLMs []string `json:"preferred_llms"`
			Active        *bool    `json:"active"`
			IsDefault     *bool    `json:"default"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}
		name := strings.TrimSpace(req.Name)
		content := req.Content
		if name == "" || strings.TrimSpace(content) == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "name and content are required"})
			return
		}
		active := false
		if req.Active != nil {
			active = *req.Active
		}
		isDefault := false
		if req.IsDefault != nil {
			isDefault = *req.IsDefault
		}
		if isDefault {
			active = true
		}
		dbc := db.Get()
		if dbc == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database not initialized"})
			return
		}
		tx, err := dbc.Begin()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed"})
			return
		}
		defer func() { _ = tx.Rollback() }()
		if isDefault {
			if _, err := tx.Exec(`UPDATE system_prompts SET is_default=FALSE WHERE user_id=$1 AND is_default=TRUE`, uid); err != nil {
				log.Printf("[Prompts] clear defaults err: %v", err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed"})
				return
			}
		}
		var id int64
		err = tx.QueryRow(
			`INSERT INTO system_prompts(user_id, name, content, preferred_llms, active, is_default) VALUES($1,$2,$3,$4,$5,$6) RETURNING id`,
			uid, name, content, req.PreferredLLMs, active, isDefault,
		).Scan(&id)
		if err != nil {
			log.Printf("[Prompts] insert err: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to insert"})
			return
		}
		if err := tx.Commit(); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"id": id})
	})

	// Update prompt
	auth.PUT("/api/settings/prompts/:id", func(c *gin.Context) {
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
		pidStr := c.Param("id")
		pid, err := strconv.ParseInt(pidStr, 10, 64)
		if err != nil || pid <= 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
			return
		}
		var req struct {
			Name          *string  `json:"name"`
			Content       *string  `json:"content"`
			PreferredLLMs []string `json:"preferred_llms"`
			Active        *bool    `json:"active"`
			IsDefault     *bool    `json:"default"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}
		dbc := db.Get()
		if dbc == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database not initialized"})
			return
		}
		tx, err := dbc.Begin()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed"})
			return
		}
		defer func() { _ = tx.Rollback() }()

		// Load current values to enforce rules
		var curIsDefault bool
		if err := tx.QueryRow(`SELECT is_default FROM system_prompts WHERE id=$1 AND user_id=$2`, pid, uid).Scan(&curIsDefault); err != nil {
			if err == sql.ErrNoRows {
				c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed"})
			return
		}

		// Enforce: default cannot be disabled
		if req.Active != nil && !*req.Active {
			// If currently default or becoming default, reject
			nextIsDefault := curIsDefault
			if req.IsDefault != nil {
				nextIsDefault = *req.IsDefault
			}
			if nextIsDefault {
				c.JSON(http.StatusBadRequest, gin.H{"error": "default prompt cannot be disabled"})
				return
			}
		}

		// If setting default true, clear others
		if req.IsDefault != nil && *req.IsDefault {
			if _, err := tx.Exec(`UPDATE system_prompts SET is_default=FALSE WHERE user_id=$1 AND is_default=TRUE AND id<>$2`, uid, pid); err != nil {
				log.Printf("[Prompts] clear defaults err: %v", err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed"})
				return
			}
		}

		// Build dynamic update
		setParts := []string{}
		args := []interface{}{}
		idx := 1
		if req.Name != nil {
			setParts = append(setParts, "name=$"+strconv.Itoa(idx))
			args = append(args, strings.TrimSpace(*req.Name))
			idx++
		}
		if req.Content != nil {
			setParts = append(setParts, "content=$"+strconv.Itoa(idx))
			args = append(args, *req.Content)
			idx++
		}
		if req.Active != nil {
			setParts = append(setParts, "active=$"+strconv.Itoa(idx))
			args = append(args, *req.Active)
			idx++
		}
		if req.IsDefault != nil {
			setParts = append(setParts, "is_default=$"+strconv.Itoa(idx))
			// If making default, also ensure active=true implicitly
			args = append(args, *req.IsDefault)
			idx++
			if *req.IsDefault {
				setParts = append(setParts, "active=TRUE")
			}
		}
		if req.PreferredLLMs != nil {
			setParts = append(setParts, "preferred_llms=$"+strconv.Itoa(idx))
			args = append(args, req.PreferredLLMs)
			idx++
		}
		if len(setParts) == 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "no fields to update"})
			return
		}
		// updated_at is bumped by trigger
		q := "UPDATE system_prompts SET " + strings.Join(setParts, ", ") + " WHERE id=$" + strconv.Itoa(idx) + " AND user_id=$" + strconv.Itoa(idx+1)
		args = append(args, pid, uid)
		if _, err := tx.Exec(q, args...); err != nil {
			log.Printf("[Prompts] update err: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update"})
			return
		}
		if err := tx.Commit(); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	// Delete prompt
	auth.DELETE("/api/settings/prompts/:id", func(c *gin.Context) {
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
		pidStr := c.Param("id")
		pid, err := strconv.ParseInt(pidStr, 10, 64)
		if err != nil || pid <= 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
			return
		}
		dbc := db.Get()
		if dbc == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database not initialized"})
			return
		}
		if _, err := dbc.Exec(`DELETE FROM system_prompts WHERE id=$1 AND user_id=$2`, pid, uid); err != nil {
			log.Printf("[Prompts] delete err: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
}
