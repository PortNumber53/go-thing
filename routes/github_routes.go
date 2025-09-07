package routes

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go-thing/utility"
)

// RegisterGithubRoutes registers the GitHub webhook endpoint with HMAC validation
func RegisterGithubRoutes(r *gin.Engine) {
	r.POST("/webhook/github", func(c *gin.Context) {
		// Read body with a reasonable limit
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 1<<20) // 1MB
		body, err := io.ReadAll(c.Request.Body)
		if err != nil {
			log.Printf("[GitHubWebhook] read error: %v", err)
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
			return
		}
		// Log basic request metadata (no secrets)
		evt := strings.TrimSpace(c.Request.Header.Get("X-GitHub-Event"))
		delivery := strings.TrimSpace(c.Request.Header.Get("X-GitHub-Delivery"))
		ua := strings.TrimSpace(c.Request.Header.Get("User-Agent"))
		ctype := strings.TrimSpace(c.Request.Header.Get("Content-Type"))
		sigPresent := c.Request.Header.Get("X-Hub-Signature-256") != ""
		clientIP := c.ClientIP()
		qstr := c.Request.URL.RawQuery
		log.Printf("[GitHubWebhook] headers event=%q delivery=%q ua=%q content_type=%q sig256_present=%t ip=%q body_len=%d query=%q", evt, delivery, ua, ctype, sigPresent, clientIP, len(body), qstr)
		// Log the raw body for debugging/analysis (body already limited to 1MB above)
		log.Printf("[GitHubWebhook] raw body: %s", string(body))

		// Try to parse JSON for structured logging (generic map for common fields)
		var payload map[string]interface{}
		if err := json.Unmarshal(body, &payload); err != nil {
			// If not JSON, just log raw (truncated)
			raw := string(body)
			if len(raw) > 512 {
				raw = raw[:512] + "…"
			}
			log.Printf("[GitHubWebhook] non-JSON payload: %s", raw)
			c.JSON(http.StatusOK, gin.H{"ok": true})
			return
		}

		// Validate HMAC signature
		// Prefer INI config [default] GITHUB_WEBHOOK_SECRET; fallback to environment.
		secret := ""
		if cfg, err := utility.LoadConfig(); err == nil && cfg != nil {
			secret = strings.TrimSpace(cfg["GITHUB_WEBHOOK_SECRET"])
		}
		if secret == "" {
			secret = os.Getenv("GITHUB_WEBHOOK_SECRET")
		}
		if secret == "" {
			log.Printf("[GitHubWebhook] reject: missing GITHUB_WEBHOOK_SECRET")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		signature := c.Request.Header.Get("X-Hub-Signature-256")
		if signature == "" {
			log.Printf("[GitHubWebhook] reject: missing X-Hub-Signature-256")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		expected := utility.HMACSHA256(secret, body)
		if !utility.HMACEqual(signature, expected) {
			log.Printf("[GitHubWebhook] reject: invalid X-Hub-Signature-256")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}

		// Extract common fields for visibility
		action := ""
		if v, ok := payload["action"].(string); ok {
			action = v
		}
		var repoName, repoFull, repoID string
		if r, ok := payload["repository"].(map[string]interface{}); ok {
			if n, ok := r["name"].(string); ok {
				repoName = n
			}
			if fn, ok := r["full_name"].(string); ok {
				repoFull = fn
			}
			switch idv := r["id"].(type) {
			case float64:
				repoID = strconv.FormatInt(int64(idv), 10)
			case json.Number:
				repoID = idv.String()
			case string:
				repoID = idv
			}
		}
		sender := ""
		if s, ok := payload["sender"].(map[string]interface{}); ok {
			if lg, ok := s["login"].(string); ok {
				sender = lg
			}
		}
		installation := ""
		if ins, ok := payload["installation"].(map[string]interface{}); ok {
			switch idv := ins["id"].(type) {
			case float64:
				installation = strconv.FormatInt(int64(idv), 10)
			case json.Number:
				installation = idv.String()
			case string:
				installation = idv
			}
		}
		ref := ""
		if v, ok := payload["ref"].(string); ok {
			ref = v
		}
		before := ""
		if v, ok := payload["before"].(string); ok {
			before = v
		}
		after := ""
		if v, ok := payload["after"].(string); ok {
			after = v
		}
		pusher := ""
		if p, ok := payload["pusher"].(map[string]interface{}); ok {
			if nm, ok := p["name"].(string); ok {
				pusher = nm
			}
		}
		log.Printf("[GitHubWebhook] parsed action=%q repo=%q full=%q id=%q sender=%q installation=%q ref=%q before=%q after=%q pusher=%q", action, repoName, repoFull, repoID, sender, installation, ref, before, after, pusher)

		// Downstream typed parsing and AI follow-up may occur elsewhere in the handler chain; here we simply ack
		_ = time.Now() // ensure time import retained for possible future use
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
}
