package routes

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go-thing/utility"
)

// RegisterJiraRoutes registers the Jira webhook endpoint (no CSRF; optional token)
func RegisterJiraRoutes(r *gin.Engine) {
	r.POST("/webhook/jira", func(c *gin.Context) {
		// Optional shared token check from config
		var expectedToken string
		if cfg, err := utility.LoadConfig(); err == nil && cfg != nil {
			expectedToken = strings.TrimSpace(cfg["JIRA_WEBHOOK_TOKEN"])
		}
		if expectedToken != "" {
			got := strings.TrimSpace(c.Request.Header.Get("X-Webhook-Token"))
			if got == "" || got != expectedToken {
				log.Printf("[JiraWebhook] reject: missing or invalid X-Webhook-Token")
				c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
				return
			}
		}

		// Limit body and read
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 1<<20) // 1MB
		body, err := io.ReadAll(c.Request.Body)
		if err != nil {
			log.Printf("[JiraWebhook] read error: %v", err)
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
			return
		}
		log.Printf("[JiraWebhook] raw body: %s", string(body))

		// Parse JSON if possible
		var payload map[string]interface{}
		if err := json.Unmarshal(body, &payload); err != nil {
			raw := string(body)
			if len(raw) > 512 {
				raw = raw[:512] + "…"
			}
			log.Printf("[JiraWebhook] non-JSON payload: %s", raw)
			c.JSON(http.StatusOK, gin.H{"ok": true})
			return
		}

		// Extract fields
		event := ""
		if v, ok := payload["webhookEvent"].(string); ok {
			event = v
		} else if v, ok := payload["issue_event_type_name"].(string); ok {
			event = v
		}
		issueKey := ""
		issueID := ""
		fields := map[string]interface{}{}
		if issue, ok := payload["issue"].(map[string]interface{}); ok {
			if k, ok := issue["key"].(string); ok {
				issueKey = k
			}
			switch idv := issue["id"].(type) {
			case string:
				issueID = idv
			case float64:
				issueID = strconv.FormatInt(int64(idv), 10)
			}
			if f, ok := issue["fields"].(map[string]interface{}); ok {
				fields = f
			}
		}
		if issueKey == "" {
			if k, ok := payload["key"].(string); ok {
				issueKey = k
			}
		}
		if issueID == "" {
			switch idv := payload["id"].(type) {
			case string:
				issueID = idv
			case float64:
				issueID = strconv.FormatInt(int64(idv), 10)
			case json.Number:
				if iv, err := idv.Int64(); err == nil {
					issueID = strconv.FormatInt(iv, 10)
				}
			}
		}
		if len(fields) == 0 {
			if f, ok := payload["fields"].(map[string]interface{}); ok {
				fields = f
			}
		}
		log.Printf("[JiraWebhook] event=%q issue=%q id=%q", event, issueKey, issueID)

		// Build system prompt for AI Agent using requested fields
		projectKey := ""
		if p, ok := fields["project"].(map[string]interface{}); ok {
			if k, ok := p["key"].(string); ok {
				projectKey = k
			}
		}
		if projectKey == "" {
			if p, ok := payload["project"].(map[string]interface{}); ok {
				if k, ok := p["key"].(string); ok {
					projectKey = k
				}
			}
		}
		var labels []string
		if la, ok := fields["labels"].([]interface{}); ok {
			for _, lv := range la {
				if s, ok := lv.(string); ok && s != "" {
					trimmed := strings.TrimSpace(s)
					if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
						inner := strings.Trim(trimmed, "[]")
						parts := strings.Split(inner, ",")
						for _, p := range parts {
							v := strings.TrimSpace(p)
							v = strings.Trim(v, "'\"")
							if v != "" {
								labels = append(labels, v)
							}
						}
						continue
					}
					labels = append(labels, trimmed)
				}
			}
		}
		statusName := ""
		if st, ok := fields["status"].(map[string]interface{}); ok {
			if n, ok := st["name"].(string); ok {
				statusName = n
			}
		}
		if statusName == "" {
			if st, ok := payload["status"].(map[string]interface{}); ok {
				if n, ok := st["name"].(string); ok {
					statusName = n
				}
			} else if s, ok := payload["status"].(string); ok {
				statusName = s
			}
		}
		summary := ""
		if s, ok := fields["summary"].(string); ok {
			summary = s
		}
		if summary == "" {
			if s, ok := payload["summary"].(string); ok {
				summary = s
			}
		}
		description := ""
		if s, ok := fields["description"].(string); ok {
			description = s
		}
		if description == "" {
			if s, ok := payload["description"].(string); ok {
				description = s
			}
		}
		var comments []string
		if cmt, ok := fields["comment"].(map[string]interface{}); ok {
			if arr, ok := cmt["comments"].([]interface{}); ok {
				for _, cv := range arr {
					if cm, ok := cv.(map[string]interface{}); ok {
						if b, ok := cm["body"].(string); ok && b != "" {
							comments = append(comments, b)
						} else if cbody, ok := cm["renderedBody"].(string); ok && cbody != "" {
							comments = append(comments, cbody)
						}
					}
				}
			}
		}
		if len(comments) == 0 {
			if cm, ok := payload["comment"].(map[string]interface{}); ok {
				if b, ok := cm["body"].(string); ok && b != "" {
					comments = append(comments, b)
				}
			}
		}
		log.Printf("[JiraWebhook] project=%q status=%q summary=%q labels=%v comments=%d", projectKey, statusName, summary, labels, len(comments))

		// Build agent prompt
		promptStr := ""
		{
			var b strings.Builder
			b.WriteString("You are an AI assistant for triaging Jira events.\n")
			if projectKey != "" {
				b.WriteString("Project: ")
				b.WriteString(projectKey)
				b.WriteString("\n")
			}
			if summary != "" {
				b.WriteString("Summary: ")
				b.WriteString(summary)
				b.WriteString("\n")
			}
			if statusName != "" {
				b.WriteString("Status: ")
				b.WriteString(statusName)
				b.WriteString("\n")
			}
			if len(labels) > 0 {
				b.WriteString("Labels: ")
				b.WriteString(strings.Join(labels, ", "))
				b.WriteString("\n")
			}
			if description != "" {
				b.WriteString("Description:\n")
				b.WriteString(description)
				b.WriteString("\n")
			}
			if len(comments) > 0 {
				b.WriteString("Comments:\n")
				for i, cm := range comments {
					b.WriteString(strconv.Itoa(i+1))
					b.WriteString(". ")
					b.WriteString(cm)
					b.WriteString("\n")
				}
			}
			promptStr = b.String()
		}

		// Dispatch a background Gemini task to process this event (log-only)
		go func(promptStr, issueKey string) {
			title := "Jira Webhook Event"
			if strings.TrimSpace(issueKey) != "" {
				title = "Jira: " + strings.TrimSpace(issueKey)
			}
			threadID, err := utility.GetOrCreateThreadByTitle(title)
			if err != nil {
				log.Printf("[JiraWebhook][DB] create thread error: %v", err)
				return
			}
            if err := utility.StoreMessage(threadID, "system", promptStr, map[string]interface{}{"source": "jira", "issue_key": issueKey}); err != nil {
				log.Printf("[JiraWebhook][DB] store system message error: %v", err)
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			resp, _, err := utility.GeminiAPIHandler(ctx, promptStr, nil)
			if err != nil {
				log.Printf("[JiraWebhook][Gemini] error: %v", err)
				return
			}
			if strings.TrimSpace(resp) == "" {
				resp = "**No response available.**"
			}
			if err := utility.StoreMessage(threadID, "assistant", resp, map[string]interface{}{"source": "jira", "issue_key": issueKey}); err != nil {
				log.Printf("[JiraWebhook][DB] store assistant message error: %v", err)
				return
			}
		}(promptStr, issueKey)

		c.Status(http.StatusOK)
	})
}
