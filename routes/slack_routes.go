package routes

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/slack-go/slack"
	"go-thing/utility"
)

// slackViewInfo contains information about a Slack view, such as its hash.
type slackViewInfo struct {
	Hash string `json:"hash"`
}

// slackAppHomeOpenedEvent represents the structure of a Slack app_home_opened event.
type slackAppHomeOpenedEvent struct {
	User string         `json:"user"`
	Tab  string         `json:"tab"`
	View *slackViewInfo `json:"view"`
}

// RegisterSlackRoutes registers the Slack webhook route(s)
func RegisterSlackRoutes(r *gin.Engine, getOrCreateAnyThread func() (int64, error)) {
	r.POST("/webhook/slack", func(c *gin.Context) {
		body, err := c.GetRawData()
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to read body"})
			return
		}
		var ev slack.Event
		if err := json.Unmarshal(body, &ev); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid event"})
			return
		}
		if ev.Type == "url_verification" {
			var ch struct {
				Challenge string `json:"challenge"`
			}
			if err := json.Unmarshal(body, &ch); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid challenge"})
				return
			}
			c.JSON(http.StatusOK, gin.H{"challenge": ch.Challenge})
			return
		}
		if ev.Type == "event_callback" {
			// Envelope contains the inner event as raw JSON so we can branch by type
			var envelope struct {
				Event json.RawMessage `json:"event"`
			}
			if err := json.Unmarshal(body, &envelope); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid callback"})
				return
			}
			// Detect inner event type
			var meta struct {
				Type string `json:"type"`
			}
			if err := json.Unmarshal(envelope.Event, &meta); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid inner event"})
				return
			}
			switch meta.Type {
			case "message":
				var msg slack.MessageEvent
				if err := json.Unmarshal(envelope.Event, &msg); err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid message event"})
					return
				}
				utility.HandleSlackMessage(c, &msg, getOrCreateAnyThread, utility.GeminiAPIHandler)
				return
			case "app_home_opened":
				var ah slackAppHomeOpenedEvent
				if err := json.Unmarshal(envelope.Event, &ah); err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid app_home_opened event"})
					return
				}
				if strings.TrimSpace(ah.User) == "" {
					c.JSON(http.StatusBadRequest, gin.H{"error": "Missing user in app_home_opened"})
					return
				}
				hash := ""
				if ah.View != nil {
					hash = strings.TrimSpace(ah.View.Hash)
				}
				if err := utility.PublishSlackHomeTab(c.Request.Context(), ah.User, hash); err != nil {
					// logging remains in agent layer; ignore here
				}
				c.JSON(http.StatusOK, gin.H{"status": "home updated"})
				return
			default:
				// Ignore other inner events for now
				c.JSON(http.StatusOK, gin.H{"status": "event ignored", "event_type": meta.Type})
				return
			}
		}
		c.JSON(http.StatusOK, gin.H{"status": "event received"})
	})
}
