package utility

import (
	"context"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/slack-go/slack"
)

// HandleSlackMessage processes a Slack message event.
// Dependencies are injected to avoid cross-package coupling to main internals.
func HandleSlackMessage(
	c *gin.Context,
	event *slack.MessageEvent,
	getOrCreateThread func() (int64, error),
	llmHandler func(ctx context.Context, task string, initialContext []string) (string, []string, error),
) {
	// Ignore bot messages to prevent loops
	if event.BotID != "" {
		log.Printf("[Slack Message] Ignoring bot message from bot ID: %s", event.BotID)
		c.JSON(http.StatusOK, gin.H{"status": "bot message ignored"})
		return
	}

	// Ensure a thread exists
	threadID, err := getOrCreateThread()
	if err != nil {
		log.Printf("[Slack Message] ensure thread failed: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to ensure thread"})
		return
	}

	// Persist user message
	if err := StoreMessage(threadID, "user", event.Text, map[string]interface{}{
		"source":        "slack",
		"slack_channel": event.Channel,
		"slack_ts":      event.Timestamp,
	}); err != nil {
		log.Printf("[Slack Message] Failed to persist user message: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to persist user message"})
		return
	}

	// Load last context
	initialCtx, err := GetLastContextForThread(threadID)
	if err != nil {
		log.Printf("[Slack Message] Failed to get last context: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load conversation context"})
		return
	}

	// Run LLM/tool loop
	reply, updatedCtx, err := llmHandler(c.Request.Context(), event.Text, initialCtx)
	if err != nil {
		log.Printf("[Slack Message] Gemini error: %v", err)
		if serr := SendSlackResponse(event.Channel, "Sorry, I encountered an error. Please try again."); serr != nil {
			log.Printf("[Slack Message] Failed to send error notice to Slack: %v", serr)
		}
		c.JSON(http.StatusOK, gin.H{"status": "error_processed"})
		return
	}

	// Persist assistant message
	if err := StoreMessage(threadID, "assistant", reply, map[string]interface{}{
		"source":          "slack",
		"slack_channel":   event.Channel,
		"current_context": updatedCtx,
	}); err != nil {
		log.Printf("[Slack Message] Failed to persist assistant message: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to persist assistant message"})
		return
	}

	// Send reply back to Slack
	if err := SendSlackResponse(event.Channel, reply); err != nil {
		log.Printf("[Slack Message] Failed to send response to Slack: %v", err)
	}

	log.Printf("[Slack Message] Channel: %s, User: %s, Text: %s", event.Channel, event.User, event.Text)
	log.Printf("[Slack Message] Response: %s", reply)
	c.JSON(http.StatusOK, gin.H{"status": "message processed", "reply": reply})
}
